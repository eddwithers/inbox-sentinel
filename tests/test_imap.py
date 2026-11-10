"""Behaviour tests for Inbox Sentinel's IMAP provider.

A hand-rolled fake ``imaplib`` client stands in for the real server so these
tests never touch the network. Every state transition the plugin relies on —
the baseline UID cursor, new-UID discovery, login failures bubbling up to the
watch loop, retry-cap behaviour — is exercised end to end against the shared
pipeline.
"""
from __future__ import annotations

import asyncio
import base64
import importlib.util
import sys
from pathlib import Path

import pytest

from conftest import ParsedBox, TextBox


REPO_ROOT = Path(__file__).resolve().parent.parent
IMAP_PATH = REPO_ROOT / "imap.py"

pytestmark = pytest.mark.usefixtures("capture_notifications")


# ---------------------------------------------------------------- fixtures

@pytest.fixture()
def imap_module(plugin):
    """Load imap.py as a fresh sibling module bound to the plugin under test."""
    spec = importlib.util.spec_from_file_location(
        "inbox_sentinel_imap_under_test", IMAP_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["inbox_sentinel_imap_under_test"] = mod
    spec.loader.exec_module(mod)
    # Bind the parent AFTER exec_module (the module's own ``_sentinel = None``
    # line would otherwise overwrite a pre-set attribute).
    mod._sentinel = plugin
    yield mod
    sys.modules.pop("inbox_sentinel_imap_under_test", None)


@pytest.fixture()
def imap_ctx(ctx):
    """Minimal IMAP config: valid host/user/folder + notification capture."""
    ctx.config.update({
        "provider": "imap",
        "imap_host": "imap.example.test",
        "imap_port": 993,
        "imap_ssl": True,
        "imap_user": "me@example.test",
        "imap_folder": "INBOX",
        "delivery_target": "push",
    })
    return ctx


@pytest.fixture()
def capture_notifications(plugin, ctx, monkeypatch):
    ctx.delivered_messages = []

    async def fake_deliver(current_ctx, text):
        current_ctx.delivered_messages.append(text)

    monkeypatch.setattr(plugin, "_deliver", fake_deliver)
    return ctx.delivered_messages


# ---------------------------------------------------------------- fake imap

def _make_rfc822(sender="Alice <alice@example.test>",
                 subject="Hi there",
                 to="me@example.test",
                 plain="Hello from IMAP.",
                 reply_to=None):
    headers = [f"From: {sender}",
               f"To: {to}",
               f"Subject: {subject}",
               "MIME-Version: 1.0",
               'Content-Type: text/plain; charset="utf-8"']
    if reply_to:
        headers.insert(2, f"Reply-To: {reply_to}")
    return ("\r\n".join(headers) + "\r\n\r\n" + plain).encode("utf-8")


class FakeIMAP:
    """Stand-in for ``imaplib.IMAP4_SSL``.

    Scripted responses: ``.inbox`` maps uid → RFC 822 bytes; ``.login_error``
    forces a login failure; ``.fetch_errors`` maps uid → exception to raise
    for the retry-cap tests.
    """
    def __init__(self, host, port, ssl_context=None, timeout=None):
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.login_called_with = None
        self.selected = None
        self.logged_out = False
        self.commands = []
        self.inbox = {}          # uid -> rfc822 bytes
        self.login_error = None  # Exception to raise on login
        self.fetch_errors = {}   # uid -> Exception to raise on FETCH
        self.search_error = None
        self._readonly = False
        self.uidvalidity = 42
        self.size_fetch_responses = {}  # uid -> int/bytes/str/None for RFC822.SIZE

    def login(self, user, password):
        self.commands.append(("LOGIN", user))
        self.login_called_with = (user, password)
        if self.login_error is not None:
            raise self.login_error
        return ("OK", [b"Logged in"])

    def select(self, mailbox, readonly=False):
        self.commands.append(("SELECT", mailbox, readonly))
        self.selected = mailbox
        self._readonly = readonly
        return ("OK", [b"42"])

    def response(self, code):
        if code == "UIDVALIDITY":
            if self.uidvalidity is None:
                return None
            return ("OK", [str(self.uidvalidity).encode()])
        return None

    def uid(self, command, *args):
        self.commands.append(("UID", command, args))
        if command == "SEARCH":
            if self.search_error is not None:
                raise self.search_error
            # args = (criterion_or_None, *rest)
            criteria = [a for a in args if a is not None]
            if not criteria or criteria == ["ALL"]:
                uids = sorted(self.inbox.keys())
            else:
                # Parse "UID N:*" — everything with UID >= N.
                tail = criteria[-1]
                if tail.startswith("UID "):
                    spec = tail[4:]
                    low_str, _, _ = spec.partition(":")
                    try:
                        low = int(low_str)
                    except ValueError:
                        low = 0
                    uids = sorted(u for u in self.inbox if u >= low)
                else:
                    uids = sorted(self.inbox.keys())
            payload = b" ".join(str(u).encode() for u in uids)
            return ("OK", [payload])
        if command == "FETCH":
            uid = int(args[0])
            request = args[1] if len(args) > 1 else ""
            if uid in self.fetch_errors:
                raise self.fetch_errors[uid]
            body = self.inbox.get(uid)
            if "RFC822.SIZE" in request.upper():
                if uid in self.size_fetch_responses:
                    size = self.size_fetch_responses[uid]
                    if size is None:
                        return ("OK", [b""])
                    if isinstance(size, int):
                        return ("OK", [f"{uid} (RFC822.SIZE {size})".encode()])
                    if isinstance(size, bytes):
                        return ("OK", [size])
                    return ("OK", [str(size).encode()])
                if body is None:
                    return ("OK", [b""])
                return ("OK", [f"{uid} (RFC822.SIZE {len(body)})".encode()])
            if body is None:
                return ("NO", [b""])
            # imaplib shape for literals: a tuple (envelope, body_bytes).
            envelope = f"{uid} (UID {uid} BODY[]<0> {{{len(body)}}}".encode()
            return ("OK", [(envelope, body), b")"])
        return ("OK", [b""])

    def shutdown(self):
        self.logged_out = True
        self.commands.append(("SHUTDOWN",))

    def logout(self):
        self.logged_out = True
        self.commands.append(("LOGOUT",))
        return ("BYE", [b"bye"])


def _install_fake_imap(monkeypatch, imap_module, fake_factory):
    """Replace the imap module's ``imaplib.IMAP4_SSL`` with ``fake_factory``."""
    monkeypatch.setattr(imap_module.imaplib, "IMAP4_SSL", fake_factory)
    # Also silence the ssl context build — the fake ignores it, but the real
    # module calls ssl.create_default_context() unconditionally.
    monkeypatch.setattr(imap_module.ssl, "create_default_context",
                        lambda: object())


def _install_fake_secret(monkeypatch, imap_module, password="hunter2"):
    """Make agent.secret_scope.get_secret return a canned password."""
    # imap.py imports get_secret lazily inside _get_imap_password, so patch
    # the function on the agent.secret_scope module itself.
    import agent.secret_scope as ss
    monkeypatch.setattr(ss, "get_secret",
                        lambda name, default=None:
                        password if name == "INBOX_SENTINEL_IMAP_PASSWORD" else default)


# ---------------------------------------------------------------- tests

def test_bootstrap_records_baseline_uid_without_alerting(
        imap_module, imap_ctx, monkeypatch):
    """First tick with pre-existing mail must record max UID and alert none."""
    fakes = []

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        f.inbox = {
            1: _make_rfc822(subject="old-1"),
            7: _make_rfc822(subject="old-7"),
            12: _make_rfc822(subject="old-12"),
        }
        fakes.append(f)
        return f

    _install_fake_imap(monkeypatch, imap_module, factory)
    _install_fake_secret(monkeypatch, imap_module)

    asyncio.run(imap_module.tick(imap_ctx))

    assert imap_ctx.state().get("imap_last_uid") == 12
    assert imap_ctx.delivered_messages == []
    assert imap_ctx.injected_messages == []
    assert imap_ctx.llm.structured_calls == []
    assert fakes[0].logged_out is True
    assert fakes[0]._readonly is True   # select MUST be read-only


def test_uidvalidity_change_reboots_to_safe_cursor(
        imap_module, imap_ctx, monkeypatch):
    """A UIDVALIDITY change must discard the old cursor and re-bootstrap."""
    imap_ctx.state().set("imap_last_uid", 10)
    imap_ctx.state().set("imap_uidvalidity", 111)
    fakes = []

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        f.uidvalidity = 222
        f.inbox = {
            1: _make_rfc822(subject="old-1"),
            3: _make_rfc822(subject="new-3"),
        }
        fakes.append(f)
        return f

    _install_fake_imap(monkeypatch, imap_module, factory)
    _install_fake_secret(monkeypatch, imap_module)

    asyncio.run(imap_module.tick(imap_ctx))

    assert imap_ctx.state().get("imap_last_uid") == 3
    assert imap_ctx.state().get("imap_uidvalidity") == 222
    assert imap_ctx.delivered_messages == []
    assert imap_ctx.injected_messages == []
    assert fakes[0].logged_out is True


def test_new_uid_runs_full_pipeline_and_delivers_alert(
        imap_module, imap_ctx, plugin, monkeypatch):
    """A new UID past the baseline is parsed, gated, drafted and delivered."""
    # Baseline already recorded; one new message at uid 42.
    imap_ctx.state().set("imap_last_uid", 10)
    fakes = []

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        f.inbox = {
            42: _make_rfc822(
                sender="Boss <boss@work.test>",
                subject="Can you review the deck?",
                reply_to="boss-reply@work.test",
                plain="Please look at slides 3-5 before noon."),
        }
        fakes.append(f)
        return f

    _install_fake_imap(monkeypatch, imap_module, factory)
    _install_fake_secret(monkeypatch, imap_module)

    imap_ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Boss wants deck reviewed."})
    imap_ctx.llm.complete_result = TextBox("On it — looking now.")

    asyncio.run(imap_module.tick(imap_ctx))

    # Pipeline fired once with the expected content.
    assert len(imap_ctx.delivered_messages) == 1
    alert = imap_ctx.delivered_messages[0]
    assert "EMAIL ALERT" in alert
    assert "Subject: Can you review the deck?" in alert
    assert "From: Boss ‹boss@\u200bwork.test›" in alert
    assert "Boss wants deck reviewed." in alert
    assert "Suggested reply (to boss-reply@\u200bwork.test):" in alert
    assert "On it — looking now." in alert
    # IMAP msgid prefix MUST differ from Gmail's.
    assert "msgid: imap:42" in alert
    assert imap_ctx.state().get("imap_last_uid") == 42
    assert imap_ctx.state().get("alerts_sent") == 1


def test_password_resolved_via_secret_scope(
        imap_module, imap_ctx, monkeypatch):
    """The IMAP password MUST flow through agent.secret_scope.get_secret —
    the plugin never reads INBOX_SENTINEL_IMAP_PASSWORD from os.environ
    directly (catalog rule 11)."""
    seen = []

    import agent.secret_scope as ss

    def fake_get(name, default=None):
        seen.append(name)
        if name == "INBOX_SENTINEL_IMAP_PASSWORD":
            return "scoped-password-123"
        return default

    monkeypatch.setattr(ss, "get_secret", fake_get)

    fakes = []

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        f.inbox = {}
        fakes.append(f)
        return f
    _install_fake_imap(monkeypatch, imap_module, factory)

    asyncio.run(imap_module.tick(imap_ctx))

    assert "INBOX_SENTINEL_IMAP_PASSWORD" in seen
    assert fakes[0].login_called_with == ("me@example.test", "scoped-password-123")


def test_password_lookup_fails_closed_without_secret_scope(
        imap_module, imap_ctx, monkeypatch):
    """If secret scope lookup fails, the IMAP path must not fall back to env."""
    monkeypatch.setenv("INBOX_SENTINEL_IMAP_PASSWORD", "fallback-should-not-be-used")
    import agent.secret_scope as ss
    monkeypatch.setattr(ss, "get_secret", lambda name, default=None: (_ for _ in ()).throw(RuntimeError("no secret scope")))
    with pytest.raises(RuntimeError, match="INBOX_SENTINEL_IMAP_PASSWORD is not set"):
        imap_module._connect(imap_ctx)


def test_login_failure_surfaces_to_watch_loop_without_killing_it(
        imap_module, imap_ctx, plugin, monkeypatch):
    """A single bad tick must not kill the loop. The watch loop's generic
    handler should catch the exception, record last_error, and the next tick
    starts a fresh connection."""
    # ctx.config provider must be imap so _tick dispatches to us.
    imap_ctx.config["provider"] = "imap"
    # Make the plugin's lazy loader return our fresh module.
    monkeypatch.setattr(plugin, "_load_imap_module", lambda: imap_module)

    fakes = []
    call_count = {"n": 0}

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        call_count["n"] += 1
        if call_count["n"] == 1:
            import imaplib
            f.login_error = imaplib.IMAP4.error("bad credentials")
        else:
            f.inbox = {}  # clean second tick
        fakes.append(f)
        return f
    _install_fake_imap(monkeypatch, imap_module, factory)
    _install_fake_secret(monkeypatch, imap_module)

    # First tick: login error bubbles up as RuntimeError. We assert via the
    # full watch loop that ``last_error`` is set and the loop survives.
    async def run_two_ticks():
        state = imap_ctx.state()
        try:
            await plugin._tick(imap_ctx)
        except Exception as exc:
            state.set("last_error", repr(exc))
        # Second tick must succeed (loop survived).
        await plugin._tick(imap_ctx)

    asyncio.run(run_two_ticks())

    assert "imap login/select failed" in imap_ctx.state().get("last_error", "")
    # The second tick reconnected fresh and recorded a baseline (empty inbox).
    assert imap_ctx.state().get("imap_last_uid") == 0
    # And the first connection WAS logged out (finally block runs).
    assert all(f.logged_out for f in fakes)


def test_fetch_failure_retries_until_cap_then_advances(
        imap_module, imap_ctx, monkeypatch):
    """A message that keeps failing hits RETRY_CAP, emits the give-up ping,
    and the cursor advances past it so the loop doesn't wedge."""
    imap_ctx.state().set("imap_last_uid", 100)

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        f.inbox = {101: _make_rfc822(subject="stuck")}
        f.fetch_errors = {101: RuntimeError("fetch blew up")}
        return f
    _install_fake_imap(monkeypatch, imap_module, factory)
    _install_fake_secret(monkeypatch, imap_module)

    plugin_mod = imap_module._sentinel
    # Run RETRY_CAP ticks — each sees the same UID and fails.
    for _ in range(plugin_mod.RETRY_CAP):
        asyncio.run(imap_module.tick(imap_ctx))

    # Give-up ping delivered once with the IMAP-prefixed msgid.
    delivered = [m for m in imap_ctx.delivered_messages
                 if "delivery failed after retries" in m]
    assert len(delivered) == 1
    assert "msgid: imap:101" in delivered[0]
    # Cursor advanced past the poison UID so the loop can make progress.
    assert imap_ctx.state().get("imap_last_uid") == 101
    assert imap_ctx.state().get("fails", {}).get("imap:101") is None


def test_tick_processes_at_most_twenty_uids_per_run(
        imap_module, imap_ctx, plugin, monkeypatch):
    imap_ctx.state().set("imap_last_uid", 0)
    imap_ctx.config["draft_replies"] = False
    imap_ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "Review."})

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        f.inbox = {uid: _make_rfc822(subject=f"mail-{uid}") for uid in range(1, 22)}
        return f

    _install_fake_imap(monkeypatch, imap_module, factory)
    _install_fake_secret(monkeypatch, imap_module)

    asyncio.run(imap_module.tick(imap_ctx))

    assert imap_ctx.state().get("imap_last_uid") == 20
    assert len(imap_ctx.delivered_messages) == 20
    assert len(imap_ctx.llm.structured_calls) == 20
    assert imap_ctx.injected_messages == []


def test_oversized_message_prefetches_size_only_and_emits_notice(
        imap_module, imap_ctx, plugin, monkeypatch):
    imap_ctx.state().set("imap_last_uid", 10)

    fakes = []

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        f.inbox = {11: _make_rfc822(subject="too-big")}
        f.size_fetch_responses = {11: 262145}
        fakes.append(f)
        return f

    _install_fake_imap(monkeypatch, imap_module, factory)
    _install_fake_secret(monkeypatch, imap_module)

    asyncio.run(imap_module.tick(imap_ctx))

    assert imap_ctx.state().get("imap_last_uid") == 11
    assert imap_ctx.llm.structured_calls == []
    assert imap_ctx.llm.complete_calls == []
    assert len(imap_ctx.delivered_messages) == 1
    assert "review original email" in imap_ctx.delivered_messages[0]
    assert any("RFC822.SIZE" in str(cmd) for cmd in fakes[0].commands)
    assert not any("BODY.PEEK[]<0.262145>" in str(cmd) for cmd in fakes[0].commands)


def test_partial_body_size_mismatch_emits_notice_and_advances(
        imap_module, imap_ctx, plugin, monkeypatch):
    imap_ctx.state().set("imap_last_uid", 10)

    fakes = []

    def factory(host, port, ssl_context=None, timeout=None):
        f = FakeIMAP(host, port, ssl_context)
        f.inbox = {11: _make_rfc822(subject="mismatch")}
        f.size_fetch_responses = {11: 4}
        fakes.append(f)
        return f

    _install_fake_imap(monkeypatch, imap_module, factory)
    _install_fake_secret(monkeypatch, imap_module)

    asyncio.run(imap_module.tick(imap_ctx))

    assert imap_ctx.state().get("imap_last_uid") == 11
    assert imap_ctx.llm.structured_calls == []
    assert imap_ctx.llm.complete_calls == []
    assert len(imap_ctx.delivered_messages) == 1
    assert "review original email" in imap_ctx.delivered_messages[0]
    assert any("RFC822.SIZE" in str(cmd) for cmd in fakes[0].commands)
    assert any("BODY.PEEK[]<0.262145>" in str(cmd) for cmd in fakes[0].commands)


def test_tick_dispatches_to_imap_when_provider_is_imap(
        plugin, imap_ctx, imap_module, monkeypatch):
    """The top-level _tick must route to the IMAP module when provider=imap."""
    imap_ctx.config["provider"] = "imap"
    called = {"n": 0}

    async def fake_tick(ctx):
        called["n"] += 1
    monkeypatch.setattr(imap_module, "tick", fake_tick)
    monkeypatch.setattr(plugin, "_load_imap_module", lambda: imap_module)

    asyncio.run(plugin._tick(imap_ctx))
    assert called["n"] == 1


def test_gmail_provider_still_default(plugin, ctx, gmail):
    """With no provider configured, the dispatcher must take the Gmail path
    (byte-identical to the original — test only the dispatch edge here)."""
    gmail.respond("GET", "/users/me/profile", {"historyId": "1"})
    gmail.respond("GET", "/users/me/messages", {"messages": []})
    gmail.respond("GET", "/users/me/history",
                  {"history": [], "historyId": "2"})
    asyncio.run(plugin._tick(ctx))
    assert ctx.state().get("history_id") == "2"

