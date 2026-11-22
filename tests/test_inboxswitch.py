"""M2 IS-InboxSwitch behaviour tests: account registry validation, the
module's bounded policy (disabled-account drop, alert tag), per-account
importance profiles, and legacy byte-identical fallbacks. Fictional mail
only; no network, no real model calls, no sleeps (clocks injected).
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from conftest import ParsedBox, TextBox, make_raw, meta_response

pytestmark = pytest.mark.usefixtures("capture_notifications")

REGISTRY = json.dumps([
    {"id": "personal", "provider": "gmail", "label": "Personal"},
    {"id": "work", "provider": "imap", "label": "Work",
     "imap_host": "imap.work.test", "imap_user": "me@work.test",
     "password_env": "INBOX_SENTINEL_IMAP_PASSWORD2"},
])


def _important_mail(gmail, mid="mImp"):
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  meta_response(sender="Alice <alice@example.test>",
                                subject="Hello"))
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  {"raw": make_raw(subject="Hello",
                                   sender="Alice <alice@example.test>",
                                   plain="A short note.")})


# ---------------------------------------------------------------- registry

def test_registry_parses_valid_accounts(plugin, ctx):
    ctx.config["accounts"] = REGISTRY
    accts = plugin._accounts(ctx)
    assert [a["id"] for a in accts] == ["personal", "work"]
    p, w = accts
    assert p["provider"] == "gmail" and p["oauth_id"] == "gmail"
    assert p["label"] == "Personal" and p["enabled"] is True
    assert w["provider"] == "imap"
    assert w["password_env"] == "INBOX_SENTINEL_IMAP_PASSWORD2"
    assert w["imap_host"] == "imap.work.test" and w["imap_user"] == "me@work.test"


def test_registry_absent_or_empty_is_legacy(plugin, ctx):
    assert plugin._accounts(ctx) == []
    ctx.config["accounts"] = ""
    assert plugin._accounts(ctx) == []
    ctx.config["accounts"] = "   "
    assert plugin._accounts(ctx) == []


def test_registry_invalid_json_falls_back(plugin, ctx):
    ctx.config["accounts"] = "{not json"
    with pytest.raises(plugin.AccountConfigurationError):
        plugin._accounts(ctx)


def test_registry_wrong_shape_falls_back(plugin, ctx):
    for bad in ("{}", "[1]", json.dumps([{"id": f"a{i}"} for i in range(5)])):
        ctx.config["accounts"] = bad
        with pytest.raises(plugin.AccountConfigurationError):
            plugin._accounts(ctx)


def test_registry_duplicate_ids_rejected(plugin, ctx):
    ctx.config["accounts"] = json.dumps([{"id": "dup"}, {"id": "dup"}])
    with pytest.raises(plugin.AccountConfigurationError):
        plugin._accounts(ctx)


def test_registry_bad_ids_rejected(plugin, ctx):
    for bad_id in ("Personal", "has space", "x" * 33, "", "a/b", "ümlaut"):
        ctx.config["accounts"] = json.dumps([{"id": bad_id}])
        with pytest.raises(plugin.AccountConfigurationError):
            plugin._accounts(ctx)


def test_registry_unknown_provider_rejected(plugin, ctx):
    ctx.config["accounts"] = json.dumps([{"id": "a", "provider": "pop3"}])
    with pytest.raises(plugin.AccountConfigurationError):
        plugin._accounts(ctx)


def test_registry_unknown_credential_pool_rejected(plugin, ctx):
    ctx.config["accounts"] = json.dumps([{"id": "a", "oauth_id": "gmail9"}])
    with pytest.raises(plugin.AccountConfigurationError):
        plugin._accounts(ctx)
    ctx.config["accounts"] = json.dumps(
        [{"id": "a", "provider": "imap", "password_env": "OTHER_SECRET"}])
    with pytest.raises(plugin.AccountConfigurationError):
        plugin._accounts(ctx)


def test_registry_secret_values_rejected(plugin, ctx):
    for item in ({"id": "a", "password": "hunter2"},
                 {"id": "a", "client_secret": "abc"},
                 {"id": "a", "imap_host": "-----BEGIN PRIVATE KEY-----"},
                 {"id": "a", "label": "gho_1234567890abcdef"}):
        ctx.config["accounts"] = json.dumps([item])
        with pytest.raises(plugin.AccountConfigurationError):
            plugin._accounts(ctx)


def test_registry_bad_types_rejected(plugin, ctx):
    for item in ({"id": "a", "enabled": "yes"},
                 {"id": "a", "label": 123},
                 {"id": "a", "label": ""},
                 {"id": "a", "importance_profile": "x" * 2001},
                 {"id": "a", "gmail_query": "q" * 1001},
                 {"id": "a", "delivery_target": 5}):
        ctx.config["accounts"] = json.dumps([item])
        with pytest.raises(plugin.AccountConfigurationError):
            plugin._accounts(ctx)


def test_registry_hostile_oversized_json_timing(plugin, ctx):
    ctx.config["accounts"] = json.dumps([{"id": "a", "pad": "x" * 1000000}])
    start = time.monotonic()
    with pytest.raises(plugin.AccountConfigurationError):
        plugin._accounts(ctx)
    assert time.monotonic() - start < 2.0


def test_registry_defaults_and_global_imap_fallback(plugin, ctx):
    ctx.config["imap_host"] = "global.imap.test"
    ctx.config["imap_user"] = "global@imap.test"
    ctx.config["accounts"] = json.dumps([{"id": "solo", "provider": "imap"}])
    (a,) = plugin._accounts(ctx)
    assert a["label"] == "solo" and a["enabled"] is True
    assert a["password_env"] == "INBOX_SENTINEL_IMAP_PASSWORD"
    assert a["imap_host"] == "global.imap.test"
    assert a["imap_user"] == "global@imap.test"
    assert a["imap_folder"] == "INBOX" and a["imap_port"] == 993
    assert a["imap_ssl"] is True


def test_invalid_registry_never_polls_legacy(plugin, ctx, gmail):
    ctx.config["accounts"] = "{bad json"
    with pytest.raises(plugin.AccountConfigurationError):
        asyncio.run(plugin._tick(ctx))
    assert gmail.calls == []
    assert "polling stopped" in plugin._status(ctx)["last_error"]



# ---------------------------------------------------------------- module

def test_inboxswitch_discovered(plugin):
    m = plugin._modules()["inboxswitch"]
    assert m.NAME == "inboxswitch"
    assert m.BRAND == "IS-InboxSwitch"
    assert set(m.STAGES) == {"prefilter", "post_gate"}
    assert m.DEFAULT_ENABLED is True
    assert m.PRIORITY < plugin._modules()["noisefilter"].PRIORITY


def test_inboxswitch_prefilter_drops_disabled_account(plugin, ctx):
    m = plugin._modules()["inboxswitch"]
    api = plugin._ModuleAPI(ctx, "inboxswitch", m)
    view = {"account_id": "work", "account_enabled": False, "flags": {}}
    out = m.prefilter(view, api)
    assert out["drop"] is True
    view["account_enabled"] = True
    assert m.prefilter(view, api) is None
    assert m.prefilter({"flags": {}}, api) is None  # legacy: no account context


def test_inboxswitch_post_gate_tag(plugin, ctx):
    m = plugin._modules()["inboxswitch"]
    api = plugin._ModuleAPI(ctx, "inboxswitch", m)
    view = {"account_id": "work", "account_label": "Work", "flags": {}}
    assert m.post_gate(view, api) == {"account_tag": "Work"}
    assert m.post_gate({"flags": {}}, api) is None


def test_inboxswitch_tag_sanitised(plugin, ctx):
    m = plugin._modules()["inboxswitch"]
    api = plugin._ModuleAPI(ctx, "inboxswitch", m)
    view = {"account_id": "work", "account_label": "<b>@evil://x</b>", "flags": {}}
    tag = m.post_gate(view, api)["account_tag"]
    assert "<b>" not in tag and "@evil" not in tag and "://x" not in tag
    assert tag == plugin._safe_text("<b>@evil://x</b>", 60)


# ---------------------------------------------------------------- tagging helper

def test_account_tag_inserted_after_header(plugin):
    text = "EMAIL ALERT\n\nSubject: Hello"
    assert plugin._insert_account_tag(text, "Work") == \
        "EMAIL ALERT\nAccount: Work\n\nSubject: Hello"
    scam = "POSSIBLE SCAM — do not reply.\n\nSubject: Hello"
    assert plugin._insert_account_tag(scam, "Work").startswith(
        "POSSIBLE SCAM — do not reply.\nAccount: Work\n")


# ---------------------------------------------------------------- profiles

def test_gate_instructions_account_profile_override(plugin, ctx):
    ctx.config["importance_profile"] = "global priorities"
    acct = {"importance_profile": "work priorities matter"}
    assert "work priorities matter" in plugin._gate_instructions(ctx, account=acct)
    assert "global priorities" not in plugin._gate_instructions(ctx, account=acct)
    assert "global priorities" in plugin._gate_instructions(
        ctx, account={"importance_profile": ""})
    assert "global priorities" in plugin._gate_instructions(ctx)


# ---------------------------------------------------------------- multi-account intake

def _acct(aid, oauth_id="gmail", **kw):
    a = {"id": aid, "label": aid.capitalize(), "provider": "gmail",
         "enabled": True, "oauth_id": oauth_id, "gmail_query": "",
         "importance_profile": "", "delivery_target": ""}
    a.update(kw)
    return a


def _freeze(plugin, monkeypatch):
    monkeypatch.setattr(plugin.time, "strftime",
                        lambda fmt: "2026-11-22" if fmt == "%Y-%m-%d" else "00:00")


def _bootstrap_responses(gmail, oauth_id, history_id, inbox_ids=()):
    gmail.respond("GET", "/users/me/profile", {"historyId": history_id},
                  oauth_id=oauth_id)
    gmail.respond("GET", "/users/me/messages",
                  {"messages": [{"id": i} for i in inbox_ids]}, oauth_id=oauth_id)
    gmail.respond("GET", "/users/me/history", {"historyId": history_id, "history": []},
                  oauth_id=oauth_id)


def _history_add(gmail, oauth_id, new_history_id, mid):
    gmail.respond("GET", "/users/me/history",
                  {"historyId": new_history_id,
                   "history": [{"messagesAdded": [
                       {"message": {"id": mid, "labelIds": ["INBOX"]}}]}]},
                  oauth_id=oauth_id)


def _mail_responses(gmail, oauth_id, mid):
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  meta_response(sender="Alice <alice@example.test>",
                                subject="Hello"), oauth_id=oauth_id)
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  {"raw": make_raw(subject="Hello",
                                   sender="Alice <alice@example.test>",
                                   plain="A short note.")}, oauth_id=oauth_id)


def test_two_gmail_accounts_separate_cursors_and_tags(plugin, ctx, gmail, monkeypatch):
    _freeze(plugin, monkeypatch)
    a, b = _acct("alpha"), _acct("beta", "gmail2")
    _bootstrap_responses(gmail, "gmail", "h1", ["oldA"])
    asyncio.run(plugin._tick_gmail(ctx, account=a))
    assert ctx.state.get("acct_alpha_history_id") == "h1"
    assert "oldA" in ctx.state.get("acct_alpha_seen", {})
    _bootstrap_responses(gmail, "gmail2", "k1")
    asyncio.run(plugin._tick_gmail(ctx, account=b))

    _history_add(gmail, "gmail", "h2", "mA")
    _mail_responses(gmail, "gmail", "mA")
    _history_add(gmail, "gmail2", "k2", "mA")
    _mail_responses(gmail, "gmail2", "mA")
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    asyncio.run(plugin._tick_gmail(ctx, account=a))
    asyncio.run(plugin._tick_gmail(ctx, account=b))

    assert len(ctx.delivered_messages) == 2
    assert ctx.delivered_messages[0].startswith("EMAIL ALERT\nAccount: Alpha\n\nSubject:")
    assert ctx.delivered_messages[1].startswith("EMAIL ALERT\nAccount: Beta\n\nSubject:")
    assert "msgid: gmail:mA" in ctx.delivered_messages[0]
    assert "msgid: gmail:mA" in ctx.delivered_messages[1]
    assert "mA" in ctx.state.get("acct_alpha_seen", {})
    assert "mA" in ctx.state.get("acct_beta_seen", {})  # same provider id, distinct mailbox
    assert ctx.state.get("acct_alpha_history_id") == "h2"
    assert ctx.state.get("acct_beta_history_id") == "k2"
    assert ctx.state.get("history_id") is None      # legacy keys untouched
    assert ctx.state.get("seen") is None
    assert ctx.state.get("acct_alpha_alerts_sent") == 1
    assert ctx.state.get("acct_beta_alerts_sent") == 1
    assert ctx.state.get("alerts_sent") == 2        # global counter kept


def test_disabled_account_never_polled(plugin, ctx, gmail):
    ctx.config["accounts"] = json.dumps([
        {"id": "alpha", "oauth_id": "gmail"},
        {"id": "beta", "oauth_id": "gmail2", "enabled": False}])
    _bootstrap_responses(gmail, "gmail", "h1")
    asyncio.run(plugin._tick(ctx))
    assert gmail.calls and all(c[3] == "gmail" for c in gmail.calls)
    assert ctx.state.get("acct_beta_history_id") is None


def test_account_auth_failure_isolation_and_backoff(plugin, ctx, gmail, monkeypatch):
    _freeze(plugin, monkeypatch)
    monkeypatch.setattr(plugin.time, "time", lambda: 1000.0)
    a, b = _acct("alpha"), _acct("beta", "gmail2")
    ctx.config["accounts"] = json.dumps([a, b])
    gmail.respond("GET", "/users/me/profile",
                  plugin.ProviderNotSignedIn("no grant"), oauth_id="gmail")
    _bootstrap_responses(gmail, "gmail2", "k1")
    asyncio.run(plugin._tick(ctx))
    assert ctx.state.get("acct_beta_history_id") == "k1"
    assert ctx.state.get("acct_alpha_last_error")
    assert "alpha:" in ctx.state.get("last_error")
    assert ctx.state.get("acct_alpha_health_notice_day") == "2026-11-22"
    assert ctx.state.get("acct_alpha_next_retry_at", 0) > time.time()
    assert any("not watching your inbox" in m and "Account: Alpha" in m
               for m in ctx.delivered_messages)
    # Immediate second tick: alpha backs off, beta still polls.
    gmail.respond("GET", "/users/me/history", {"historyId": "k1", "history": []},
                  oauth_id="gmail2")
    before = len(gmail.calls)
    asyncio.run(plugin._tick(ctx))
    assert all(c[3] == "gmail2" for c in gmail.calls[before:])
    # Only one health notice per account per day.
    notices = [m for m in ctx.delivered_messages if "not watching" in m]
    assert len(notices) == 1


def test_budget_shared_across_accounts(plugin, ctx, gmail):
    ctx.config["daily_gate_cap"] = 1
    a, b = _acct("alpha"), _acct("beta", "gmail2")
    ctx.config["accounts"] = json.dumps([a, b])
    ctx.state.set("acct_alpha_history_id", "h1")
    ctx.state.set("acct_alpha_seen", {})
    ctx.state.set("acct_beta_history_id", "k1")
    ctx.state.set("acct_beta_seen", {})
    _history_add(gmail, "gmail", "h2", "mA")
    _mail_responses(gmail, "gmail", "mA")
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    with pytest.raises(plugin.GateBudgetExhausted):
        asyncio.run(plugin._tick(ctx))
    assert ctx.state.get("gate_count") == 1
    assert len(ctx.delivered_messages) == 1          # alpha only; beta deferred
    assert all(c[3] == "gmail" for c in gmail.calls)  # beta never fetched


def test_deliver_per_account_target(plugin, ctx, monkeypatch):
    calls = []
    class Process:
        returncode = 0
        async def communicate(self):
            return b"", b""
    async def spawn(*args, **kwargs):
        calls.append(args)
        return Process()
    monkeypatch.setattr(plugin.asyncio, "create_subprocess_exec", spawn)
    ctx.config["hermes_send_path"] = __import__("sys").executable
    asyncio.run(plugin._deliver(ctx, "text", account=_acct("alpha", delivery_target="none")))
    assert calls == []
    asyncio.run(plugin._deliver(ctx, "text", account=_acct("beta", "gmail2", delivery_target="telegram")))
    assert "telegram" in calls[0]



def test_per_account_importance_profile_reaches_gate(plugin, ctx, gmail, monkeypatch):
    _freeze(plugin, monkeypatch)
    a = _acct("alpha", importance_profile="alpha priorities rule")
    ctx.state.set("acct_alpha_history_id", "h1")
    ctx.state.set("acct_alpha_seen", {})
    _history_add(gmail, "gmail", "h2", "mA")
    _mail_responses(gmail, "gmail", "mA")
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "note"})
    asyncio.run(plugin._tick_gmail(ctx, account=a))
    assert "alpha priorities rule" in ctx.llm.structured_calls[0]["instructions"]


def test_scam_alert_tagged_in_multi_account(plugin, ctx, gmail, monkeypatch):
    _freeze(plugin, monkeypatch)
    a = _acct("alpha")
    ctx.state.set("acct_alpha_history_id", "h1")
    ctx.state.set("acct_alpha_seen", {})
    _history_add(gmail, "gmail", "h2", "mS")
    gmail.respond("GET", "/users/me/messages/mS",
                  meta_response(sender="Lure <lure@scam.test>", subject="Order"),
                  oauth_id="gmail")
    gmail.respond("GET", "/users/me/messages/mS",
                  {"raw": make_raw(subject="Order", sender="Lure <lure@scam.test>",
                                   plain="Open the password protected PDF.")},
                  oauth_id="gmail")
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Order."})
    asyncio.run(plugin._tick_gmail(ctx, account=a))
    assert ctx.delivered_messages[0].startswith("POSSIBLE SCAM")
    assert "\nAccount: Alpha\n" in ctx.delivered_messages[0]
    assert ctx.llm.complete_calls == []


def test_inboxswitch_off_host_fallback_tag(plugin, ctx, gmail, monkeypatch):
    _freeze(plugin, monkeypatch)
    ctx.config["module_inboxswitch_enabled"] = False
    a = _acct("alpha")
    ctx.state.set("acct_alpha_history_id", "h1")
    ctx.state.set("acct_alpha_seen", {})
    _history_add(gmail, "gmail", "h2", "mA")
    _mail_responses(gmail, "gmail", "mA")
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    asyncio.run(plugin._tick_gmail(ctx, account=a))
    assert ctx.delivered_messages[0].startswith("EMAIL ALERT\nAccount: Alpha\n")


def test_storm_suppression_is_account_scoped(plugin, ctx, monkeypatch):
    _freeze(plugin, monkeypatch)
    ctx.config["storm_threshold"] = 2
    ctx.config["draft_replies"] = False
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "Sale."})
    a, b = _acct("alpha"), _acct("beta", "gmail2")

    async def run(mid, acct):
        await plugin._run_pipeline(
            ctx, mid_prefix="gmail", mid=mid, sender="Blast <blast@shop.test>",
            subject="Sale", recipient="me@example.test",
            reply_to="Blast <blast@shop.test>", label_ids=["INBOX"],
            fetch_body=lambda: {"body": "Same body", "attachments": [], "links": []},
            account=acct)

    asyncio.run(run("m1", a))
    asyncio.run(run("m2", a))   # identical repeat → suppressed for alpha
    asyncio.run(run("m3", b))   # same content, different account → still alerts
    assert len(ctx.delivered_messages) == 2
    assert ctx.delivered_messages[0].startswith("EMAIL ALERT\nAccount: Alpha")
    assert ctx.delivered_messages[1].startswith("EMAIL ALERT\nAccount: Beta")


def test_resource_notice_account_scoped(plugin, ctx):
    a, b = _acct("alpha"), _acct("beta", "gmail2")
    asyncio.run(plugin._resource_notice(ctx, "gmail", "m1", "reason", account=a))
    asyncio.run(plugin._resource_notice(ctx, "gmail", "m2", "reason", account=a))
    asyncio.run(plugin._resource_notice(ctx, "gmail", "m3", "reason", account=b))
    assert len(ctx.delivered_messages) == 2
    assert "Account: Alpha" in ctx.delivered_messages[0]
    assert "Account: Beta" in ctx.delivered_messages[1]
    assert ctx.state.get("acct_alpha_resource_notice_day") is not None
    assert ctx.state.get("resource_notice_day") is None


# ---------------------------------------------------------------- IMAP multi-account

class _FakeIMAP:
    def __init__(self, uids, raws, uidvalidity=1):
        self.uids = list(uids)
        self.raws = dict(raws)
        self.uidvalidity = uidvalidity
        self.selected = None

    def login(self, user, password):
        self.login_args = (user, password)
        return ("OK", [])

    def select(self, folder, readonly=False):
        self.selected = (folder, readonly)
        return ("OK", [b"1"])

    def response(self, code):
        if code == "UIDVALIDITY":
            return ("UIDVALIDITY", [str(self.uidvalidity).encode()])
        return (None, [])

    def uid(self, command, *args):
        if command == "SEARCH":
            criterion = args[-1]
            if criterion == "ALL":
                sel = self.uids
            else:
                start = int(criterion.split()[1].split(":")[0])
                sel = [u for u in self.uids if u >= start]
            return ("OK", [b" ".join(str(u).encode() for u in sel)])
        if command == "FETCH":
            uid = int(args[0])
            if "RFC822.SIZE" in args[1]:
                return ("OK", [(f"{uid} (RFC822.SIZE {len(self.raws[uid])})".encode(), b"")])
            return ("OK", [(f"{uid} (BODY[] literal".encode(), self.raws[uid])])
        raise AssertionError(command)

    def logout(self):
        return ("BYE", [])

    def shutdown(self):
        pass


def _rfc822(subject="Hello", plain="A short note."):
    return (f"From: Alice <alice@example.test>\r\nTo: me@example.test\r\n"
            f"Subject: {subject}\r\nMIME-Version: 1.0\r\n"
            f"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n{plain}").encode()


def test_imap_multi_account_cursors_and_tags(plugin, ctx, monkeypatch):
    _freeze(plugin, monkeypatch)
    imap_mod = plugin._load_imap_module()
    a = {"id": "imapone", "label": "Imapone", "provider": "imap", "enabled": True,
         "password_env": "INBOX_SENTINEL_IMAP_PASSWORD",
         "imap_host": "one.imap.test", "imap_port": 993, "imap_ssl": True,
         "imap_user": "me@one.test", "imap_folder": "INBOX",
         "importance_profile": "", "delivery_target": ""}
    b = dict(a, id="imaptwo", label="Imaptwo",
             password_env="INBOX_SENTINEL_IMAP_PASSWORD2",
             imap_host="two.imap.test", imap_user="me@two.test")
    clients = {"imapone": _FakeIMAP([10], {}), "imaptwo": _FakeIMAP([20], {})}
    secrets = {"INBOX_SENTINEL_IMAP_PASSWORD": "pw1",
               "INBOX_SENTINEL_IMAP_PASSWORD2": "pw2"}
    seen_envs = []

    def fake_secret(env_name="INBOX_SENTINEL_IMAP_PASSWORD"):
        seen_envs.append(env_name)
        return secrets[env_name]

    monkeypatch.setattr(imap_mod.imaplib, "IMAP4_SSL",
                        lambda host, port, **kw: clients["imapone" if host == "one.imap.test" else "imaptwo"])
    monkeypatch.setattr(imap_mod, "_get_imap_password", fake_secret)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")

    asyncio.run(imap_mod.tick(ctx, account=a))   # baselines
    asyncio.run(imap_mod.tick(ctx, account=b))
    assert ctx.state.get("acct_imapone_imap_last_uid") == 10
    assert ctx.state.get("acct_imaptwo_imap_last_uid") == 20
    assert ctx.state.get("imap_last_uid") is None  # legacy key untouched

    clients["imapone"].uids.append(11)
    clients["imapone"].raws[11] = _rfc822()
    clients["imaptwo"].uids.append(21)
    clients["imaptwo"].raws[21] = _rfc822(subject="Other")
    asyncio.run(imap_mod.tick(ctx, account=a))
    asyncio.run(imap_mod.tick(ctx, account=b))
    assert len(ctx.delivered_messages) == 2
    assert ctx.delivered_messages[0].startswith("EMAIL ALERT\nAccount: Imapone")
    assert ctx.delivered_messages[1].startswith("EMAIL ALERT\nAccount: Imaptwo")
    assert "msgid: imap:11" in ctx.delivered_messages[0]
    assert "msgid: imap:21" in ctx.delivered_messages[1]
    assert ctx.state.get("acct_imapone_imap_last_uid") == 11
    assert ctx.state.get("acct_imaptwo_imap_last_uid") == 21
    assert seen_envs == ["INBOX_SENTINEL_IMAP_PASSWORD", "INBOX_SENTINEL_IMAP_PASSWORD2"] * 2
    assert clients["imapone"].login_args == ("me@one.test", "pw1")
    assert clients["imaptwo"].login_args == ("me@two.test", "pw2")
    # readonly selection invariant holds for both accounts
    assert clients["imapone"].selected == ("INBOX", True)
    assert clients["imaptwo"].selected == ("INBOX", True)


def test_imap_uidvalidity_reset_is_account_scoped(plugin, ctx, monkeypatch):
    _freeze(plugin, monkeypatch)
    imap_mod = plugin._load_imap_module()
    a = {"id": "imapone", "label": "Imapone", "provider": "imap", "enabled": True,
         "password_env": "INBOX_SENTINEL_IMAP_PASSWORD",
         "imap_host": "one.imap.test", "imap_port": 993, "imap_ssl": True,
         "imap_user": "me@one.test", "imap_folder": "INBOX",
         "importance_profile": "", "delivery_target": ""}
    b = dict(a, id="imaptwo", label="Imaptwo", imap_host="two.imap.test",
             password_env="INBOX_SENTINEL_IMAP_PASSWORD2")
    clients = {"imapone": _FakeIMAP([10], {}), "imaptwo": _FakeIMAP([20], {})}

    monkeypatch.setattr(imap_mod.imaplib, "IMAP4_SSL",
                        lambda host, port, **kw: clients["imapone" if host == "one.imap.test" else "imaptwo"])
    monkeypatch.setattr(imap_mod, "_get_imap_password", lambda env_name="x": "pw")
    asyncio.run(imap_mod.tick(ctx, account=a))
    asyncio.run(imap_mod.tick(ctx, account=b))
    clients["imapone"].uidvalidity = 99   # server reset on account one only
    clients["imapone"].uids = [5]
    asyncio.run(imap_mod.tick(ctx, account=a))
    asyncio.run(imap_mod.tick(ctx, account=b))
    # alpha re-baselined at the new max UID; beta cursor untouched
    assert ctx.state.get("acct_imapone_imap_last_uid") == 5
    assert ctx.state.get("acct_imapone_imap_uidvalidity") == 99
    assert ctx.state.get("acct_imaptwo_imap_last_uid") == 20
    assert ctx.state.get("acct_imaptwo_imap_uidvalidity") == 1
    assert ctx.delivered_messages == []   # re-baseline never alerts old mail
