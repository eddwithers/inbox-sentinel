"""Shared fixtures for Inbox Sentinel behaviour tests.

The plugin module imports ``hermes_cli.plugin_provider_requests`` at module
top. Hermes' own install tree ships that package, so we add it to
``sys.path`` at conftest-load time (before pytest collects the test module).
The plugin is loaded as a fresh module under a synthetic name
(``inbox_sentinel_plugin_under_test``) so we don't collide with any real
install.

Everything that would reach the network, the filesystem under ~/.hermes, or
the real LLM is injected via a hand-rolled ``ctx`` double and ``monkeypatch``.
"""
from __future__ import annotations

import base64
import importlib.util
import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_PATH = REPO_ROOT / "__init__.py"


def _candidate_hermes_cli_roots():
    env = os.environ.get("HERMES_CLI_ROOT")
    if env:
        yield Path(env)
    # Installed hermes-agent checkout (standard Hermes layout).
    yield Path.home() / ".hermes" / "hermes-agent"


def _ensure_hermes_cli_on_path():
    """Make ``hermes_cli.*`` importable; try the standard Hermes install.

    Runs at conftest import time so the plugin module (which imports
    ``hermes_cli`` at top level) can itself be imported by pytest's
    collector.
    """
    try:
        import hermes_cli  # noqa: F401
        return True
    except ImportError:
        pass
    for root in _candidate_hermes_cli_roots():
        if (root / "hermes_cli" / "__init__.py").exists():
            sys.path.insert(0, str(root))
            try:
                import hermes_cli  # noqa: F401
                return True
            except ImportError:
                continue
    return False


_HERMES_CLI_OK = _ensure_hermes_cli_on_path()


def pytest_collectstart(collector):
    if not _HERMES_CLI_OK:
        pytest.skip("hermes_cli not importable; set HERMES_CLI_ROOT")


@pytest.fixture()
def plugin():
    """Load the plugin module fresh for each test (no shared state)."""
    spec = importlib.util.spec_from_file_location(
        "inbox_sentinel_plugin_under_test", PLUGIN_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Reset the module-level watcher registry between tests.
    mod._WATCHERS.clear()
    return mod


# ---------------------------------------------------------------- ctx double

class DictState:
    """Dict-backed stand-in for ``ctx.state()`` with get/set, no persistence."""
    def __init__(self, store: dict):
        self._store = store

    def get(self, key, default=None):
        return self._store.get(key, default)

    def set(self, key, value):
        self._store[key] = value

    def __call__(self):
        return self


class StubLLM:
    def __init__(self):
        # Callables let tests change behaviour per-call.
        self.structured_result = None   # object with .parsed attribute, or callable
        self.complete_result = None     # object with .text attribute, or callable
        self.structured_calls = []
        self.complete_calls = []

    async def acomplete_structured(self, **kwargs):
        self.structured_calls.append(kwargs)
        r = self.structured_result
        return r(**kwargs) if callable(r) else r

    async def acomplete(self, **kwargs):
        self.complete_calls.append(kwargs)
        r = self.complete_result
        return r(**kwargs) if callable(r) else r


class StubCtx:
    def __init__(self):
        self.profile_name = "default"
        self.config = {}
        self._state_store = {}
        self._state = DictState(self._state_store)
        self.llm = StubLLM()
        self.injected_messages = []
        self.delivered_messages = []
        self.inject_return = True
        self.spawn_task_raises = True
        self.spawned = []
        self.tools = {}
        self.hooks = {}
        self.unload_callbacks = []
        self.skills = {}
        self.aux_tasks = {}

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    @property
    def state(self):
        return self._state

    def inject_message(self, text):
        self.injected_messages.append(text)
        return self.inject_return

    def spawn_task(self, coro, name=None):
        self.spawned.append((name, coro))
        if self.spawn_task_raises:
            # Match the "no running loop" contract: the plugin guards
            # ``asyncio.get_running_loop`` before calling spawn_task, so the
            # only way we see it get called in a test is if the guard passed.
            # We still want tests that *bypass* the guard to see a loud error.
            raise RuntimeError("no running event loop in test")
        return _FakeTask()

    # plugin registration surface
    def register_tool(self, name, toolset, schema, handler, description, **kwargs):
        self.tools[name] = {"toolset": toolset, "schema": schema,
                            "handler": handler, "description": description,
                            **kwargs}

    def register_hook(self, name, cb):
        self.hooks.setdefault(name, []).append(cb)

    def register_skill(self, name, path):
        self.skills[name] = path

    def register_auxiliary_task(self, key, *, display_name, description, defaults=None, inherit_from=None):
        self.aux_tasks[key] = {
            "display_name": display_name,
            "description": description,
            "defaults": defaults,
            "inherit_from": inherit_from,
        }
        return {"key": key}

    def on_unload(self, cb):
        self.unload_callbacks.append(cb)


class _FakeTask:
    def __init__(self):
        self._done = False
    def add_done_callback(self, callback):
        self._callback = callback
    def cancel(self):
        self._done = True
        if hasattr(self, '_callback'):
            self._callback(self)
    def done(self):
        return self._done


@pytest.fixture()
def ctx():
    return StubCtx()


@pytest.fixture()
def capture_notifications(plugin, ctx, monkeypatch, request):
    if request.node.name.startswith("test_deliver"):
        return

    async def record_delivery(_ctx, text):
        ctx.delivered_messages.append(text)

    monkeypatch.setattr(plugin, "_deliver", record_delivery)


# ---------------------------------------------------------------- gmail stub

class GmailStub:
    """Sequenced responses keyed by (method, path) prefix.

    Each entry is a list consumed in order; falls back to a default or raises
    if nothing matches.
    """
    def __init__(self):
        self.calls = []
        self.handlers = {}  # key -> list[dict | Exception | callable]

    def respond(self, method, path_prefix, response):
        self.handlers.setdefault((method, path_prefix), []).append(response)

    def __call__(self, method, path, params=()):
        self.calls.append((method, path, list(params)))
        # Find the most specific prefix match.
        best = None
        for (m, p), queue in self.handlers.items():
            if m == method and path.startswith(p) and queue:
                if best is None or len(p) > len(best[0][1]):
                    best = ((m, p), queue)
        if best is None:
            raise AssertionError(f"GmailStub: unexpected call {method} {path}")
        queue = best[1]
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(method, path, params)
        return item


@pytest.fixture()
def gmail(plugin, monkeypatch):
    stub = GmailStub()
    monkeypatch.setattr(plugin, "_gmail", stub)
    return stub


# ---------------------------------------------------------------- raw email helpers

def make_raw(subject="Test subject", sender="Alice <alice@example.test>",
             to="me@example.test", plain=None, html=None):
    """Assemble a base64url Gmail 'raw' payload."""
    if plain is not None and html is not None:
        boundary = "BOUND"
        body = (
            f'From: {sender}\r\n'
            f'To: {to}\r\n'
            f'Subject: {subject}\r\n'
            f'MIME-Version: 1.0\r\n'
            f'Content-Type: multipart/alternative; boundary="{boundary}"\r\n\r\n'
            f'--{boundary}\r\n'
            f'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            f'{plain}\r\n'
            f'--{boundary}\r\n'
            f'Content-Type: text/html; charset="utf-8"\r\n\r\n'
            f'{html}\r\n'
            f'--{boundary}--\r\n'
        )
    elif html is not None:
        body = (
            f'From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n'
            f'MIME-Version: 1.0\r\n'
            f'Content-Type: text/html; charset="utf-8"\r\n\r\n{html}'
        )
    else:
        body = (
            f'From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n'
            f'MIME-Version: 1.0\r\n'
            f'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            f'{plain or ""}'
        )
    return base64.urlsafe_b64encode(body.encode("utf-8")).decode("ascii")


def meta_response(sender="Alice <alice@example.test>",
                  subject="Hello",
                  reply_to=None,
                  to="me@example.test",
                  delivered_to="me@example.test",
                  label_ids=("INBOX",),
                  size_estimate=1000):
    headers = [
        {"name": "From", "value": sender},
        {"name": "Subject", "value": subject},
        {"name": "To", "value": to},
        {"name": "Delivered-To", "value": delivered_to},
    ]
    if reply_to:
        headers.append({"name": "Reply-To", "value": reply_to})
    return {
        "payload": {"headers": headers},
        "labelIds": list(label_ids),
        "sizeEstimate": size_estimate,
    }


class ParsedBox:
    """Minimal stand-in for an LLM structured-response object (.parsed)."""
    def __init__(self, parsed):
        self.parsed = parsed


class TextBox:
    def __init__(self, text):
        self.text = text
