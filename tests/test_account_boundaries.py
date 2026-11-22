"""M2 fail-closed account boundaries and real host integration tests."""
import asyncio
import json
from types import SimpleNamespace
import pytest
from conftest import StubCtx


def test_duplicate_grant_is_rejected(plugin, ctx, gmail):
    ctx.config["accounts"] = json.dumps([{"id": "one"}, {"id": "two"}])
    with pytest.raises(plugin.AccountConfigurationError):
        asyncio.run(plugin._tick(ctx))
    assert gmail.calls == []


@pytest.mark.parametrize("raw", ["[]", '[{"id":"one","enabled":false}]'])
def test_empty_or_disabled_registry_never_falls_back(plugin, ctx, gmail, raw):
    ctx.config["accounts"] = raw
    asyncio.run(plugin._tick(ctx))
    assert gmail.calls == []


@pytest.mark.parametrize("raw", ["{bad", 3, "[" * 1500, '[{"id":"a","unknown":1}]'])
def test_bad_config_is_private_and_closed(plugin, ctx, gmail, raw):
    ctx.config["accounts"] = raw
    with pytest.raises(plugin.AccountConfigurationError):
        asyncio.run(plugin._tick(ctx))
    assert gmail.calls == []
    assert plugin._status(ctx)["last_error"] == "Invalid accounts configuration; polling stopped"


def test_connection_change_cannot_reuse_cursor(plugin, ctx, monkeypatch):
    calls = []
    async def poll(ctx, account=None):
        calls.append(account["oauth_id"])
    monkeypatch.setattr(plugin, "_tick_gmail", poll)
    acct = {"id":"one", "label":"One", "enabled":True, "provider":"gmail", "oauth_id":"gmail"}
    asyncio.run(plugin._tick_account(ctx, acct))
    ctx.state.set("acct_one_history_id", "old")
    asyncio.run(plugin._tick_account(ctx, dict(acct, oauth_id="gmail2")))
    assert calls == ["gmail"]
    assert ctx.state.get("acct_one_history_id") == "old"
    assert "new account id" in ctx.state.get("acct_one_last_error")


def test_same_ids_in_separate_profiles_remain_isolated(plugin, ctx, gmail):
    other = StubCtx()
    other.profile_name = "other"
    acct = {"id":"one", "label":"One", "enabled":True, "provider":"gmail", "oauth_id":"gmail"}
    for c, cursor in [(ctx, "first"), (other, "second")]:
        gmail.respond("GET", "/users/me/profile", {"historyId":cursor})
        gmail.respond("GET", "/users/me/messages", {"messages":[]})
        gmail.respond("GET", "/users/me/history", {"historyId":cursor, "history":[]})
        asyncio.run(plugin._tick_account(c, acct))
    assert ctx.state.get("acct_one_history_id") == "first"
    assert other.state.get("acct_one_history_id") == "second"


def test_gmail_transport_uses_exact_grant(plugin, monkeypatch):
    calls = []
    def request(provider, method, url, **kwargs):
        calls.append((provider, method, url))
        return SimpleNamespace(status=200, json=lambda: {})
    monkeypatch.setattr(plugin, "credentialed_provider_request", request)
    plugin._gmail("GET", "/users/me/profile", oauth_id="gmail2")
    assert calls == [("gmail2", "GET", plugin.GMAIL + "/users/me/profile")]


@pytest.mark.parametrize("key", ["accounts", "client_secret", "imap_password", "delivery_target"])
def test_modules_cannot_read_connection_config(plugin, ctx, key):
    ctx.config[key] = "private"
    with pytest.raises(PermissionError):
        plugin._ModuleAPI(ctx, "inboxswitch").config_get(key)


def test_disabled_account_guard_is_host_owned(plugin, ctx, monkeypatch):
    ctx.config["module_inboxswitch_enabled"] = False
    def fetch():
        pytest.fail("disabled account content fetched")
    asyncio.run(plugin._run_pipeline(ctx, mid_prefix="gmail", mid="same", sender="a@example.test",
        subject="Hello", recipient="b@example.test", reply_to="a@example.test", label_ids=[],
        fetch_body=fetch, account={"id":"one", "enabled":False, "label":"One"}))


def test_auth_failure_does_not_consume_message_retry(plugin, ctx, gmail):
    ctx.state.set("acct_one_history_id", "old")
    ctx.state.set("acct_one_pending_message_ids", ["same"])
    gmail.respond("GET", "/users/me/messages/same", plugin.ProviderNotSignedIn("expired"))
    acct = {"id":"one", "label":"One", "enabled":True, "provider":"gmail", "oauth_id":"gmail", "gmail_query":""}
    with pytest.raises(plugin.ProviderNotSignedIn):
        asyncio.run(plugin._tick_gmail(ctx, account=acct))
    assert ctx.state.get("acct_one_pending_message_ids") == ["same"]
    assert ctx.state.get("acct_one_fails") == {}


def test_declared_scopes_malformed_are_refused(plugin):
    for scopes in (None, "gmail.readonly", {"gmail.modify": True}, 42):
        assert not plugin._module_scopes_ok(SimpleNamespace(SCOPES=scopes))


def test_broken_inboxswitch_tag_uses_host_fallback(plugin, ctx, monkeypatch):
    from conftest import ParsedBox
    ctx.delivered_messages = []
    async def deliver(ctx, text, account=None):
        ctx.delivered_messages.append(text)
    monkeypatch.setattr(plugin, "_deliver", deliver)
    def broken(message, api):
        raise RuntimeError("fixture bug")
    monkeypatch.setattr(plugin._modules()["inboxswitch"], "post_gate", broken)
    ctx.config["draft_replies"] = False
    ctx.llm.structured_result = ParsedBox({"verdict":"IMPORTANT", "summary":"Note."})
    asyncio.run(plugin._run_pipeline(ctx, mid_prefix="gmail", mid="same",
        sender="a@example.test", subject="Hello", recipient="b@example.test",
        reply_to="a@example.test", label_ids=[], fetch_body=lambda: "Note.",
        account={"id":"one", "enabled":True, "label":"<b>@tag</b>"}))
    assert "Account: " + plugin._safe_text("<b>@tag</b>", 60) in ctx.delivered_messages[0]


def test_account_query_excludes_before_body_read(plugin, ctx, gmail):
    account = {"id":"one", "enabled":True, "oauth_id":"gmail2", "gmail_query":"label:scope"}
    gmail.respond("GET", "/users/me/messages", {"messages":[]}, oauth_id="gmail2")
    asyncio.run(plugin._process(ctx, "outside", account=account))
    assert len(gmail.calls) == 1
    assert gmail.calls[0][3] == "gmail2"
    assert ("q", "in:inbox (label:scope)") in gmail.calls[0][2]
    assert ctx.llm.structured_calls == []


def test_failed_draft_spends_shared_cap_across_accounts(plugin, ctx, monkeypatch):
    from conftest import ParsedBox
    calls = []
    async def broken(**kwargs):
        calls.append(1)
        raise RuntimeError("unavailable")
    async def deliver(ctx, text, account=None):
        pass
    monkeypatch.setattr(plugin, "_deliver", deliver)
    ctx.llm.acomplete = broken
    ctx.llm.structured_result = ParsedBox({"verdict":"IMPORTANT", "summary":"Note."})
    ctx.config["daily_draft_cap"] = 1
    for aid in ("one", "two"):
        asyncio.run(plugin._run_pipeline(ctx, mid_prefix="gmail", mid="same",
            sender="a@example.test", subject="Hello", recipient="b@example.test",
            reply_to="a@example.test", label_ids=[], fetch_body=lambda: "Note.",
            account={"id":aid, "enabled":True, "label":aid}))
    assert calls == [1]
    assert ctx.state.get("budget_count") == 1
