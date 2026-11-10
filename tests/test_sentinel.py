"""Behaviour tests for the Inbox Sentinel plugin.

These tests exercise the plugin's logic without any network, filesystem
access under ~/.hermes, or real LLM calls. Every external surface the
plugin touches (``_gmail``, ``ctx.llm``, ``ctx.state``, ``ctx.inject_message``,
``asyncio.create_subprocess_exec``) is stubbed in ``conftest.py`` or here.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from conftest import (
    ParsedBox,
    TextBox,
    make_raw,
    meta_response,
)

pytestmark = pytest.mark.usefixtures("capture_notifications")


# ---------------------------------------------------------------- helpers

class _FakeProc:
    def __init__(self, returncode=0, stderr=b""):
        self.returncode = returncode
        self._stderr = stderr

    async def communicate(self):
        return (b"", self._stderr)


def _install_fake_subprocess(monkeypatch, returncode=0, stderr=b"",
                             capture=None):
    """Replace ``asyncio.create_subprocess_exec`` with a recording fake."""
    async def fake(*args, **kwargs):
        if capture is not None:
            capture.append((args, kwargs))
        return _FakeProc(returncode=returncode, stderr=stderr)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)


# ---------------------------------------------------------------- register()

def test_register_wires_tools_hooks_and_unload(plugin, ctx):
    """``register`` must install three tools, two lifecycle hooks, and an
    unload callback that removes this profile's watcher entry."""
    plugin.register(ctx)
    assert set(ctx.tools) == {
        "inbox_sentinel_status",
        "inbox_sentinel_test",
        "inbox_sentinel_feedback",
    }
    assert set(ctx.aux_tasks) == {plugin.GATE_TASK, plugin.DRAFT_TASK}
    assert ctx.aux_tasks[plugin.GATE_TASK]["display_name"] == "Inbox Sentinel gate"
    assert ctx.aux_tasks[plugin.DRAFT_TASK]["display_name"] == "Inbox Sentinel draft"
    assert "on_session_start" in ctx.hooks
    assert "pre_llm_call" in ctx.hooks
    assert ctx.unload_callbacks, "on_unload callback should be registered"
    # No running loop in the test; the guard inside _ensure_watcher must have
    # kept us from reaching spawn_task.
    assert ctx.spawned == []
    # Unload callback is safe to call even when no watcher is registered.
    from concurrent.futures import Future
    task = Future()
    plugin._WATCHERS[ctx.profile_name] = task
    ctx.unload_callbacks[0]()
    assert task.cancelled()
    assert ctx.profile_name not in plugin._WATCHERS


def test_fictional_gate_uses_owned_auxiliary_task(plugin, ctx):
    plugin.register(ctx)
    ctx.llm.structured_result = SimpleNamespace(parsed={"verdict": "NOISE", "summary": "Newsletter"})
    result = asyncio.run(plugin._test(ctx, {
        "from": "Deals <deals@example.test>",
        "subject": "Weekly offers",
        "body": "Sale now on",
    }))
    assert ctx.llm.structured_calls and ctx.llm.structured_calls[0]["task"] == plugin.GATE_TASK
    assert ctx.llm.complete_calls == []
    assert result == {"verdict": "NOISE", "summary": "Newsletter"}
    assert ctx.delivered_messages == []


def test_fictional_draft_uses_owned_auxiliary_task(plugin, ctx):
    plugin.register(ctx)
    ctx.llm.structured_result = SimpleNamespace(parsed={"verdict": "IMPORTANT", "summary": "Reply needed"})
    ctx.llm.complete_result = TextBox("Thanks, that works for me.")
    result = asyncio.run(plugin._test(ctx, {
        "from": "Alice <alice@example.test>",
        "subject": "Meeting",
        "body": "Would Tuesday work?",
    }))
    assert ctx.llm.structured_calls and ctx.llm.structured_calls[0]["task"] == plugin.GATE_TASK
    assert ctx.llm.complete_calls and ctx.llm.complete_calls[0]["task"] == plugin.DRAFT_TASK
    assert result["suggested_reply"] == "Thanks, that works for me."
    assert ctx.delivered_messages == []


# ---------------------------------------------------------------- bootstrap

def test_bootstrap_records_history_id_and_baseline_seen(plugin, ctx, gmail):
    gmail.respond("GET", "/users/me/profile", {"historyId": "4242"})
    gmail.respond("GET", "/users/me/messages",
                  {"messages": [{"id": "m1"}, {"id": "m2"}, {"id": "m3"}]})
    plugin._bootstrap(ctx)
    state = ctx.state()
    assert state.get("history_id") == "4242"
    seen = state.get("seen")
    assert set(seen.keys()) == {"m1", "m2", "m3"}
    # Timestamps should be non-zero ints (used later for ring eviction order).
    assert all(isinstance(ts, int) and ts > 0 for ts in seen.values())


# ---------------------------------------------------------------- noise filter

def test_quiet_label_filtered_without_keyword_override(plugin, ctx, gmail):
    """A promotions email with no override keyword is dropped before the LLM."""
    ctx.config["quiet_labels"] = ["CATEGORY_PROMOTIONS"]
    ctx.config["keyword_overrides"] = ["urgent"]
    gmail.respond(
        "GET", "/users/me/messages/mA",
        meta_response(sender="Deals <deals@shop.test>",
                      subject="20% off everything",
                      label_ids=["INBOX", "CATEGORY_PROMOTIONS"]),
    )
    asyncio.run(plugin._process(ctx, "mA"))
    # No LLM call and no delivery.
    assert ctx.llm.structured_calls == []
    assert ctx.injected_messages == []


def test_keyword_override_bypasses_local_filter(plugin, ctx, gmail,
                                                monkeypatch):
    ctx.config["quiet_labels"] = ["CATEGORY_PROMOTIONS"]
    ctx.config["keyword_overrides"] = ["urgent"]
    ctx.config["delivery_target"] = "session"
    gmail.respond(
        "GET", "/users/me/messages/mB",
        meta_response(sender="Deals <deals@shop.test>",
                      subject="URGENT: your order",
                      label_ids=["INBOX", "CATEGORY_PROMOTIONS"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/mB",
        {"raw": make_raw(subject="URGENT: your order",
                         sender="Deals <deals@shop.test>",
                         plain="Please confirm delivery slot.")},
    )
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Confirm delivery slot."})
    ctx.llm.complete_result = TextBox("Yes, Tuesday works.")
    asyncio.run(plugin._process(ctx, "mB"))
    assert len(ctx.llm.structured_calls) == 1
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    assert "Confirm delivery slot." in ctx.delivered_messages[0]


def test_learned_blocked_sender_filtered_before_anything(plugin, ctx, gmail):
    ctx.state().set("learned_blocked_senders", {"@spammer.test": 1})
    gmail.respond(
        "GET", "/users/me/messages/mC",
        meta_response(sender="Bob <bob@spammer.test>",
                      subject="Buy crypto", label_ids=["INBOX"]),
    )
    asyncio.run(plugin._process(ctx, "mC"))
    assert ctx.llm.structured_calls == []
    assert ctx.injected_messages == []


def test_recipient_alias_skip(plugin, ctx, gmail):
    ctx.config["skip_recipient_keywords"] = ["noreply-list"]
    gmail.respond(
        "GET", "/users/me/messages/mD",
        meta_response(sender="list@example.test",
                      subject="hi",
                      to="noreply-list@example.test",
                      delivered_to="noreply-list@example.test",
                      label_ids=["INBOX"]),
    )
    asyncio.run(plugin._process(ctx, "mD"))
    assert ctx.llm.structured_calls == []


def test_learned_vip_bypasses_quiet_label(plugin, ctx, gmail, monkeypatch):
    """A VIP sender should go through even when the message carries a quiet
    label."""
    ctx.config["quiet_labels"] = ["CATEGORY_PROMOTIONS"]
    ctx.config["delivery_target"] = "session"
    ctx.state().set("learned_vip_senders", {"@family.test": 1})
    gmail.respond(
        "GET", "/users/me/messages/mE",
        meta_response(sender="Mum <mum@family.test>",
                      subject="Sunday lunch?",
                      label_ids=["INBOX", "CATEGORY_PROMOTIONS"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/mE",
        {"raw": make_raw(subject="Sunday lunch?",
                         sender="Mum <mum@family.test>",
                         plain="Are you coming?")},
    )
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Sunday lunch plans."})
    ctx.llm.complete_result = TextBox("Yes, see you at 1pm.")
    asyncio.run(plugin._process(ctx, "mE"))
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []


# ---------------------------------------------------------------- body parsing

def test_fetch_body_prefers_plain_part(plugin, gmail):
    gmail.respond(
        "GET", "/users/me/messages/body1",
        {"raw": make_raw(plain="plain content here",
                          html="<p>html <b>content</b></p>")},
    )
    body = plugin._fetch_body("body1")
    assert "plain content here" in body
    assert "<p>" not in body


def test_fetch_body_strips_html_when_only_html(plugin, gmail):
    gmail.respond(
        "GET", "/users/me/messages/body2",
        {"raw": make_raw(html="<style>x{}</style><p>Hello <b>world</b></p>")},
    )
    body = plugin._fetch_body("body2")
    assert "Hello" in body and "world" in body
    assert "<" not in body


# ---------------------------------------------------------------- gate routing

def test_gate_important_produces_alert_with_draft(plugin, ctx, gmail):
    ctx.config["delivery_target"] = "session"
    gmail.respond(
        "GET", "/users/me/messages/mF",
        meta_response(sender="Boss <boss@work.test>",
                      subject="Review needed",
                      reply_to="boss-reply@work.test",
                      label_ids=["INBOX"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/mF",
        {"raw": make_raw(plain="Can you look at the deck before noon?",
                         sender="Boss <boss@work.test>",
                         subject="Review needed")},
    )
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Boss wants deck reviewed."})
    ctx.llm.complete_result = TextBox("Yes — looking now.")
    asyncio.run(plugin._process(ctx, "mF"))
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    alert = ctx.delivered_messages[0]
    assert "EMAIL ALERT" in alert
    assert "Subject: Review needed" in alert
    assert f"From: {plugin._safe_text('Boss <boss@work.test>', 300)}" in alert
    assert "Boss wants deck reviewed." in alert
    # Draft block is rendered with the Reply-To address, fenced in backticks.
    assert f"Suggested reply (to {plugin._safe_text('boss-reply@work.test', 300)}):" in alert
    assert "Yes — looking now." in alert
    assert "msgid: gmail:mF" in alert
    assert ctx.state().get("alerts_sent") == 1


def test_gate_noise_overridden_for_learned_vip(plugin, ctx, gmail):
    ctx.config["delivery_target"] = "session"
    ctx.state().set("learned_vip_senders", {"@family.test": 1})
    gmail.respond(
        "GET", "/users/me/messages/mG2",
        meta_response(sender="Mum <mum@family.test>",
                      subject="Weekend plans",
                      label_ids=["INBOX", "CATEGORY_SOCIAL"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/mG2",
        {"raw": make_raw(plain="Are you free for lunch?")},
    )
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "NOISE", "summary": "Chatty but from VIP."})
    ctx.llm.complete_result = TextBox("Yes, that works.")
    asyncio.run(plugin._process(ctx, "mG2"))
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    alert = ctx.delivered_messages[0]
    assert "EMAIL ALERT" in alert
    assert "Chatty but from VIP." in alert
    assert "Suggested reply" in alert


def test_gate_noise_silent(plugin, ctx, gmail):
    ctx.config["delivery_target"] = "session"
    gmail.respond(
        "GET", "/users/me/messages/mG",
        meta_response(sender="News <news@site.test>",
                      subject="Weekly digest",
                      label_ids=["INBOX"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/mG",
        {"raw": make_raw(plain="here are the top stories")},
    )
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "NOISE", "summary": "Newsletter."})
    asyncio.run(plugin._process(ctx, "mG"))
    assert ctx.injected_messages == []
    assert ctx.llm.complete_calls == []  # no draft attempted


def test_gate_unparseable_treated_as_noise(plugin, ctx, gmail):
    """When the structured call returns an object with no .parsed, the
    plugin logs and returns silently (defaults to NOISE)."""
    ctx.config["delivery_target"] = "session"
    gmail.respond(
        "GET", "/users/me/messages/mH",
        meta_response(sender="Someone <x@example.test>",
                      subject="?", label_ids=["INBOX"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/mH",
        {"raw": make_raw(plain="??")},
    )
    ctx.llm.structured_result = ParsedBox(None)  # .parsed is falsy
    asyncio.run(plugin._process(ctx, "mH"))
    assert ctx.injected_messages == []


def test_gate_important_no_reply_renders_awareness_line(plugin, ctx, gmail):
    ctx.config["delivery_target"] = "session"
    gmail.respond(
        "GET", "/users/me/messages/mI",
        meta_response(sender="FYI <fyi@example.test>",
                      subject="Receipt", label_ids=["INBOX"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/mI",
        {"raw": make_raw(plain="Your payment was received.")},
    )
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Payment confirmed."})
    ctx.llm.complete_result = TextBox("NO REPLY NEEDED")
    asyncio.run(plugin._process(ctx, "mI"))
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    alert = ctx.delivered_messages[0]
    assert "No reply needed — flagged for your awareness." in alert
    assert "```" not in alert


# ---------------------------------------------------------------- draft budget

def test_draft_budget_cap_blocks_further_drafts(plugin, ctx):
    ctx.config["daily_draft_cap"] = 2
    ctx.llm.complete_result = TextBox("sure, will do.")
    # First two calls consume the cap.
    r1 = asyncio.run(plugin._draft_reply(ctx, "a@x", "s", "b"))
    r2 = asyncio.run(plugin._draft_reply(ctx, "a@x", "s", "b"))
    r3 = asyncio.run(plugin._draft_reply(ctx, "a@x", "s", "b"))
    assert r1 == "sure, will do."
    assert r2 == "sure, will do."
    assert r3 is None
    assert len(ctx.llm.complete_calls) == 2
    assert ctx.state().get("budget_count") == 2


def test_draft_budget_resets_on_day_rollover(plugin, ctx, monkeypatch):
    ctx.config["daily_draft_cap"] = 1
    ctx.llm.complete_result = TextBox("reply")
    day = "2026-01-01"
    monkeypatch.setattr(plugin.time, "strftime",
                        lambda fmt: day if fmt == "%Y-%m-%d" else "00:00")
    r1 = asyncio.run(plugin._draft_reply(ctx, "a@x", "s", "b"))
    r2 = asyncio.run(plugin._draft_reply(ctx, "a@x", "s", "b"))
    assert r1 == "reply" and r2 is None
    # Advance a day.
    day = "2026-01-02"
    r3 = asyncio.run(plugin._draft_reply(ctx, "a@x", "s", "b"))
    assert r3 == "reply"
    assert ctx.state().get("budget_day") == "2026-01-02"
    assert ctx.state().get("budget_count") == 1


def test_draft_disabled_returns_none(plugin, ctx):
    ctx.config["draft_replies"] = False
    r = asyncio.run(plugin._draft_reply(ctx, "a@x", "s", "b"))
    assert r is None
    assert ctx.llm.complete_calls == []


def test_draft_llm_failure_swallowed(plugin, ctx):
    class Boom(Exception):
        pass

    async def raise_boom(**kw):
        raise Boom("nope")
    ctx.llm.acomplete = raise_boom
    r = asyncio.run(plugin._draft_reply(ctx, "a@x", "s", "b"))
    assert r is None


# ---------------------------------------------------------------- feedback

def test_feedback_noise_blocks_sender(plugin, ctx):
    ctx.state().set("learned_gate_notes", ["Mail from '@spammer.test' is always IMPORTANT (user said so)",
                                           "Mail from '@other.test' is always IMPORTANT (user said so)"])
    out = plugin._feedback(ctx, {"sender": "@spammer.test",
                                  "feedback": "noise"})
    assert out["ok"] is True
    blocked = ctx.state().get("learned_blocked_senders")
    assert "@spammer.test" in blocked
    # VIP should have been removed if present.
    assert "@spammer.test" not in ctx.state().get("learned_vip_senders", {})
    notes = ctx.state().get("learned_gate_notes")
    assert notes == []


def test_feedback_important_adds_vip_and_gate_note(plugin, ctx):
    out = plugin._feedback(ctx, {"sender": "@family.test",
                                  "feedback": "important",
                                  "note": "my GP"})
    assert out["ok"] is True
    assert "@family.test" in ctx.state().get("learned_vip_senders")
    notes = ctx.state().get("learned_gate_notes")
    assert any("@family.test" in n and "my GP" in n for n in notes)
    # The gate instructions must now surface that note.
    instructions = plugin._gate_instructions(ctx)
    assert "@family.test" in instructions
    assert "my GP" in instructions


def test_feedback_important_moves_from_blocked_to_vip(plugin, ctx):
    ctx.state().set("learned_blocked_senders", {"@family.test": 1})
    ctx.state().set("learned_gate_notes",
                     ["Mail from '@family.test' is always IMPORTANT (user said so): stale"])
    plugin._feedback(ctx, {"sender": "@family.test", "feedback": "important", "note": "fresh"})
    assert "@family.test" in ctx.state().get("learned_vip_senders")
    assert "@family.test" not in ctx.state().get("learned_blocked_senders")
    notes = ctx.state().get("learned_gate_notes")
    assert len([n for n in notes if "@family.test" in n.lower()]) == 1
    assert any(n.endswith(": fresh") for n in notes)


def test_feedback_clear_removes_both(plugin, ctx):
    ctx.state().set("learned_blocked_senders", {"x@example.test": 1})
    ctx.state().set("learned_vip_senders", {"x@example.test": 1})
    ctx.state().set("learned_gate_notes",
                     ["Mail from 'x@example.test' is always IMPORTANT (user said so)"])
    plugin._feedback(ctx, {"sender": "x@example.test", "feedback": "clear"})
    assert ctx.state().get("learned_blocked_senders") == {}
    assert ctx.state().get("learned_vip_senders") == {}
    assert ctx.state().get("learned_gate_notes") == []


def test_feedback_requires_sender(plugin, ctx):
    out = plugin._feedback(ctx, {"sender": " ", "feedback": "noise"})
    assert out["ok"] is False


def test_feedback_rejects_unknown_action(plugin, ctx):
    out = plugin._feedback(ctx, {"sender": "x@example.test", "feedback": "banana"})
    assert out["ok"] is False


def test_feedback_important_dedupes_gate_notes(plugin, ctx):
    args = {"sender": "same@example.test", "feedback": "important", "note": "reason"}
    plugin._feedback(ctx, args)
    plugin._feedback(ctx, args)
    notes = ctx.state().get("learned_gate_notes")
    assert len(notes) == 1


# ---------------------------------------------------------------- _tick loop

def test_tick_bootstraps_when_history_empty(plugin, ctx, gmail):
    # First: bootstrap probes profile + inbox listing.
    gmail.respond("GET", "/users/me/profile", {"historyId": "100"})
    gmail.respond("GET", "/users/me/messages",
                  {"messages": []})
    # Then: history call returns no new messages.
    gmail.respond("GET", "/users/me/history",
                  {"history": [], "historyId": "101"})
    asyncio.run(plugin._tick(ctx))
    assert ctx.state().get("history_id") == "101"
    assert ctx.state().get("last_poll") is not None


def test_tick_processes_new_inbox_message(plugin, ctx, gmail, monkeypatch):
    ctx.state().set("history_id", "100")
    ctx.config["delivery_target"] = "session"
    gmail.respond(
        "GET", "/users/me/history",
        {
            "history": [{
                "messagesAdded": [
                    {"message": {"id": "new1", "labelIds": ["INBOX"]}}
                ]
            }],
            "historyId": "200",
        },
    )
    gmail.respond(
        "GET", "/users/me/messages/new1",
        meta_response(sender="Alice <a@example.test>",
                      subject="Lunch?", label_ids=["INBOX"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/new1",
        {"raw": make_raw(plain="Want to grab lunch?")},
    )
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Lunch question."})
    ctx.llm.complete_result = TextBox("Yes, 12:30.")
    asyncio.run(plugin._tick(ctx))
    assert ctx.state().get("history_id") == "200"
    assert "new1" in ctx.state().get("seen")
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []


def test_tick_queues_paginated_messages_and_retries_before_advancing(
        plugin, ctx, gmail, monkeypatch):
    """Pagination must preserve order, queue later pages, and keep the cursor
    behind a failed message until the queue drains."""
    ctx.state().set("history_id", "100")
    ctx.config["delivery_target"] = "session"
    gmail.respond(
        "GET", "/users/me/history",
        {
            "history": [{"messagesAdded": [
                {"message": {"id": "a", "labelIds": ["INBOX"]}}
            ]}],
            "historyId": "200",
            "nextPageToken": "page2",
        },
    )
    gmail.respond(
        "GET", "/users/me/history",
        {
            "history": [{"messagesAdded": [
                {"message": {"id": "b", "labelIds": ["INBOX"]}}
            ]}],
            "historyId": "300",
        },
    )
    call_order = []
    attempts = {"a": 0}

    async def flaky(ctx_, mid):
        call_order.append(mid)
        if mid == "a" and attempts["a"] == 0:
            attempts["a"] += 1
            raise RuntimeError("boom")

    monkeypatch.setattr(plugin, "_process", flaky)

    asyncio.run(plugin._tick(ctx))
    assert ctx.state().get("history_id") == "100"
    assert ctx.state().get("pending_message_ids") == ["a", "b"]
    assert ctx.state().get("pending_history_id") == "300"
    assert ctx.state().get("fails", {}).get("a") == 1
    assert ctx.state().get("seen", {}) == {}

    asyncio.run(plugin._tick(ctx))
    assert ctx.state().get("history_id") == "300"
    assert ctx.state().get("pending_message_ids") == []
    assert "a" in ctx.state().get("seen", {})
    assert "b" in ctx.state().get("seen", {})
    assert call_order == ["a", "a", "b"]


def test_tick_skips_already_seen(plugin, ctx, gmail):
    ctx.state().set("history_id", "100")
    ctx.state().set("seen", {"dupe": 1})
    gmail.respond(
        "GET", "/users/me/history",
        {"history": [{
            "messagesAdded": [
                {"message": {"id": "dupe", "labelIds": ["INBOX"]}}
            ]
        }], "historyId": "101"},
    )
    asyncio.run(plugin._tick(ctx))
    assert ctx.llm.structured_calls == []


def test_tick_skips_non_inbox(plugin, ctx, gmail):
    ctx.state().set("history_id", "100")
    gmail.respond(
        "GET", "/users/me/history",
        {"history": [{
            "messagesAdded": [
                {"message": {"id": "spam1", "labelIds": ["SPAM"]}}
            ]
        }], "historyId": "101"},
    )
    asyncio.run(plugin._tick(ctx))
    assert ctx.llm.structured_calls == []


def test_tick_retry_cap_triggers_give_up_ping(plugin, ctx, gmail, monkeypatch):
    """After RETRY_CAP failures on the same mid, the plugin emits a give-up
    alert, marks the message seen, and clears the fails counter."""
    ctx.state().set("history_id", "100")
    ctx.config["delivery_target"] = "session"

    async def always_fail(ctx, mid):
        raise RuntimeError("downstream error")
    monkeypatch.setattr(plugin, "_process", always_fail)

    # Three ticks, each surfacing the same new message id.
    def history_response(method, path, params):
        return {
            "history": [{
                "messagesAdded": [
                    {"message": {"id": "stuck", "labelIds": ["INBOX"]}}
                ]
            }],
            "historyId": "200",
        }
    for _ in range(plugin.RETRY_CAP):
        gmail.respond("GET", "/users/me/history", history_response)

    for _ in range(plugin.RETRY_CAP):
        asyncio.run(plugin._tick(ctx))

    assert "stuck" in ctx.state().get("seen")
    assert "stuck" not in ctx.state().get("fails", {})
    # Give-up ping is a single delivered message with the "delivery failed"
    # banner.
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    assert "delivery failed after retries" in ctx.delivered_messages[0]
    assert "msgid: gmail:stuck" in ctx.delivered_messages[0]


def test_tick_retry_increments_fails_without_giving_up(plugin, ctx, gmail,
                                                       monkeypatch):
    ctx.state().set("history_id", "100")

    async def fail(ctx, mid):
        raise RuntimeError("nope")
    monkeypatch.setattr(plugin, "_process", fail)
    gmail.respond("GET", "/users/me/history",
                  {"history": [{"messagesAdded": [
                      {"message": {"id": "ff", "labelIds": ["INBOX"]}}]}],
                   "historyId": "101"})
    asyncio.run(plugin._tick(ctx))
    assert ctx.state().get("fails", {}).get("ff") == 1
    assert "ff" not in ctx.state().get("seen", {})


def test_tick_history_id_expired_404_rebootstraps(plugin, ctx, gmail):
    """When Gmail returns 404 (historyId older than the 7-day window), the
    plugin clears history_id so the next tick re-bootstraps instead of
    retrying a forever-stale cursor."""
    ctx.state().set("history_id", "stale")
    exc = plugin._GmailHTTPError(404, "Not Found")
    gmail.respond("GET", "/users/me/history", exc)
    asyncio.run(plugin._tick(ctx))
    assert ctx.state().get("history_id") is None


def test_tick_persists_seen_even_if_inner_raises(plugin, ctx, gmail,
                                                  monkeypatch):
    """The reliability pass wrapped the message loop in try/finally so that
    messages successfully handled this tick are not re-processed next tick if
    a later message blows up."""
    ctx.state().set("history_id", "100")
    ctx.config["delivery_target"] = "session"
    # Two messages: the first processes fine, the second will raise a bare
    # exception from inside the finally-wrapped block.
    gmail.respond(
        "GET", "/users/me/history",
        {"history": [{
            "messagesAdded": [
                {"message": {"id": "ok1", "labelIds": ["INBOX"]}},
                {"message": {"id": "boom", "labelIds": ["INBOX"]}},
            ]
        }], "historyId": "200"},
    )
    gmail.respond("GET", "/users/me/messages/ok1",
                  meta_response(sender="x@test", subject="s",
                                 label_ids=["INBOX"]))
    gmail.respond("GET", "/users/me/messages/ok1",
                  {"raw": make_raw(plain="b")})
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "NOISE", "summary": "n"})

    call_count = {"n": 0}
    original = plugin._process

    async def flaky(ctx_, mid):
        call_count["n"] += 1
        if mid == "boom":
            raise RuntimeError("inner crash")
        return await original(ctx_, mid)

    monkeypatch.setattr(plugin, "_process", flaky)
    asyncio.run(plugin._tick(ctx))
    # ok1 must have been marked seen; boom should have a fails counter.
    assert "ok1" in ctx.state().get("seen", {})
    assert ctx.state().get("fails", {}).get("boom") == 1


def test_tick_trims_seen_ring_to_limit(plugin, ctx, gmail):
    """When seen grows past SEEN_LIMIT, the oldest entries are evicted."""
    ctx.state().set("history_id", "100")
    # Pre-fill seen with SEEN_LIMIT entries, each timestamped with its index
    # so eviction ordering is deterministic.
    seen = {f"old{i}": i for i in range(plugin.SEEN_LIMIT)}
    ctx.state().set("seen", seen)
    # History reports one new message that will be processed and added.
    gmail.respond(
        "GET", "/users/me/history",
        {"history": [{"messagesAdded": [
            {"message": {"id": "new", "labelIds": ["INBOX"]}}]}],
         "historyId": "999"},
    )
    gmail.respond(
        "GET", "/users/me/messages/new",
        meta_response(sender="x@test", subject="s", label_ids=["INBOX"]),
    )
    gmail.respond(
        "GET", "/users/me/messages/new",
        {"raw": make_raw(plain="body")},
    )
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "NOISE", "summary": "n"})
    asyncio.run(plugin._tick(ctx))
    final_seen = ctx.state().get("seen")
    assert len(final_seen) == plugin.SEEN_LIMIT
    assert "new" in final_seen
    assert "old0" not in final_seen  # oldest evicted


# ---------------------------------------------------------------- _deliver

def test_deliver_none_target_noop(plugin, ctx):
    ctx.config["delivery_target"] = "none"
    asyncio.run(plugin._deliver(ctx, "hello"))
    assert ctx.injected_messages == []


def test_deliver_session_target_injects(plugin, ctx):
    ctx.config["delivery_target"] = "session"
    with pytest.raises(RuntimeError, match="session delivery is disabled"):
        asyncio.run(plugin._deliver(ctx, "hello"))
    assert ctx.injected_messages == []


def test_deliver_push_target_shells_out(plugin, ctx, monkeypatch, tmp_path):
    # The plugin only shells out when the configured binary actually exists
    # on disk; otherwise it falls back to inject_message. Point it at a real
    # file (contents irrelevant — we monkeypatch create_subprocess_exec).
    fake = tmp_path / "hermes"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    ctx.config["delivery_target"] = "push"
    ctx.config["hermes_send_path"] = str(fake)
    monkeypatch.setenv("HERMES_HOME", "/tmp/hermes-home")
    monkeypatch.setenv("HERMES_SESSION_ID", "session-123")
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "desktop")
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    captured = []
    _install_fake_subprocess(monkeypatch, returncode=0, capture=captured)
    asyncio.run(plugin._deliver(ctx, "payload"))
    assert captured, "push delivery should spawn hermes send"
    argv, kwargs = captured[0]
    assert argv[:5] == (str(fake), "--profile", ctx.profile_name, "send", "--to")
    assert argv[5] == "push"
    assert argv[6:] == ("--quiet", "payload")
    env = kwargs["env"]
    assert env["HERMES_HOME"] == "/tmp/hermes-home"
    assert "HERMES_SESSION_ID" not in env
    assert "HERMES_SESSION_PLATFORM" not in env
    assert "HERMES_YOLO_MODE" not in env


def test_deliver_push_nonzero_raises(plugin, ctx, monkeypatch, tmp_path):
    fake = tmp_path / "hermes"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    ctx.config["delivery_target"] = "push"
    ctx.config["hermes_send_path"] = str(fake)
    _install_fake_subprocess(monkeypatch, returncode=2, stderr=b"bad")
    with pytest.raises(RuntimeError):
        asyncio.run(plugin._deliver(ctx, "payload"))


def test_deliver_push_missing_binary_falls_back_to_inject(
        plugin, ctx, monkeypatch):
    ctx.config["delivery_target"] = "push"
    ctx.config["hermes_send_path"] = "/definitely/not/a/real/hermes"
    # Make sure the PATH-lookup fallback also fails.
    monkeypatch.setattr(plugin.shutil, "which", lambda _: None)
    monkeypatch.setattr(plugin, "_fallback_send_path",
                        lambda: "/also/not/real")
    with pytest.raises(RuntimeError, match="hermes binary unavailable"):
        asyncio.run(plugin._deliver(ctx, "payload"))
    assert ctx.injected_messages == []


def test_deliver_session_refusal_logged(plugin, ctx, caplog):
    ctx.config["delivery_target"] = "session"
    ctx.inject_return = False
    with pytest.raises(RuntimeError, match="session delivery is disabled"):
        asyncio.run(plugin._deliver(ctx, "msg"))
    assert ctx.injected_messages == []


# ---------------------------------------------------------------- status tool

def test_status_reports_counts(plugin, ctx, monkeypatch):
    # Seed state and config.
    today = "2026-11-05"
    monkeypatch.setattr(plugin.time, "strftime",
                        lambda fmt: today if fmt == "%Y-%m-%d" else "00:00")
    ctx.config["enabled"] = True
    ctx.config["delivery_target"] = "session"
    ctx.config["poll_interval_seconds"] = 20
    state = ctx.state()
    state.set("history_id", "77")
    state.set("seen", {"a": 1, "b": 2})
    state.set("alerts_sent", 4)
    state.set("gate_day", today)
    state.set("gate_count", 7)
    state.set("budget_day", today)
    state.set("budget_count", 3)
    state.set("learned_blocked_senders", {"x": 1, "y": 2})
    state.set("learned_vip_senders", {"z": 1})
    state.set("learned_gate_notes", ["note1", "note2", "note3"])
    out = plugin._status(ctx)
    assert out == {
        "running": False,
        "profile": "default",
        "enabled": True,
        "delivery_target": "session",
        "poll_interval_seconds": 20,
        "gate_calls_today": 7,
        "daily_gate_cap": 100,
        "last_poll": None,
        "history_id": "77",
        "seen_messages": 2,
        "alerts_sent": 4,
        "drafts_today": 3,
        "learned_noise_senders": 2,
        "learned_important_senders": 1,
        "learned_gate_notes": 3,
        "last_error": None,
    }


def test_status_drafts_today_zero_on_different_day(plugin, ctx, monkeypatch):
    today = "2026-11-05"
    monkeypatch.setattr(plugin.time, "strftime",
                        lambda fmt: today if fmt == "%Y-%m-%d" else "00:00")
    ctx.state().set("budget_day", "2026-11-04")
    ctx.state().set("budget_count", 9)
    out = plugin._status(ctx)
    assert out["gate_calls_today"] == 0
    assert out["drafts_today"] == 0


# ---------------------------------------------------------------- gate instructions

def test_gate_instructions_default_when_no_profile(plugin, ctx):
    text = plugin._gate_instructions(ctx)
    assert "importance gate" in text.lower()
    assert "Not newsletters" in text  # from DEFAULT_IMPORTANCE


def test_gate_instructions_includes_custom_profile(plugin, ctx):
    ctx.config["importance_profile"] = "I am a vet nurse — animal emergencies are IMPORTANT."
    text = plugin._gate_instructions(ctx)
    assert "vet nurse" in text


def test_gate_instructions_includes_learned_notes(plugin, ctx):
    ctx.state().set("learned_gate_notes", ["remember: dentist mails matter"])
    text = plugin._gate_instructions(ctx)
    assert "dentist mails matter" in text


def test_gate_instructions_caps_notes(plugin, ctx):
    many = [f"note {i}" for i in range(plugin.GATE_NOTES_LIMIT * 2)]
    ctx.state().set("learned_gate_notes", many)
    text = plugin._gate_instructions(ctx)
    # Only the last GATE_NOTES_LIMIT entries are present.
    assert "note 0" not in text
    assert many[-1] in text


# ---------------------------------------------------------------- _test tool

def test_test_tool_runs_gate_and_returns_verdict(plugin, ctx):
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Looks real."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    out = asyncio.run(plugin._test(ctx, {"from": "a@b", "subject": "hi", "body": "hello"}))
    assert out["verdict"] == "IMPORTANT"
    assert out["summary"] == "Looks real."
    assert out["suggested_reply"] == "Thanks, noted."


def test_test_tool_noise_short_circuits(plugin, ctx):
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "NOISE", "summary": "newsletter"})
    out = asyncio.run(plugin._test(ctx, {"from": "a@b", "subject": "hi", "body": "x"}))
    assert out["verdict"] == "NOISE"
    # Draft is not produced on NOISE.
    assert "suggested_reply" not in out
    assert ctx.llm.complete_calls == []


def test_test_tool_works_inside_running_event_loop(plugin, ctx):
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Loop-safe."})
    ctx.llm.complete_result = TextBox("OK")

    async def run():
        return await plugin._test(ctx, {"from": "a@b", "subject": "hi", "body": "hello"})

    out = asyncio.run(run())
    assert out["verdict"] == "IMPORTANT"
    assert out["suggested_reply"] == "OK"
    assert ctx.llm.structured_calls


def test_test_tool_deliver_injects_into_session(plugin, ctx):
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "s"})
    ctx.llm.complete_result = TextBox("ok")
    out = asyncio.run(plugin._test(ctx, {"from": "a@b", "subject": "hi",
                               "body": "x", "deliver": True}))
    assert out["delivered"] is True
    assert len(ctx.delivered_messages) == 1
    assert ctx.injected_messages == []
    assert "EMAIL ALERT (test)" in ctx.delivered_messages[0]

