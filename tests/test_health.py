"""Health notices: the watcher must say when it cannot watch the inbox.

Fictional failures only. Delivery is captured, sleeping is skipped.
"""
from __future__ import annotations

import asyncio

import pytest


def _run_loop(plugin, ctx, monkeypatch, outcomes):
    """Drive _watch_loop through scripted tick outcomes; return the sleep total per tick."""
    script = list(outcomes)
    waits = []

    async def fake_tick(_ctx):
        outcome = script.pop(0)
        if not script:
            ctx.config["enabled"] = False
        if isinstance(outcome, BaseException):
            raise outcome

    slept = {"total": 0}

    async def fake_sleep(seconds):
        slept["total"] += seconds

    real_sleep = asyncio.sleep

    async def run():
        monkeypatch.setattr(plugin, "_tick", fake_tick)
        monkeypatch.setattr(plugin.asyncio, "sleep", fake_sleep)
        try:
            original = plugin._watch_loop
            await original(ctx)
        finally:
            monkeypatch.setattr(plugin.asyncio, "sleep", real_sleep)

    ctx.config["enabled"] = True
    asyncio.run(run())
    return slept["total"]


@pytest.fixture()
def health(plugin, ctx, capture_notifications):
    return plugin, ctx


def test_not_signed_in_sends_one_notice_and_slows_polling(health, monkeypatch):
    plugin, ctx = health
    total = _run_loop(plugin, ctx, monkeypatch,
                      [plugin.ProviderNotSignedIn("fixture")] * 2 + [None])
    assert len(ctx.delivered_messages) == 1
    notice = ctx.delivered_messages[0]
    assert notice.startswith("INBOX SENTINEL — not watching your inbox")
    assert "not signed in" in notice
    assert "hermes auth add inbox-sentinel:gmail" in notice
    assert ctx.state.get("health_notice_day")
    # Two not-signed-in polls wait the access retry interval, not 15 seconds.
    assert total >= 2 * plugin.ACCESS_RETRY_SECONDS


def test_expired_grant_explains_testing_mode_expiry(health, monkeypatch):
    plugin, ctx = health
    _run_loop(plugin, ctx, monkeypatch, [plugin.AuthError("fixture"), None])
    assert len(ctx.delivered_messages) == 1
    assert "seven days" in ctx.delivered_messages[0]
    assert ctx.state.get("last_error") is None  # recovered on the next tick


def test_health_notice_is_daily_not_per_poll(health, monkeypatch):
    plugin, ctx = health
    _run_loop(plugin, ctx, monkeypatch, [plugin.AuthError("fixture")] * 5)
    _run_loop(plugin, ctx, monkeypatch, [plugin.ProviderNotSignedIn("fixture")] * 3)
    assert len(ctx.delivered_messages) == 1


def test_repeated_generic_failures_notice_after_threshold(health, monkeypatch):
    plugin, ctx = health
    below = [RuntimeError("private-fixture detail")] * (plugin.FAILURE_NOTICE_AFTER - 1)
    _run_loop(plugin, ctx, monkeypatch, below)
    assert ctx.delivered_messages == []
    _run_loop(plugin, ctx, monkeypatch,
              [RuntimeError("private-fixture detail")] * plugin.FAILURE_NOTICE_AFTER)
    assert len(ctx.delivered_messages) == 1
    notice = ctx.delivered_messages[0]
    assert "RuntimeError" in notice
    assert "private-fixture" not in notice  # exception text never reaches the alert
    assert "inbox_sentinel_status" in notice


def test_a_success_resets_the_failure_count(health, monkeypatch):
    plugin, ctx = health
    n = plugin.FAILURE_NOTICE_AFTER
    _run_loop(plugin, ctx, monkeypatch,
              [RuntimeError("x")] * (n - 1) + [None] + [RuntimeError("x")] * (n - 1))
    assert ctx.delivered_messages == []


def test_failed_notice_delivery_does_not_stop_the_loop(plugin, ctx, monkeypatch):
    attempts = []

    async def failing_delivery(_ctx, text):
        attempts.append(text)
        raise RuntimeError("delivery unavailable")

    monkeypatch.setattr(plugin, "_deliver", failing_delivery)
    _run_loop(plugin, ctx, monkeypatch, [plugin.ProviderNotSignedIn("fixture")] * 2 + [None])
    # Not marked as sent, so it is retried on the next failed poll; the loop finishes.
    assert len(attempts) == 2
    assert ctx.state.get("health_notice_day") is None
