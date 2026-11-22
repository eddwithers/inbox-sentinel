"""M1b post_gate-module behaviour tests: IS-Drafter + IS-AlertShaper.

Pins the budgeted-model seam (modules request model calls through host draft
budgets, never ctx.llm), byte-identical alert shaping with host fallbacks,
async stage support, and the degradation contracts. Fictional mail only; no
network, no real model calls, no sleeps (clocks injected).
"""
from __future__ import annotations

import asyncio

import pytest

from conftest import ParsedBox, TextBox, make_raw, meta_response

pytestmark = pytest.mark.usefixtures("capture_notifications")

EXPECTED_ALERT = (
    "EMAIL ALERT\n\n"
    "Subject: Hello\n"
    "From: Alice \u2039alice@\u200bexample.test\u203a\n"
    "Time: 00:00\n\n"
    "A note.\n\n"
    "Suggested reply (to Alice \u2039alice@\u200bexample.test\u203a):\n"
    "```\n"
    "Thanks, noted.\n"
    "```\n\n"
    "msgid: gmail:mImp"
)


def _freeze_time(plugin, monkeypatch, day="2026-11-21"):
    monkeypatch.setattr(plugin.time, "strftime",
                        lambda fmt: day if fmt == "%Y-%m-%d" else "00:00")


def _view(**kw):
    base = {"sender": "Alice <alice@example.test>", "subject": "Hello",
            "recipient": "me@example.test",
            "reply_to": "Alice <alice@example.test>",
            "label_ids": ["INBOX"], "flags": {}, "mid": "mImp",
            "mid_prefix": "gmail", "body": "A short note.",
            "attachments": [], "links": [], "verdict": "IMPORTANT",
            "summary": "A note.", "draft_blocker": None,
            "body_truncated": False}
    base.update(kw)
    return base


def _important_mail(gmail, mid="mImp", plain="A short note."):
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  meta_response(sender="Alice <alice@example.test>",
                                subject="Hello"))
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  {"raw": make_raw(subject="Hello",
                                   sender="Alice <alice@example.test>",
                                   plain=plain)})


def _run_post_gate(plugin, ctx, view):
    return asyncio.run(plugin._run_stage(ctx, "post_gate", view))


def _outcome(outcomes, key):
    return next((o for o in outcomes if key in o), None)


# ---------------------------------------------------------------- discovery

def test_postgate_modules_discovered(plugin):
    mods = plugin._modules()
    assert {"drafter", "alertshaper"} <= set(mods)
    assert mods["drafter"].NAME == "drafter"
    assert mods["drafter"].BRAND == "IS-Drafter"
    assert mods["alertshaper"].BRAND == "IS-AlertShaper"
    assert mods["drafter"].STAGES == ("post_gate",)
    assert mods["alertshaper"].STAGES == ("post_gate",)
    assert mods["drafter"].DEFAULT_ENABLED is True
    assert mods["alertshaper"].DEFAULT_ENABLED is True
    assert mods["drafter"].PRIORITY < mods["alertshaper"].PRIORITY


def test_draft_system_constant_matches_host_fallback(plugin):
    # The module owns DRAFT_SYSTEM; the host keeps a degradation copy. They
    # must never drift.
    assert plugin._modules()["drafter"].DRAFT_SYSTEM == plugin.DRAFT_SYSTEM


# ---------------------------------------------------------------- bounded seam

def test_api_surface_is_bounded(plugin, ctx):
    api = plugin._ModuleAPI(ctx, "drafter", plugin._modules()["drafter"])
    public = {a for a in dir(api) if not a.startswith("_")}
    assert public == {"state_get", "state_set", "shared_get", "config_get",
                      "sender_matches", "llm_complete", "safe_text",
                      "draft_blocker"}
    assert not hasattr(api, "ctx") and not hasattr(api, "llm")


def test_safe_text_and_draft_blocker_helpers(plugin, ctx):
    api = plugin._ModuleAPI(ctx, "drafter", plugin._modules()["drafter"])
    assert api.safe_text("<b>@x</b>") == plugin._safe_text("<b>@x</b>")
    assert api.draft_blocker("s", "b", attachments=[{"filename": "f.pdf"}]) == \
        "Attachment present, contents not reviewed."
    assert api.draft_blocker("s", "plain body") is None


def test_draft_via_seam_uses_host_task_and_module_purpose(plugin, ctx, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    view = _view()
    del view["draft_blocker"]  # module recomputes via api.draft_blocker
    outcomes = _run_post_gate(plugin, ctx, view)
    out = _outcome(outcomes, "draft")
    assert out["draft"] == "Thanks, noted."
    assert out["withheld_reason"] is None
    call = ctx.llm.complete_calls[0]
    assert call["task"] == plugin.DRAFT_TASK
    assert call["purpose"] == "inbox-sentinel.drafter"
    assert ctx.state.get("budget_count") == 1
    assert ctx.state.get("budget_day") == "2026-11-21"


def test_drafter_withheld_on_attachment(plugin, ctx):
    view = _view(attachments=[{"filename": "menu.pdf",
                               "content_type": "application/pdf"}])
    del view["draft_blocker"]
    out = _outcome(_run_post_gate(plugin, ctx, view), "draft")
    assert out["draft"] is None
    assert out["withheld_reason"] == "Attachment present, contents not reviewed."
    assert ctx.llm.complete_calls == []


def test_drafter_withheld_on_attachment_reference(plugin, ctx):
    view = _view(body="Please see the attached schedule.")
    del view["draft_blocker"]
    out = _outcome(_run_post_gate(plugin, ctx, view), "draft")
    assert out["draft"] is None
    assert out["withheld_reason"] == (
        "Attachment referenced, contents not reviewed; "
        "presence is not established by the body.")
    assert ctx.llm.complete_calls == []


def test_drafter_withheld_on_truncated_body(plugin, ctx):
    view = _view(body_truncated=True)
    del view["draft_blocker"]
    out = _outcome(_run_post_gate(plugin, ctx, view), "draft")
    assert out["draft"] is None
    assert out["withheld_reason"] == "Email body incomplete; remaining content not reviewed."


def test_drafter_withheld_on_empty_body(plugin, ctx):
    view = _view(body="   ")
    del view["draft_blocker"]
    out = _outcome(_run_post_gate(plugin, ctx, view), "draft")
    assert out["draft"] is None
    assert out["withheld_reason"] == "Email body unavailable; content not reviewed."


def test_drafter_respects_draft_replies_false(plugin, ctx):
    ctx.config["draft_replies"] = False
    out = _outcome(_run_post_gate(plugin, ctx, _view()), "draft")
    assert out["draft"] is None
    assert out["withheld_reason"] is None
    assert ctx.llm.complete_calls == []


def test_drafter_over_cap_returns_none(plugin, ctx, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    ctx.config["daily_draft_cap"] = 0
    out = _outcome(_run_post_gate(plugin, ctx, _view()), "draft")
    assert out["draft"] is None
    assert ctx.llm.complete_calls == []


def test_seam_failed_call_counts_against_cap(plugin, ctx, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    ctx.config["daily_draft_cap"] = 1
    attempts = []

    async def raise_boom(**kw):
        attempts.append(1)
        raise RuntimeError("provider down")

    ctx.llm.acomplete = raise_boom
    api = plugin._ModuleAPI(ctx, "drafter", plugin._modules()["drafter"])
    r1 = asyncio.run(api.llm_complete([{"role": "user", "content": "x"}], 700,
                                      "inbox-sentinel.drafter"))
    r2 = asyncio.run(api.llm_complete([{"role": "user", "content": "x"}], 700,
                                      "inbox-sentinel.drafter"))
    assert r1 is None and r2 is None
    assert attempts == [1]  # second request refused over cap, never sent
    assert ctx.state.get("budget_count") == 1


def test_seam_day_rollover(plugin, ctx, monkeypatch):
    day = "2026-01-01"
    monkeypatch.setattr(plugin.time, "strftime",
                        lambda fmt: day if fmt == "%Y-%m-%d" else "00:00")
    ctx.config["daily_draft_cap"] = 1
    ctx.llm.complete_result = TextBox("reply")
    api = plugin._ModuleAPI(ctx, "drafter", plugin._modules()["drafter"])
    r1 = asyncio.run(api.llm_complete([], 700, "p"))
    r2 = asyncio.run(api.llm_complete([], 700, "p"))
    assert r1 == "reply" and r2 is None
    day = "2026-01-02"
    r3 = asyncio.run(api.llm_complete([], 700, "p"))
    assert r3 == "reply"
    assert ctx.state.get("budget_day") == "2026-01-02"
    assert ctx.state.get("budget_count") == 1


def test_seam_clamps_max_tokens(plugin, ctx):
    ctx.llm.complete_result = TextBox("ok")
    api = plugin._ModuleAPI(ctx, "drafter", plugin._modules()["drafter"])
    asyncio.run(api.llm_complete([], 99999, "p"))
    assert ctx.llm.complete_calls[0]["max_tokens"] == 1000
    asyncio.run(api.llm_complete([], "garbage", "p"))
    assert ctx.llm.complete_calls[1]["max_tokens"] == 700
    asyncio.run(api.llm_complete([], 0, "p"))
    assert ctx.llm.complete_calls[2]["max_tokens"] == 1


def test_seam_budget_shared_across_modules(plugin, ctx, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    ctx.config["daily_draft_cap"] = 1
    ctx.llm.complete_result = TextBox("first")
    api_a = plugin._ModuleAPI(ctx, "drafter", plugin._modules()["drafter"])
    api_b = plugin._ModuleAPI(ctx, "othermodule")
    r1 = asyncio.run(api_a.llm_complete([], 700, "p"))
    r2 = asyncio.run(api_b.llm_complete([], 700, "p"))
    assert r1 == "first"
    assert r2 is None  # one host budget, not one per module
    assert len(ctx.llm.complete_calls) == 1


def test_no_reply_needed_passes_through_to_host(plugin, ctx):
    ctx.llm.complete_result = TextBox("NO REPLY NEEDED")
    out = _outcome(_run_post_gate(plugin, ctx, _view()), "draft")
    assert out["draft"] == "NO REPLY NEEDED"  # host interprets, not the module


# ---------------------------------------------------------------- alert shaping

@pytest.mark.parametrize("case", ["draft", "no_reply_needed", "blocker", "no_draft"])
def test_alertshaper_byte_identical_to_host_fallback(plugin, ctx, monkeypatch, case):
    _freeze_time(plugin, monkeypatch)
    view = _view()
    draft = None
    blocker = None
    if case == "draft":
        ctx.llm.complete_result = TextBox("Thanks, noted.")
        draft = "Thanks, noted."
    elif case == "no_reply_needed":
        ctx.llm.complete_result = TextBox("NO REPLY NEEDED")
        draft = "NO REPLY NEEDED"
    elif case == "blocker":
        blocker = "Attachment present, contents not reviewed."
        view["draft_blocker"] = blocker
        view["attachments"] = [{"filename": "f.pdf"}]
    elif case == "no_draft":
        ctx.config["draft_replies"] = False
    outcomes = _run_post_gate(plugin, ctx, view)
    shaper = _outcome(outcomes, "alert_text")
    assert shaper is not None
    expected = plugin._email_alert_text(
        subject=view["subject"], sender=view["sender"], summary=view["summary"],
        reply_to=view["reply_to"], draft=draft, draft_blocker=blocker,
        mid_prefix="gmail", mid="mImp")
    assert shaper["alert_text"] == expected


def test_full_important_mail_alert_exact_string(plugin, ctx, gmail, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    _important_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    asyncio.run(plugin._process(ctx, "mImp"))
    assert ctx.delivered_messages == [EXPECTED_ALERT]


def test_alertshaper_toggle_off_host_fallback(plugin, ctx, gmail, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    ctx.config["module_alertshaper_enabled"] = False
    _important_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    asyncio.run(plugin._process(ctx, "mImp"))
    assert ctx.delivered_messages == [EXPECTED_ALERT]


def test_alertshaper_failure_host_fallback(plugin, ctx, gmail, monkeypatch):
    _freeze_time(plugin, monkeypatch)

    def boom(message, api):
        raise RuntimeError("shaper bug")

    monkeypatch.setattr(plugin._modules()["alertshaper"], "post_gate", boom)
    _important_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    asyncio.run(plugin._process(ctx, "mImp"))  # must not raise
    assert ctx.delivered_messages == [EXPECTED_ALERT]


def test_untrusted_fields_sanitised(plugin, ctx, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    hostile = "<script>alert(1)</script> `x` @evil://link [b] *i* _u_ ! # |"
    view = _view(subject=hostile, summary=hostile)
    ctx.llm.complete_result = TextBox("reply with <b>markup</b> @x://y")
    outcomes = _run_post_gate(plugin, ctx, view)
    text = _outcome(outcomes, "alert_text")["alert_text"]
    assert "<script>" not in text
    assert "`x`" not in text
    assert "@evil" not in text          # zero-width broken
    assert "://link" not in text
    assert "[b]" not in text
    expected = plugin._email_alert_text(
        subject=hostile, sender=view["sender"], summary=hostile,
        reply_to=view["reply_to"], draft="reply with <b>markup</b> @x://y",
        draft_blocker=None, mid_prefix="gmail", mid="mImp")
    assert text == expected


# ---------------------------------------------------------------- degradation

def test_drafter_toggle_off_host_fallback_draft(plugin, ctx, gmail, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    ctx.config["module_drafter_enabled"] = False
    _important_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    asyncio.run(plugin._process(ctx, "mImp"))
    assert ctx.delivered_messages == [EXPECTED_ALERT]
    # Host fallback path: the host's own purpose, not the module's.
    assert ctx.llm.complete_calls[0]["purpose"] == plugin.DRAFT_PURPOSE


def test_drafter_failure_degrades_to_host_draft(plugin, ctx, gmail, monkeypatch):
    _freeze_time(plugin, monkeypatch)

    def boom(message, api):
        raise RuntimeError("drafter bug")

    monkeypatch.setattr(plugin._modules()["drafter"], "post_gate", boom)
    _important_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    asyncio.run(plugin._process(ctx, "mImp"))  # must not raise
    assert ctx.delivered_messages == [EXPECTED_ALERT]
    assert ctx.llm.complete_calls[0]["purpose"] == plugin.DRAFT_PURPOSE


def test_host_blocker_authoritative_over_truncated_view(plugin, ctx, gmail, monkeypatch):
    """The attachment keyword sits beyond the 4000-char view truncation.
    The host computed the blocker from the full body; the module must honour
    it, not re-derive from the truncated view and miss the keyword."""
    _freeze_time(plugin, monkeypatch)
    body_raw = "x" * 4100 + " attached"
    _important_mail(gmail, plain=body_raw)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("should never be used")
    asyncio.run(plugin._process(ctx, "mImp"))
    assert ctx.llm.complete_calls == []
    alert = ctx.delivered_messages[0]
    assert ("No reply drafted — Attachment referenced, contents not reviewed; "
            "presence is not established by the body. "
            "Please review the original email.") in alert


def test_over_cap_pipeline_summary_only_alert(plugin, ctx, gmail, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    ctx.config["daily_draft_cap"] = 0
    _important_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    asyncio.run(plugin._process(ctx, "mImp"))
    assert ctx.llm.complete_calls == []
    alert = ctx.delivered_messages[0]
    assert "No reply drafted — draft generation unavailable or disabled; review the email." in alert
    assert "msgid: gmail:mImp" in alert


# ---------------------------------------------------------------- async stages

def test_async_and_sync_handlers_coexist(plugin, ctx, monkeypatch):
    async def async_drafter(message, api):
        return {"draft": "async draft", "withheld_reason": None,
                "flags": {"draft": "async draft", "draft_withheld_reason": None}}

    monkeypatch.setattr(plugin._modules()["drafter"], "post_gate", async_drafter)
    outcomes = _run_post_gate(plugin, ctx, _view())
    assert outcomes[0]["draft"] == "async draft"       # priority order kept
    assert "async draft" in outcomes[1]["alert_text"]  # sync shaper saw the flags


def test_async_handler_failure_degrades(plugin, ctx, gmail, monkeypatch):
    _freeze_time(plugin, monkeypatch)

    async def async_boom(message, api):
        raise RuntimeError("async module bug")

    monkeypatch.setattr(plugin._modules()["drafter"], "post_gate", async_boom)
    _important_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "A note."})
    ctx.llm.complete_result = TextBox("Thanks, noted.")
    asyncio.run(plugin._process(ctx, "mImp"))  # must not raise
    assert ctx.delivered_messages == [EXPECTED_ALERT]
    assert ctx.llm.complete_calls[0]["purpose"] == plugin.DRAFT_PURPOSE


def test_scam_path_never_runs_postgate(plugin, ctx, gmail, monkeypatch):
    _freeze_time(plugin, monkeypatch)
    calls = []
    monkeypatch.setattr(plugin._modules()["drafter"], "post_gate",
                        lambda m, a: calls.append(1))
    gmail.respond("GET", "/users/me/messages/mScam",
                  meta_response(sender="Lure <lure@scam.test>", subject="Order"))
    gmail.respond("GET", "/users/me/messages/mScam",
                  {"raw": make_raw(subject="Order", sender="Lure <lure@scam.test>",
                                   plain="Open the password protected PDF.")})
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Order."})
    asyncio.run(plugin._process(ctx, "mScam"))
    assert ctx.delivered_messages[0].startswith("POSSIBLE SCAM")
    assert calls == []                 # security shaping is host-owned
    assert ctx.llm.complete_calls == []  # never draft to a suspected scammer
