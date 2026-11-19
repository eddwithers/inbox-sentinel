"""Deterministic scam-signal behaviour tests.

Regression for the fake-order miss: a order-confirmation lure with a
password-protected PDF once passed the importance gate as a clean alert.
The ported check must re-label such mail as POSSIBLE SCAM — never silently
gate it away, never draft a reply to it. Signals are pure literal substring
checks (watcher parity); authentication results are not scam evidence and
never clear a hit.

Fictional mail only; no network, no real account, no real model calls.
"""
from __future__ import annotations

import asyncio

import pytest

from conftest import ParsedBox, TextBox, make_raw, meta_response

pytestmark = pytest.mark.usefixtures("capture_notifications")


SCAM_BODY = ("Thank you for your order. The order confirmation is attached as a "
             "password protected PDF. The password is your order number.")
SCAM_SENDER = "GymKit Orders <orders@gymkit.test>"
SCAM_SUBJECT = "Your GymKit order #88123"


def _scam_mail(gmail, mid="mScam"):
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  meta_response(sender=SCAM_SENDER, subject=SCAM_SUBJECT))
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  {"raw": make_raw(subject=SCAM_SUBJECT, sender=SCAM_SENDER,
                                   plain=SCAM_BODY)})


# ---------------------------------------------------------------- pure signals

def test_password_protected_pdf_hits(plugin):
    hits = plugin.scam_signal_hits(
        "Your order", "The attached PDF is password protected. Password: 1234",
        "me@example.test")
    assert hits == ["password-protected attachment"]


def test_signals_are_case_insensitive(plugin):
    hits = plugin.scam_signal_hits("ORDER", "PASSWORD PROTECTED document (PDF)", "")
    assert hits == ["password-protected attachment"]


def test_password_protected_without_pdf_is_near_miss(plugin):
    assert plugin.scam_signal_hits(
        "Report", "The archive is password protected.", "me@example.test") == []


def test_pdf_without_password_is_near_miss(plugin):
    assert plugin.scam_signal_hits(
        "Statement", "Your monthly statement PDF is attached.", "me@example.test") == []


def test_signals_are_literal_substrings(plugin):
    # Watcher parity: the pattern is "password protected" with a space. A
    # hyphenated variant does not match — pinned so any future widening is a
    # deliberate, reviewed change rather than silent drift.
    assert plugin.scam_signal_hits(
        "Report", "The password-protected PDF is attached.", "") == []


def test_undisclosed_recipients_hits(plugin):
    hits = plugin.scam_signal_hits("Hello", "Dear customer", "undisclosed-recipients:;")
    assert hits == ["undisclosed recipients"]


def test_both_signals_reported_in_order(plugin):
    hits = plugin.scam_signal_hits("Invoice", "password protected PDF",
                                   "undisclosed-recipients:;")
    assert hits == ["password-protected attachment", "undisclosed recipients"]


def test_clean_mail_has_no_hits(plugin):
    assert plugin.scam_signal_hits("Lunch", "See you at noon", "me@example.test") == []


def test_signal_split_across_fields_hits(plugin):
    # subject + body + recipient are scanned as one text (watcher parity).
    hits = plugin.scam_signal_hits("password protected", "see attached pdf", "")
    assert hits == ["password-protected attachment"]


# ---------------------------------------------------------------- pipeline

def test_scam_alerts_even_when_gate_says_noise(plugin, ctx, gmail):
    """The deterministic signal outranks the model verdict: the mail reaches
    the user as a warning, not a silent NOISE drop."""
    _scam_mail(gmail)
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "NOISE", "summary": "Order confirmation."})
    asyncio.run(plugin._process(ctx, "mScam"))
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert text.startswith("POSSIBLE SCAM")
    assert "password-protected attachment" in text
    assert "do not reply" in text
    assert "Suggested reply" not in text
    assert "msgid: gmail:mScam" in text
    assert ctx.llm.complete_calls == []  # never draft a reply to a scammer
    assert ctx.state.get("alerts_sent") == 1


def test_scam_never_drafts_even_when_gate_says_important(plugin, ctx, gmail):
    _scam_mail(gmail)
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Order confirmation."})
    ctx.llm.complete_result = TextBox("Thanks for the order!")  # must never be used
    asyncio.run(plugin._process(ctx, "mScam"))
    assert ctx.llm.complete_calls == []
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert text.startswith("POSSIBLE SCAM")
    assert "Suggested reply" not in text
    assert "Thanks for the order!" not in text


def test_scam_alerts_without_model_when_gate_fails(plugin, ctx, gmail):
    """Model down: the warning still goes out, with an untrusted body excerpt
    instead of a model summary."""
    _scam_mail(gmail)

    def boom(**kwargs):
        raise RuntimeError("model down")

    ctx.llm.structured_result = boom
    asyncio.run(plugin._process(ctx, "mScam"))
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert text.startswith("POSSIBLE SCAM")
    assert "password-protected attachment" in text
    assert "order confirmation" in text  # excerpt fallback
    assert ctx.llm.complete_calls == []


def test_scam_alerts_when_gate_budget_exhausted(plugin, ctx, gmail):
    """A scam warning is never deferred behind the daily classification cap."""
    ctx.config["daily_gate_cap"] = 0
    _scam_mail(gmail)
    asyncio.run(plugin._process(ctx, "mScam"))
    assert ctx.llm.structured_calls == []
    assert ctx.llm.complete_calls == []
    assert len(ctx.delivered_messages) == 1
    assert ctx.delivered_messages[0].startswith("POSSIBLE SCAM")


def test_undisclosed_recipients_header_hits(plugin, ctx, gmail):
    gmail.respond("GET", "/users/me/messages/mUnd",
                  meta_response(subject="Dear customer",
                                to="undisclosed-recipients:;",
                                delivered_to="me@example.test"))
    gmail.respond("GET", "/users/me/messages/mUnd",
                  {"raw": make_raw(subject="Dear customer",
                                   plain="You have won a prize.")})
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Prize lure."})
    asyncio.run(plugin._process(ctx, "mUnd"))
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert text.startswith("POSSIBLE SCAM")
    assert "undisclosed recipients" in text


def test_near_miss_takes_normal_path(plugin, ctx, gmail):
    """A statement PDF without a password mention is not scam-shaped: the
    gate decides as usual (accepted false-positive boundary)."""
    gmail.respond("GET", "/users/me/messages/mNear",
                  meta_response(subject="Your statement"))
    gmail.respond("GET", "/users/me/messages/mNear",
                  {"raw": make_raw(subject="Your statement",
                                   plain="Your monthly statement PDF is attached.")})
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Monthly statement."})
    asyncio.run(plugin._process(ctx, "mNear"))
    assert len(ctx.delivered_messages) == 1
    assert ctx.delivered_messages[0].startswith("EMAIL ALERT")
    assert "POSSIBLE SCAM" not in ctx.delivered_messages[0]


def test_clean_mail_still_drafts(plugin, ctx, gmail):
    gmail.respond("GET", "/users/me/messages/mClean",
                  meta_response(subject="Meeting"))
    gmail.respond("GET", "/users/me/messages/mClean",
                  {"raw": make_raw(subject="Meeting", plain="Would Tuesday work?")})
    ctx.llm.structured_result = ParsedBox(
        {"verdict": "IMPORTANT", "summary": "Meeting proposal."})
    ctx.llm.complete_result = TextBox("Yes, Tuesday works.")
    asyncio.run(plugin._process(ctx, "mClean"))
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert text.startswith("EMAIL ALERT")
    assert "Suggested reply" in text
    assert "Yes, Tuesday works." in text


def test_learned_noise_sender_still_filtered_first(plugin, ctx, gmail):
    """Local filters keep their watcher-parity order: an explicit always-noise
    rule drops the mail before the scam check runs."""
    ctx.state.set("learned_blocked_senders", {"orders@gymkit.test": 1})
    _scam_mail(gmail)
    asyncio.run(plugin._process(ctx, "mScam"))
    assert ctx.delivered_messages == []
    assert ctx.llm.structured_calls == []


def test_scam_check_runs_for_imap_style_body(plugin, ctx):
    """The check lives in the shared pipeline: a plain-string body (IMAP
    shape) is scanned exactly like the Gmail dict shape."""
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Lure."})
    asyncio.run(plugin._run_pipeline(
        ctx, mid_prefix="imap", mid="42", sender="Lure <lure@scam.test>",
        subject="Invoice", recipient="me@example.test", reply_to="lure@scam.test",
        label_ids=[], fetch_body=lambda: "Please open the password protected PDF."))
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert text.startswith("POSSIBLE SCAM")
    assert "msgid: imap:42" in text
    assert ctx.llm.complete_calls == []


# ---------------------------------------------------------------- sample tool

def test_test_tool_scam_sample_never_drafts(plugin, ctx):
    plugin.register(ctx)
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Fake order."})
    ctx.llm.complete_result = TextBox("Should never be used")
    result = asyncio.run(plugin._test(ctx, {
        "from": SCAM_SENDER, "subject": SCAM_SUBJECT, "body": SCAM_BODY,
    }))
    assert result["verdict"] == "IMPORTANT"
    assert result["scam_signals"] == ["password-protected attachment"]
    assert result["suggested_reply"] is None
    assert ctx.llm.complete_calls == []


def test_test_tool_scam_sample_survives_budget_exhaustion(plugin, ctx):
    plugin.register(ctx)
    ctx.config["daily_gate_cap"] = 0
    result = asyncio.run(plugin._test(ctx, {
        "from": SCAM_SENDER, "subject": SCAM_SUBJECT, "body": SCAM_BODY,
    }))
    assert result["verdict"] == "IMPORTANT"
    assert result["scam_signals"] == ["password-protected attachment"]
    assert ctx.llm.structured_calls == []


def test_test_tool_internal_deliver_path_uses_scam_shaping(plugin, ctx):
    """Internal-path coverage: the registered tool wrapper blocks delivery
    (inspection-only); if the internal deliver branch ever runs, a scam
    sample must use the warning shape, not the clean test-alert shape."""
    plugin.register(ctx)
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Fake order."})
    result = asyncio.run(plugin._test(ctx, {
        "from": SCAM_SENDER, "subject": SCAM_SUBJECT, "body": SCAM_BODY,
        "deliver": True,
    }))
    assert result["delivered"] is True
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert text.startswith("POSSIBLE SCAM")
    assert "msgid:" not in text  # a sample carries no real message id
