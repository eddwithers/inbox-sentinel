"""Guard-module behaviour tests: IS-AttachmentGuard, IS-LinkGuard, IS-StormShield.

Elite-grade coverage: signal hits and near-misses, false-positive boundaries,
bounded hostile input, storm safety invariants (first occurrence always
alerts, different bodies never suppress, security warnings outrank drops),
multi-module merged warnings, toggles and degradation. Fictional mail only;
no network, no real model calls, no sleeps (clock is injected).
"""
from __future__ import annotations

import asyncio
import base64
import time

import pytest

from conftest import ParsedBox, TextBox, make_raw, meta_response

pytestmark = pytest.mark.usefixtures("capture_notifications")


def _raw_with_attachment(filename="invoice.pdf.exe",
                         content_type="application/x-msdownload",
                         plain="Please see attached."):
    boundary = "MIX"
    body = (
        f'From: Lure <lure@scam.test>\r\nTo: me@example.test\r\nSubject: Invoice\r\n'
        f'MIME-Version: 1.0\r\n'
        f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
        f'--{boundary}\r\nContent-Type: text/plain; charset="utf-8"\r\n\r\n{plain}\r\n'
        f'--{boundary}\r\nContent-Type: {content_type}; name="{filename}"\r\n'
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        f'Content-Transfer-Encoding: base64\r\n\r\nTQ==\r\n'
        f'--{boundary}--\r\n'
    )
    return base64.urlsafe_b64encode(body.encode("utf-8")).decode("ascii")


def _att(filename="", content_type="application/octet-stream"):
    return {"filename": filename, "content_type": content_type}


# ---------------------------------------------------------------- AttachmentGuard

def test_attachment_executable_hits(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals([_att("setup.exe")]) == ["executable attachment"]


def test_attachment_double_extension_hits(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals([_att("invoice.pdf.exe")]) == ["double-extension attachment"]


def test_attachment_macro_hits(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals([_att("report.docm")]) == ["macro-enabled document"]


def test_attachment_html_hits(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals([_att("login.html")]) == ["HTML attachment"]


def test_attachment_password_archive_hits(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals([_att("photos.zip")], "The archive password is 1234") == [
        "password-protected archive"]


def test_attachment_clean_pdf_near_miss(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals([_att("statement.pdf", "application/pdf")]) == []


def test_attachment_octet_stream_near_miss(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals([_att("data.bin")]) == []


def test_attachment_executable_content_type_without_filename(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals([_att("", "application/x-msdownload")]) == ["executable attachment"]


def test_attachment_case_insensitive_and_deduped(plugin):
    m = plugin._modules()["attachmentguard"]
    hits = m.attachment_signals([_att("INVOICE.PDF.EXE"), _att("tool.exe")])
    assert hits == ["double-extension attachment", "executable attachment"]


def test_attachment_malformed_entries_ignored(plugin):
    m = plugin._modules()["attachmentguard"]
    assert m.attachment_signals(["not-a-dict", None, _att("ok.pdf")]) == []


# ---------------------------------------------------------------- LinkGuard

def test_link_ip_literal_hits(plugin):
    m = plugin._modules()["linkguard"]
    assert "IP-address link" in m.link_signals(["http://192.168.1.1/login"])


def test_link_hex_ip_hits(plugin):
    m = plugin._modules()["linkguard"]
    assert "IP-address link" in m.link_signals(["http://0x7f000001/"])


def test_link_credentials_trick_hits(plugin):
    m = plugin._modules()["linkguard"]
    assert "credentials-in-URL" in m.link_signals(["http://***@evil.test/"])


def test_link_punycode_hits(plugin):
    m = plugin._modules()["linkguard"]
    assert "punycode/IDN link" in m.link_signals(["https://xn--80ak6aa92e.com/"])


def test_link_shortener_hits(plugin):
    m = plugin._modules()["linkguard"]
    assert m.link_signals(["https://bit.ly/3xYz"]) == ["shortened link"]


def test_link_high_risk_tld_hits(plugin):
    m = plugin._modules()["linkguard"]
    assert "high-risk TLD" in m.link_signals(["https://invoice.zip/"])


def test_link_deep_subdomain_hits(plugin):
    m = plugin._modules()["linkguard"]
    assert "deep-subdomain link" in m.link_signals(["https://a.b.c.d.evil.test/"])


def test_link_insecure_login_hits(plugin):
    m = plugin._modules()["linkguard"]
    assert "insecure login link" in m.link_signals(["http://accounts.test/verify"])


def test_link_clean_https_near_miss(plugin):
    m = plugin._modules()["linkguard"]
    assert m.link_signals(["https://www.bbc.co.uk/news", "https://login.microsoft.com/"]) == []


def test_link_malformed_url_no_crash(plugin):
    m = plugin._modules()["linkguard"]
    assert m.link_signals(["http://[bad-ipv6", "https://", "not a url"]) == []


def test_link_urls_extracted_from_body_text(plugin):
    m = plugin._modules()["linkguard"]
    assert "shortened link" in m.link_signals([], "Go to https://tinyurl.com/abc now")


def test_link_https_login_not_flagged_insecure(plugin):
    m = plugin._modules()["linkguard"]
    assert m.link_signals(["https://bank.test/login"]) == []


def test_link_bounded_on_hostile_input(plugin):
    m = plugin._modules()["linkguard"]
    hostile = ("http://bit.ly/" + "a" * 100 + " ") * 3000  # ~350 KB
    start = time.perf_counter()
    hits = m.link_signals([], hostile)
    assert time.perf_counter() - start < 2.0
    assert hits == ["shortened link"]  # deduped, capped, linear


# ---------------------------------------------------------------- host link extraction

def test_html_hrefs_collected(plugin):
    raw = make_raw(html='<p>Hi</p><a href="https://bit.ly/abc">click</a>')
    parsed = plugin._parse_message_bytes(base64.urlsafe_b64decode(raw + "=="))
    content = plugin._extract_message_content(parsed)
    assert content["links"] == ["https://bit.ly/abc"]


def test_plain_preferred_still_collects_html_links(plugin):
    raw = make_raw(plain="Plain body", html='<a href="http://192.168.1.1/x">x</a>')
    parsed = plugin._parse_message_bytes(base64.urlsafe_b64decode(raw + "=="))
    content = plugin._extract_message_content(parsed)
    assert content["body"] == "Plain body"
    assert content["links"] == ["http://192.168.1.1/x"]


def test_link_extraction_capped(plugin):
    html = "".join(f'<a href="https://x.test/{i}">l</a>' for i in range(80))
    assert len(plugin._extract_links(html)) == 50


# ---------------------------------------------------------------- StormShield

def test_storm_first_occurrences_pass_then_suppress(plugin, ctx, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    m = plugin._modules()["stormshield"]
    api = plugin._ModuleAPI(ctx, "stormshield", m)
    msg = {"sender": "Blast <blast@shop.test>", "subject": "Sale", "body": "Same body"}
    assert m.pre_gate(msg, api) is None          # 1st
    assert m.pre_gate(msg, api) is None          # 2nd (threshold 3)
    out = m.pre_gate(msg, api)                   # 3rd identical
    assert out and out["drop"] is True
    assert "storm suppressed" in out["reason"]


def test_storm_retries_of_same_mid_do_not_count(plugin, ctx, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    m = plugin._modules()["stormshield"]
    api = plugin._ModuleAPI(ctx, "stormshield", m)
    msg = {"sender": "Blast <blast@shop.test>", "subject": "Sale",
           "body": "Same body", "mid": "m1"}
    for _ in range(5):  # transport retries of a single arrival
        assert m.pre_gate(msg, api) is None


def test_storm_different_body_never_suppresses(plugin, ctx, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    m = plugin._modules()["stormshield"]
    api = plugin._ModuleAPI(ctx, "stormshield", m)
    for i in range(6):
        msg = {"sender": "Blast <blast@shop.test>", "subject": "Alert",
               "body": f"Incident {i} details"}
        assert m.pre_gate(msg, api) is None


def test_storm_window_expiry_resets(plugin, ctx, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    m = plugin._modules()["stormshield"]
    api = plugin._ModuleAPI(ctx, "stormshield", m)
    msg = {"sender": "Blast <blast@shop.test>", "subject": "Sale", "body": "Same"}
    m.pre_gate(msg, api)
    m.pre_gate(msg, api)
    clock[0] += 31 * 60  # past the 30-minute window
    assert m.pre_gate(msg, api) is None  # fresh window, count reset


def test_storm_state_bounded(plugin, ctx, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    m = plugin._modules()["stormshield"]
    api = plugin._ModuleAPI(ctx, "stormshield", m)
    for i in range(250):
        m.pre_gate({"sender": f"s{i}@shop.test", "subject": "x", "body": "y"}, api)
    assert len(api.state_get("storms")) <= 200


def test_storm_garbage_config_degrades_to_defaults(plugin, ctx, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    ctx.config["storm_threshold"] = "banana"
    ctx.config["storm_window_minutes"] = None
    m = plugin._modules()["stormshield"]
    api = plugin._ModuleAPI(ctx, "stormshield", m)
    msg = {"sender": "Blast <blast@shop.test>", "subject": "Sale", "body": "Same"}
    assert m.pre_gate(msg, api) is None
    assert m.pre_gate(msg, api) is None
    assert m.pre_gate(msg, api)["drop"] is True  # default threshold 3 still applies


def test_storm_disabled(plugin, ctx, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    ctx.config["module_stormshield_enabled"] = False
    m = plugin._modules()["stormshield"]
    msg = {"sender": "Blast <blast@shop.test>", "subject": "Sale", "body": "Same"}
    view = dict(msg, flags={})
    for _ in range(10):
        assert not any(o.get("drop") for o in plugin._run_stage(ctx, "pre_gate", view))


# ---------------------------------------------------------------- pipeline integration

def test_attachment_lure_warns_via_pipeline(plugin, ctx, gmail):
    gmail.respond("GET", "/users/me/messages/mAtt", meta_response(
        sender="Lure <lure@scam.test>", subject="Invoice"))
    gmail.respond("GET", "/users/me/messages/mAtt",
                  {"raw": _raw_with_attachment()})
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Invoice."})
    asyncio.run(plugin._process(ctx, "mAtt"))
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert text.startswith("POSSIBLE SCAM")
    assert "IS-AttachmentGuard signals detected: double-extension attachment." in text
    assert ctx.llm.complete_calls == []


def test_link_lure_warns_via_pipeline(plugin, ctx, gmail):
    gmail.respond("GET", "/users/me/messages/mLink", meta_response(
        sender="Lure <lure@scam.test>", subject="Verify"))
    gmail.respond("GET", "/users/me/messages/mLink",
                  {"raw": make_raw(subject="Verify", sender="Lure <lure@scam.test>",
                                   html='<a href="http://192.168.1.1/verify">Verify now</a>')})
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Verify."})
    asyncio.run(plugin._process(ctx, "mLink"))
    text = ctx.delivered_messages[0]
    assert "IS-LinkGuard signals detected:" in text
    assert "IP-address link" in text


def test_multi_module_signals_merge_into_one_warning(plugin, ctx, gmail):
    gmail.respond("GET", "/users/me/messages/mBoth", meta_response(
        sender="Lure <lure@scam.test>", subject="Invoice"))
    gmail.respond("GET", "/users/me/messages/mBoth",
                  {"raw": _raw_with_attachment(plain="The PDF is password protected.")})
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Invoice."})
    asyncio.run(plugin._process(ctx, "mBoth"))
    assert len(ctx.delivered_messages) == 1
    text = ctx.delivered_messages[0]
    assert "IS-ScamShield signals detected: password-protected attachment." in text
    assert "IS-AttachmentGuard signals detected: double-extension attachment." in text
    assert ctx.llm.complete_calls == []


def _blast_mail(gmail, mid):
    gmail.respond("GET", f"/users/me/messages/{mid}", meta_response(
        sender="Blast <blast@shop.test>", subject="Sale"))
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  {"raw": make_raw(subject="Sale", sender="Blast <blast@shop.test>",
                                   plain="Same body every time.")})


def test_storm_suppresses_third_identical_alert(plugin, ctx, gmail):
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "Sale."})
    ctx.llm.complete_result = TextBox("NO REPLY NEEDED")
    for mid in ("mS1", "mS2", "mS3"):
        _blast_mail(gmail, mid)
        asyncio.run(plugin._process(ctx, mid))
    assert len(ctx.delivered_messages) == 2   # first two alert
    assert len(ctx.llm.structured_calls) == 2  # third never reached the gate


def test_scam_storm_is_never_suppressed(plugin, ctx, gmail):
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Lure."})
    for i in range(4):
        mid = f"mSc{i}"
        gmail.respond("GET", f"/users/me/messages/{mid}", meta_response(
            sender="Lure <lure@scam.test>", subject="Order"))
        gmail.respond("GET", f"/users/me/messages/{mid}",
                      {"raw": make_raw(subject="Order", sender="Lure <lure@scam.test>",
                                       plain="Open the password protected PDF.")})
        asyncio.run(plugin._process(ctx, mid))
    assert len(ctx.delivered_messages) == 4  # security warnings outrank storm drops
    assert all(t.startswith("POSSIBLE SCAM") for t in ctx.delivered_messages)


def test_attachmentguard_toggle_off(plugin, ctx, gmail):
    ctx.config["module_attachmentguard_enabled"] = False
    gmail.respond("GET", "/users/me/messages/mOff", meta_response(
        sender="Lure <lure@scam.test>", subject="Invoice"))
    gmail.respond("GET", "/users/me/messages/mOff",
                  {"raw": _raw_with_attachment()})
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Invoice."})
    asyncio.run(plugin._process(ctx, "mOff"))
    assert ctx.delivered_messages == []  # gate decides; no module warning


def test_sample_tool_storm_suppression(plugin, ctx):
    plugin.register(ctx)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "Sale."})
    args = {"from": "Blast <blast@shop.test>", "subject": "Sale", "body": "Same sample."}
    assert asyncio.run(plugin._test(ctx, args))["verdict"] == "IMPORTANT"
    assert asyncio.run(plugin._test(ctx, args))["verdict"] == "IMPORTANT"
    third = asyncio.run(plugin._test(ctx, args))
    assert third["verdict"] == "NOISE"
    assert third["suppressed"] is True
    assert len(ctx.llm.structured_calls) == 2
