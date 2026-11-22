"""M1a prefilter-module behaviour tests: noise filter + sender learning.

Pins the modular prefilter contract: priority order, toggles, zero-cost drops
before any body fetch, vip rescue and gate override via stage outcomes, and
the bounded ModuleAPI (declared shared state, config reads, pure helpers).
Fictional mail only; no network, no real model calls.
"""
from __future__ import annotations

import asyncio

import pytest

from conftest import ParsedBox, TextBox, make_raw, meta_response

pytestmark = pytest.mark.usefixtures("capture_notifications")


def _promo_mail(gmail, mid="mPromo", sender="Deals <deals@shop.test>",
                subject="20% off everything", labels=("INBOX", "CATEGORY_PROMOTIONS")):
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  meta_response(sender=sender, subject=subject,
                                label_ids=list(labels)))
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  {"raw": make_raw(subject=subject, sender=sender,
                                   plain="Sale now on.")})


# ---------------------------------------------------------------- discovery

def test_prefilter_modules_discovered(plugin):
    mods = plugin._modules()
    assert {"noisefilter", "senderlearning"} <= set(mods)
    assert mods["senderlearning"].PRIORITY < mods["noisefilter"].PRIORITY
    assert "gate" in mods["senderlearning"].STAGES
    assert mods["senderlearning"].SHARED_STATE == (
        "learned_blocked_senders", "learned_vip_senders")


def test_prefilter_runs_in_priority_order(plugin, ctx, monkeypatch):
    order = []
    for name in ("noisefilter", "senderlearning"):
        mod = plugin._modules()[name]
        monkeypatch.setattr(mod, "prefilter",
                            lambda m, a, n=name: order.append(n))
    asyncio.run(plugin._run_stage(ctx, "prefilter", {"sender": "x@example.test"}))
    assert order == ["senderlearning", "noisefilter"]


# ---------------------------------------------------------------- toggles

def test_disabled_noisefilter_lets_promotions_reach_gate(plugin, ctx, gmail):
    ctx.config["module_noisefilter_enabled"] = False
    ctx.config["quiet_labels"] = ["CATEGORY_PROMOTIONS"]
    ctx.config["keyword_overrides"] = ["urgent"]
    _promo_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Sale."})
    asyncio.run(plugin._process(ctx, "mPromo"))
    assert len(ctx.llm.structured_calls) == 1  # gate decides, not the module
    assert ctx.delivered_messages == []


def test_disabled_senderlearning_ignores_learned_rule(plugin, ctx, gmail):
    ctx.config["module_senderlearning_enabled"] = False
    ctx.state.set("learned_blocked_senders", {"deals@shop.test": 1})
    _promo_mail(gmail, labels=["INBOX"])
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Sale."})
    asyncio.run(plugin._process(ctx, "mPromo"))
    assert len(ctx.llm.structured_calls) == 1
    assert ctx.delivered_messages == []


def test_learned_drop_happens_before_body_fetch(plugin, ctx, gmail):
    """Only metadata is stubbed: a raw fetch would raise. The learned-rule
    drop must keep its zero-cost position before any body access."""
    ctx.state.set("learned_blocked_senders", {"deals@shop.test": 1})
    gmail.respond("GET", "/users/me/messages/mDrop",
                  meta_response(sender="Deals <deals@shop.test>", subject="Sale"))
    asyncio.run(plugin._process(ctx, "mDrop"))
    assert ctx.delivered_messages == []
    assert ctx.llm.structured_calls == []


# ---------------------------------------------------------------- vip path

def test_vip_rescue_and_gate_override_via_modules(plugin, ctx, gmail):
    ctx.state.set("learned_vip_senders", {"alice@example.test": 1})
    ctx.config["quiet_labels"] = ["CATEGORY_PROMOTIONS"]
    ctx.config["keyword_overrides"] = []
    _promo_mail(gmail, mid="mVip", sender="Alice <alice@example.test>",
                subject="Weekly offers")
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Offers."})
    ctx.llm.complete_result = TextBox("NO REPLY NEEDED")
    asyncio.run(plugin._process(ctx, "mVip"))
    assert len(ctx.llm.structured_calls) == 1  # rescued from the quiet label
    assert len(ctx.delivered_messages) == 1    # NOISE overruled by the exact rule
    assert ctx.delivered_messages[0].startswith("EMAIL ALERT")


def test_flags_flow_from_prefilter_to_gate_stage(plugin, ctx):
    ctx.state.set("learned_vip_senders", {"alice@example.test": 1})
    view = {"sender": "Alice <alice@example.test>", "subject": "Hi",
            "recipient": "me@example.test", "label_ids": [], "flags": {}}
    for outcome in asyncio.run(plugin._run_stage(ctx, "prefilter", view)):
        flags = outcome.get("flags")
        if isinstance(flags, dict):
            view["flags"].update(flags)
    assert view["flags"].get("vip") is True
    view["verdict"] = "NOISE"
    assert any(o.get("force_important")
               for o in asyncio.run(plugin._run_stage(ctx, "gate", view)))


# ---------------------------------------------------------------- bounded API

def test_shared_state_requires_declaration(plugin, ctx):
    mod = plugin._modules()["senderlearning"]
    api = plugin._ModuleAPI(ctx, "senderlearning", mod)
    ctx.state.set("learned_blocked_senders", {"a@b.test": 1})
    assert api.shared_get("learned_blocked_senders") == {"a@b.test": 1}
    with pytest.raises(PermissionError):
        api.shared_get("seen")  # host cursor: not declared, not readable
    with pytest.raises(PermissionError):
        plugin._ModuleAPI(ctx, "noisefilter",
                          plugin._modules()["noisefilter"]).shared_get(
                              "learned_blocked_senders")


def test_config_get_reads_host_config(plugin, ctx):
    ctx.config["quiet_labels"] = ["CATEGORY_UPDATES"]
    api = plugin._ModuleAPI(ctx, "noisefilter", plugin._modules()["noisefilter"])
    assert api.config_get("quiet_labels") == ["CATEGORY_UPDATES"]
    assert api.config_get("missing_key", "fallback") == "fallback"


def test_sender_matches_helper_is_canonical(plugin, ctx):
    api = plugin._ModuleAPI(ctx, "senderlearning",
                            plugin._modules()["senderlearning"])
    assert api.sender_matches("Alice <alice@example.test>", "alice@example.test")
    assert api.sender_matches("Alice <alice@example.test>", "@example.test")
    assert not api.sender_matches("Alice <alice@example.test>", "@sub.example.test")
    assert not api.sender_matches("Alice <alice@evil.test>", "alice@example.test")


def test_boundary_violation_degrades_to_host_default(plugin, ctx, gmail, monkeypatch):
    mod = plugin._modules()["senderlearning"]

    def violating(message, api):
        api.shared_get("seen")  # undeclared — must fail closed, not leak
        return {"drop": True, "reason": "should never apply"}

    monkeypatch.setattr(mod, "prefilter", violating)
    ctx.state.set("learned_blocked_senders", {"deals@shop.test": 1})
    _promo_mail(gmail, mid="mDeg", labels=["INBOX"])
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Sale."})
    asyncio.run(plugin._process(ctx, "mDeg"))  # must not raise
    assert len(ctx.llm.structured_calls) == 1  # host default: mail reaches the gate
    assert ctx.delivered_messages == []
