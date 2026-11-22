"""Module system behaviour tests (M0): discovery, toggles, isolation, failure.

The host owns transport, budgets, delivery and alert shaping; modules plug
into named stages through a bounded API. These tests pin that contract with
fictional mail and stubbed surfaces — no network, no real model calls.
"""
from __future__ import annotations

import asyncio

import pytest

from conftest import ParsedBox, make_raw, meta_response

pytestmark = pytest.mark.usefixtures("capture_notifications")


SCAM_BODY = "Open the password protected PDF to confirm your order."


def _scam_mail(gmail, mid="mMod"):
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  meta_response(sender="Lure <lure@scam.test>", subject="Order"))
    gmail.respond("GET", f"/users/me/messages/{mid}",
                  {"raw": make_raw(subject="Order", sender="Lure <lure@scam.test>",
                                   plain=SCAM_BODY)})


# ---------------------------------------------------------------- discovery

def test_scamshield_is_discovered_with_declarations(plugin):
    mods = plugin._modules()
    assert "scamshield" in mods
    m = mods["scamshield"]
    assert m.NAME == "scamshield"
    assert m.BRAND == "IS-ScamShield"
    assert "pre_gate" in m.STAGES
    assert m.DEFAULT_ENABLED is True
    assert callable(m.pre_gate)


def test_loader_skips_malformed_and_broken_modules(plugin, tmp_path, monkeypatch):
    mdir = tmp_path / "modules"
    mdir.mkdir()
    (mdir / "noname.py").write_text("STAGES = ('pre_gate',)\ndef pre_gate(m, a):\n    return None\n")
    (mdir / "nohandler.py").write_text("NAME = 'x'\nSTAGES = ('pre_gate',)\n")
    (mdir / "broken.py").write_text("raise RuntimeError('boom')\n")
    (mdir / "_private.py").write_text("NAME = 'p'\nSTAGES = ('pre_gate',)\ndef pre_gate(m, a):\n    return None\n")
    (mdir / "good.py").write_text(
        "NAME = 'good'\nSTAGES = ('pre_gate',)\ndef pre_gate(m, a):\n    return {'ok': True}\n")
    monkeypatch.setattr(plugin, "__file__", str(tmp_path / "__init__.py"))
    plugin._MODULES = None
    mods = plugin._modules()
    assert set(mods) == {"good"}


def test_missing_modules_dir_is_empty_not_fatal(plugin, tmp_path, monkeypatch):
    monkeypatch.setattr(plugin, "__file__", str(tmp_path / "__init__.py"))
    plugin._MODULES = None
    assert plugin._modules() == {}


# ---------------------------------------------------------------- toggles

def test_disabled_scamshield_takes_normal_path(plugin, ctx, gmail):
    ctx.config["module_scamshield_enabled"] = False
    _scam_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Order."})
    asyncio.run(plugin._process(ctx, "mMod"))
    assert ctx.delivered_messages == []  # gate decides, as before the module existed


def test_disabled_scamshield_important_mail_alerts_normally(plugin, ctx, gmail):
    ctx.config["module_scamshield_enabled"] = False
    _scam_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "IMPORTANT", "summary": "Order."})
    asyncio.run(plugin._process(ctx, "mMod"))
    assert len(ctx.delivered_messages) == 1
    assert ctx.delivered_messages[0].startswith("EMAIL ALERT")
    assert "POSSIBLE SCAM" not in ctx.delivered_messages[0]


def test_disabled_module_handler_is_not_called(plugin, ctx, monkeypatch):
    ctx.config["module_scamshield_enabled"] = False
    calls = []
    mod = plugin._modules()["scamshield"]
    monkeypatch.setattr(mod, "pre_gate", lambda m, a: calls.append(1))
    assert asyncio.run(plugin._run_stage(ctx, "pre_gate", {})) == []
    assert calls == []


def test_default_enabled_without_config(plugin, ctx, gmail):
    _scam_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Order."})
    asyncio.run(plugin._process(ctx, "mMod"))
    assert len(ctx.delivered_messages) == 1
    assert ctx.delivered_messages[0].startswith("POSSIBLE SCAM")


# ---------------------------------------------------------------- isolation

def test_module_state_is_namespaced(plugin, ctx):
    api_a = plugin._ModuleAPI(ctx, "alpha")
    api_b = plugin._ModuleAPI(ctx, "beta")
    api_a.state_set("count", 7)
    assert ctx.state.get("module_alpha_count") == 7
    assert api_a.state_get("count") == 7
    assert api_b.state_get("count") is None  # cannot read another module's state
    api_b.state_set("count", 9)
    assert api_a.state_get("count") == 7


def test_non_dict_outcomes_are_ignored(plugin, ctx, monkeypatch):
    mod = plugin._modules()["scamshield"]
    monkeypatch.setattr(mod, "pre_gate", lambda m, a: "not a dict")
    assert asyncio.run(plugin._run_stage(ctx, "pre_gate", {})) == []


def test_failing_module_degrades_to_host_default(plugin, ctx, gmail, monkeypatch):
    mod = plugin._modules()["scamshield"]

    def boom(message, api):
        raise RuntimeError("module bug")

    monkeypatch.setattr(mod, "pre_gate", boom)
    _scam_mail(gmail)
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "Order."})
    asyncio.run(plugin._process(ctx, "mMod"))  # must not raise
    assert ctx.delivered_messages == []  # host default: gate decides


def test_stage_filters_by_declaration(plugin, ctx, monkeypatch):
    # Host-only stages run no modules at all.
    assert asyncio.run(plugin._run_stage(ctx, "deliver", {})) == []
    # scamshield declares only pre_gate; it must not run at post_gate
    # (which now has its own declared modules).
    calls = []
    mod = plugin._modules()["scamshield"]
    monkeypatch.setattr(mod, "pre_gate", lambda m, a: calls.append(1))
    asyncio.run(plugin._run_stage(ctx, "post_gate", {}))
    assert calls == []


def test_stages_declaration_filter_is_real(plugin, ctx, monkeypatch):
    """Pin the STAGES filter itself: give scamshield a post_gate attribute
    it does not declare. A missing attribute would be swallowed as a module
    failure, so only a present-but-undeclared handler detects the filter
    (gate-audit finding, 22 Nov)."""
    mod = plugin._modules()["scamshield"]
    calls = []
    monkeypatch.setattr(mod, "post_gate", lambda m, a: calls.append(1),
                        raising=False)
    asyncio.run(plugin._run_stage(ctx, "post_gate", {}))
    assert calls == []
