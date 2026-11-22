"""M2 mode-preset behaviour tests: Watcher / Desk-PA / Custom bundles over
module toggles, the fail-closed write-scope refusal seam, and status
disclosure. Fictional mail only; no network, no real model calls.
"""
from __future__ import annotations

import asyncio

import pytest

from conftest import ParsedBox, make_raw, meta_response

pytestmark = pytest.mark.usefixtures("capture_notifications")


def _module(plugin, name):
    return plugin._modules()[name]


# ---------------------------------------------------------------- presets

def test_custom_mode_honours_toggles(plugin, ctx):
    assert plugin._module_enabled(ctx, "scamshield", _module(plugin, "scamshield"))
    ctx.config["module_linkguard_enabled"] = False
    assert not plugin._module_enabled(ctx, "linkguard", _module(plugin, "linkguard"))
    ctx.config["mode"] = "custom"
    assert not plugin._module_enabled(ctx, "linkguard", _module(plugin, "linkguard"))


def test_watcher_preset_bundles_core_alerting(plugin, ctx):
    ctx.config["mode"] = "watcher"
    # Core read-only alerting ON — even against explicit toggles.
    for name in ("scamshield", "noisefilter", "senderlearning",
                 "drafter", "alertshaper", "inboxswitch"):
        ctx.config[f"module_{name}_enabled"] = False
        assert plugin._module_enabled(ctx, name, _module(plugin, name)), name
    # Platform guards beyond the production watcher contract OFF.
    for name in ("attachmentguard", "linkguard", "stormshield"):
        ctx.config[f"module_{name}_enabled"] = True
        assert not plugin._module_enabled(ctx, name, _module(plugin, name)), name


def test_desk_pa_preset_enables_all_shipped_modules(plugin, ctx):
    ctx.config["mode"] = "desk_pa"
    for name, mod in plugin._modules().items():
        ctx.config[f"module_{name}_enabled"] = False
        assert plugin._module_enabled(ctx, name, mod), name


def test_unknown_mode_degrades_to_custom(plugin, ctx):
    ctx.config["mode"] = "nonsense"
    ctx.config["module_linkguard_enabled"] = False
    assert not plugin._module_enabled(ctx, "linkguard", _module(plugin, "linkguard"))
    assert plugin._module_enabled(ctx, "scamshield", _module(plugin, "scamshield"))


def test_watcher_mode_pipeline_drops_guard_warnings(plugin, ctx):
    from email.message import EmailMessage
    msg = EmailMessage()
    msg.set_content("Please review this file.")
    msg.add_attachment(b"fictional", maintype="application", subtype="octet-stream", filename="invoice.exe")
    content = plugin._extract_message_content(plugin._parse_message_bytes(msg.as_bytes()))
    ctx.llm.structured_result = ParsedBox({"verdict": "NOISE", "summary": "File."})
    async def run():
        await plugin._run_pipeline(ctx, mid_prefix="gmail", mid="fixture",
            sender="a@example.test", subject="File", recipient="b@example.test",
            reply_to="a@example.test", label_ids=[], fetch_body=lambda: content)
    ctx.config["mode"] = "watcher"
    asyncio.run(run())
    assert ctx.delivered_messages == []
    ctx.config["mode"] = "custom"
    asyncio.run(run())
    assert ctx.delivered_messages[0].startswith("POSSIBLE SCAM")
    assert "IS-AttachmentGuard" in ctx.delivered_messages[0]



# ---------------------------------------------------------------- write refusal

def test_write_scope_module_is_refused(plugin, ctx, tmp_path, monkeypatch):
    """Fail-closed: a module declaring scopes beyond gmail.readonly never
    runs — no consent flow exists yet (design §5, M3+)."""
    mdir = tmp_path / "modules"
    mdir.mkdir()
    (mdir / "writemod.py").write_text(
        "NAME = 'writemod'\n"
        "STAGES = ('pre_gate',)\n"
        "SCOPES = ('gmail.modify',)\n"
        "def pre_gate(m, a):\n"
        "    return {'force_alert': True, 'signals': ['should never run'],\n"
        "            'brand': 'IS-WriteMod'}\n")
    monkeypatch.setattr(plugin, "__file__", str(tmp_path / "__init__.py"))
    plugin._MODULES = None
    mods = plugin._modules()
    assert "writemod" in mods  # discovered, but refused at run time
    view = {"sender": "x@example.test", "subject": "s", "body": "b",
            "recipient": "", "flags": {}}
    outcomes = asyncio.run(plugin._run_stage(ctx, "pre_gate", view))
    assert not any(o.get("brand") == "IS-WriteMod" for o in outcomes)


def test_readonly_scopes_declaration_runs(plugin, ctx, tmp_path, monkeypatch):
    mdir = tmp_path / "modules"
    mdir.mkdir()
    (mdir / "romod.py").write_text(
        "NAME = 'romod'\n"
        "STAGES = ('pre_gate',)\n"
        "SCOPES = ('gmail.readonly',)\n"
        "def pre_gate(m, a):\n"
        "    return {'ok': True}\n")
    monkeypatch.setattr(plugin, "__file__", str(tmp_path / "__init__.py"))
    plugin._MODULES = None
    outcomes = asyncio.run(plugin._run_stage(ctx, "pre_gate", {"flags": {}}))
    assert any(o.get("ok") for o in outcomes)


# ---------------------------------------------------------------- status

def test_status_discloses_mode_modules_accounts(plugin, ctx):
    out = plugin._status(ctx)
    assert out["mode"] == "custom"
    assert out["accounts"] == []
    mods = out["modules"]
    assert {"scamshield", "noisefilter", "senderlearning", "attachmentguard",
            "linkguard", "stormshield", "drafter", "alertshaper",
            "inboxswitch"} <= set(mods)
    assert all(mods.values())
    ctx.config["mode"] = "watcher"
    out = plugin._status(ctx)
    assert out["mode"] == "watcher"
    assert out["modules"]["linkguard"] is False
    assert out["modules"]["scamshield"] is True
