"""Integration tests for Inbox Sentinel against Hermes plugin discovery.

These tests stage the plugin into an isolated HERMES_HOME, let Hermes discover
it for real, and exercise registered tools through the registry instead of a
hand-rolled ctx stub.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _stage_plugin(home: Path) -> Path:
    plugin_dir = home / "plugins" / "inbox-sentinel"
    shutil.copytree(
        REPO_ROOT,
        plugin_dir,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "tests", ".pytest_cache"),
    )
    (home / "config.yaml").write_text("plugins:\n  enabled:\n    - inbox-sentinel\n", encoding="utf-8")
    return plugin_dir


def test_real_plugin_discovery_and_tool_invocation(tmp_path, monkeypatch):
    """Hermes must discover the plugin from temp HERMES_HOME and run its tools."""
    home = tmp_path / "hermes-home"
    home.mkdir()
    _stage_plugin(home)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.syspath_prepend(str(Path.home() / ".hermes" / "hermes-agent"))

    from hermes_cli.plugins import PluginManager
    from tools.registry import registry

    manager = PluginManager(scope_key=str(home))
    manager.discover_and_load()
    try:
        # Loaded either in-process or through the plugin host; in both cases the
        # plugin must register tool handlers successfully.
        loaded = [name for name in manager._plugins if "inbox" in name]
        assert loaded, "Inbox Sentinel should be discovered from temp HERMES_HOME"

        feedback_raw = registry.dispatch(
            "inbox_sentinel_feedback",
            {"sender": "vip@example.test", "feedback": "important", "note": "local"},
            scope=manager.scope_key,
        )
        assert isinstance(feedback_raw, str)
        feedback_payload = json.loads(feedback_raw)
        feedback = feedback_payload.get("result", feedback_payload) if isinstance(feedback_payload, dict) else feedback_payload
        assert feedback["ok"] is True

        status_raw = registry.dispatch("inbox_sentinel_status", {}, scope=manager.scope_key)
        assert isinstance(status_raw, str)
        status_payload = json.loads(status_raw)
        status = status_payload.get("result", status_payload) if isinstance(status_payload, dict) else status_payload
        assert status["learned_important_senders"] == 1
        assert status["learned_gate_notes"] == 1
    finally:
        manager.unload()
        host = getattr(manager, "_plugin_host_instance", None)
        if host is not None:
            host.shutdown()


@pytest.mark.parametrize("isolation", ["host", "in_process"])
def test_real_host_registers_model_slots_and_trust_gate_accepts_only_them(tmp_path, monkeypatch, isolation):
    """The real manager records both slots for this plugin; the real ctx.llm trust
    gate accepts them for this plugin only. No provider or model is invoked."""
    home = tmp_path / "hermes-home"
    home.mkdir()
    _stage_plugin(home)
    (home / "config.yaml").write_text(
        f"plugins:\n  enabled:\n    - inbox-sentinel\n  isolation: {isolation}\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(Path.home() / ".hermes" / "hermes-agent"))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_DISABLE_LAZY_INSTALLS", "1")
    monkeypatch.setenv("HOME", str(tmp_path / "os-home"))
    empty = tmp_path / "empty-bundled"
    empty.mkdir()
    monkeypatch.setattr("hermes_cli.plugins.get_bundled_plugins_dir", lambda: empty)

    import hermes_cli.plugins as plugins_mod
    from agent import plugin_llm
    from hermes_cli.plugins import PluginManager

    manager = PluginManager(scope_key=str(home))
    manager.discover_and_load()
    monkeypatch.setattr(plugins_mod, "_ensure_plugins_discovered", lambda *a, **k: manager)
    try:
        loaded = manager._plugins.get("inbox-sentinel")
        assert loaded is not None and loaded.enabled, getattr(loaded, "error", "not discovered")
        if isolation == "host":
            host = getattr(manager, "_plugin_host_instance", None)
            assert host is not None and host.alive, "must really run in the isolated plugin host"
        slots = {key: entry for key, entry in manager._aux_tasks.items() if key.startswith("inbox_sentinel_")}
        assert set(slots) == {"inbox_sentinel_gate", "inbox_sentinel_draft"}
        owner = {entry["plugin"] for entry in slots.values()}
        assert len(owner) == 1
        owner_id = owner.pop()
        assert slots["inbox_sentinel_gate"]["defaults"]["provider"] == "auto"
        assert slots["inbox_sentinel_gate"]["defaults"]["model"] == ""

        policy = plugin_llm._TrustPolicy(plugin_id=owner_id)
        for key in slots:
            assert plugin_llm._check_task(policy, plugin_id=owner_id, requested_task=key) == key

        stranger = plugin_llm._TrustPolicy(plugin_id="someone-else")
        with pytest.raises(Exception):
            plugin_llm._check_task(stranger, plugin_id="someone-else", requested_task="inbox_sentinel_gate")
        with pytest.raises(Exception):
            plugin_llm._check_task(policy, plugin_id=owner_id, requested_task="compression")
    finally:
        manager.unload()
        host = getattr(manager, "_plugin_host_instance", None)
        if host is not None:
            host.shutdown()
