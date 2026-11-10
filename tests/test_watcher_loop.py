"""In-process watcher must outlive the loop that started it.

Under the multiplex gateway with ``plugins.isolation: in_process``, lifecycle
hooks run on a per-turn event loop that ends with the turn. The watcher must
keep polling after that loop is gone, and stop cleanly on unload.
"""
from __future__ import annotations

import asyncio
import threading
import time


class _RealSpawnCtx:
    """Mirrors in-process PluginContext.spawn_task: a task on the running loop."""

    def __init__(self, base):
        self._base = base

    def __getattr__(self, name):
        return getattr(self._base, name)

    def spawn_task(self, coro, name=None):
        return asyncio.get_running_loop().create_task(coro, name=name)


def _wait(predicate, seconds=5.0):
    deadline = time.monotonic() + seconds
    stop = threading.Event()
    while time.monotonic() < deadline:
        if predicate():
            return True
        stop.wait(0.02)
    return False


def test_watcher_survives_end_of_turn_loop_and_stops_on_unload(plugin, ctx, monkeypatch):
    ticks = []
    gone = threading.Event()

    async def fake_loop(_ctx):
        try:
            while True:
                ticks.append(time.monotonic())
                await asyncio.sleep(0.02)
        finally:
            gone.set()

    monkeypatch.setattr(plugin, "_watch_loop", fake_loop)
    ctx.config["enabled"] = True
    live = _RealSpawnCtx(ctx)

    async def one_turn():
        plugin._ensure_watcher(live)

    asyncio.run(one_turn())  # the "turn" loop is closed when this returns

    count = len(ticks)
    assert _wait(lambda: len(ticks) > count + 5), "watcher stopped when the turn loop ended"
    task = plugin._WATCHERS[ctx.profile_name]
    assert not task.done()
    assert task.get_loop() is plugin._runner_loop()

    # A second turn does not start a duplicate watcher.
    asyncio.run(one_turn())
    assert plugin._WATCHERS[ctx.profile_name] is task

    plugin._stop_watcher(ctx)
    assert gone.wait(5), "unload must cancel the watcher on its own loop"
    assert ctx.profile_name not in plugin._WATCHERS


def test_plugin_host_path_still_uses_spawn_task_directly(plugin, ctx, monkeypatch):
    calls = []

    class HostCtx(_RealSpawnCtx):
        def spawn_task(self, coro, name=None):
            calls.append(threading.current_thread().name)
            coro.close()

            class _Done:
                def done(self):
                    return False

                def add_done_callback(self, _cb):
                    pass

            return _Done()

    HostCtx.__module__ = "hermes_cli.plugin_host_child"
    ctx.config["enabled"] = True

    async def one_turn():
        plugin._ensure_watcher(HostCtx(ctx))

    asyncio.run(one_turn())
    assert calls == [threading.current_thread().name]  # called in place, not on the runner
