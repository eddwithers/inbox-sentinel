"""Cancellation and budget contracts for IMAP; fictional transports only."""
import asyncio
import importlib.util
from pathlib import Path
import threading

import pytest


@pytest.fixture
def imap(plugin):
    spec = importlib.util.spec_from_file_location('imap_cancel_test',
        Path(__file__).resolve().parents[1] / 'imap.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._sentinel = plugin
    return module


def test_cancelled_connect_closes_client_even_if_worker_already_completed(imap, ctx, monkeypatch):
    class Client:
        closed = False
        def logout(self):
            self.closed = True
    client = Client()
    # Reproduce the race: worker returns; before shield resumes the awaiting
    # coroutine, task cancellation wins. The client still must be closed.
    async def run():
        caller = asyncio.current_task()
        async def completed_worker(*args):
            asyncio.get_running_loop().call_soon(caller.cancel)
            return client
        monkeypatch.setattr(imap.asyncio, 'to_thread', completed_worker)
        closed = []
        async def close(value):
            value.logout()
            closed.append(value)
        monkeypatch.setattr(imap, '_close_client_async', close)
        with pytest.raises(asyncio.CancelledError):
            await imap._connect_async(ctx)
        assert closed == [client]
    asyncio.run(run())
    assert client.closed


def test_model_budget_exhaustion_does_not_burn_imap_retry(imap, plugin, ctx, monkeypatch):
    class Client:
        def response(self, code):
            return 'UIDVALIDITY', [b'1']
        def uid(self, *args):
            return 'OK', [b'2']
        def logout(self):
            return 'BYE', []
    client = Client()
    async def connect(_ctx):
        return client
    async def process(*args):
        raise plugin.GateBudgetExhausted('race: sample tool reserved final gate slot')
    monkeypatch.setattr(imap, '_connect_async', connect)
    monkeypatch.setattr(imap, '_process_uid', process)
    ctx.state.set('imap_last_uid', 1)
    ctx.state.set('imap_uidvalidity', 1)
    with pytest.raises(plugin.GateBudgetExhausted):
        asyncio.run(imap.tick(ctx))
    assert ctx.state.get('imap_last_uid') == 1
    assert not ctx.state.get('fails')


def test_threaded_operation_finishes_before_client_cleanup(imap, monkeypatch):
    order = []
    async def run():
        started = threading.Event()
        release = threading.Event()
        def operation():
            started.set()
            assert release.wait(2)
            order.append('operation_done')
        task = asyncio.create_task(imap._imap_call(operation))
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        order.append('cleanup')
    asyncio.run(run())
    assert order == ['operation_done', 'cleanup']
