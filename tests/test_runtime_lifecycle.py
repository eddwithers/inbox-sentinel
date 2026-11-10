"""Unattended lifecycle through the real isolated Hermes plugin host.

Only external boundaries are fictional: Gmail responses, network, notifications.
The product register/hooks/task/loop/tick/process/state implementations are intact.
"""
from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path

import hermes_yaml as yaml
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Appended to the staged COPY, never to the installed or source plugin.
ADAPTER = r'''
import socket as _fixture_socket
from pathlib import Path as _FixturePath

_FIXTURE_EVENTS = _FixturePath(__EVENTS__)
_fixture_metadata_attempts = 0


def _fixture_record(kind):
    with _FIXTURE_EVENTS.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps({'event': kind, 'time': time.monotonic()}) + '\n')


def _fixture_forbidden(*args, **kwargs):
    _fixture_record('FORBIDDEN')
    raise AssertionError('Outbound network/notification forbidden in lifecycle test')


_fixture_socket.socket.connect = _fixture_forbidden
asyncio.create_subprocess_exec = _fixture_forbidden


def _fixture_gmail(method, path, params=()):
    global _fixture_metadata_attempts
    _fixture_record(path)
    if path == '/users/me/profile':
        return {'historyId': '100'}
    if path == '/users/me/messages':
        return {'messages': []}
    if path == '/users/me/history':
        return {'historyId': '101', 'history': [{'messagesAdded': [
            {'message': {'id': 'fixture', 'labelIds': ['INBOX']}}
        ]}]}
    if path == '/users/me/messages/fixture':
        _fixture_metadata_attempts += 1
        if _fixture_metadata_attempts == 1:
            _fixture_record('transient_failure')
            raise RuntimeError('fictional transient metadata failure')
        return {'payload': {'headers': [
            {'name': 'From', 'value': 'newsletter@example.test'},
            {'name': 'Subject', 'value': 'Weekly newsletter'},
            {'name': 'To', 'value': 'reader@example.test'}
        ]}, 'labelIds': ['INBOX', 'CATEGORY_PROMOTIONS']}
    raise AssertionError('Unexpected fixture Gmail request')


_gmail = _fixture_gmail
_product_register = register


def register(ctx):
    # Preserve all product registration, then add observation only.
    _product_register(ctx)

    async def _observe_start(**kwargs):
        task = _WATCHERS.get(ctx.profile_name)
        if task is not None:
            task.add_done_callback(lambda _done: _fixture_record('watcher_done'))

    ctx.register_hook('on_session_start', _observe_start)
'''


def _events(path):
    if not path.exists():
        return []
    return [json.loads(line)['event'] for line in path.read_text().splitlines() if line]


def _state(home):
    paths = list((home / 'plugin-data').glob('*/state.json'))
    if not paths:
        return {}
    try:
        return json.loads(paths[0].read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _wait(predicate, description, seconds=12):
    deadline = time.monotonic() + seconds
    wake = threading.Event()
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        wake.wait(0.05)
    raise AssertionError(f'Timed out waiting for {description}')


def _config(home, enabled):
    (home / 'config.yaml').write_text(yaml.safe_dump({'plugins': {
        'enabled': ['inbox-sentinel'], 'isolation': 'host',
        'entries': {'inbox-sentinel': {'settings': {
            'enabled': enabled, 'delivery_target': 'none',
            'poll_interval_seconds': 5, 'quiet_labels': ['CATEGORY_PROMOTIONS'],
            'keyword_overrides': []}}}}}), encoding='utf-8')


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    home = tmp_path / 'isolated-home'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setenv('HERMES_DISABLE_LAZY_INSTALLS', '1')
    monkeypatch.setenv('HOME', str(tmp_path / 'os-home'))
    empty = tmp_path / 'empty-bundled'
    empty.mkdir()
    monkeypatch.setattr('hermes_cli.plugins.get_bundled_plugins_dir', lambda: empty)
    plugin_dir = home / 'plugins' / 'inbox-sentinel'
    shutil.copytree(REPO_ROOT, plugin_dir,
                    ignore=shutil.ignore_patterns('.git', 'tests', '__pycache__', '.pytest_cache'))
    events = home / 'events.jsonl'
    init = plugin_dir / '__init__.py'
    init.write_text(init.read_text() + '\n' + ADAPTER.replace('__EVENTS__', repr(str(events))))
    from hermes_cli.plugins import PluginManager
    manager = PluginManager(scope_key=str(home))
    try:
        yield home, events, manager
    finally:
        manager.unload()
        host = getattr(manager, '_plugin_host_instance', None)
        if host is not None:
            host.shutdown()


def _load(manager):
    manager.discover_and_load()
    plugin = manager._plugins.get('inbox-sentinel')
    assert plugin is not None and plugin.enabled, getattr(plugin, 'error', 'not discovered')
    host = getattr(manager, '_plugin_host_instance', None)
    assert host is not None and host.alive, 'Must actually run in isolated plugin host'


def _start(manager):
    manager.invoke_hook('on_session_start', session_id='fictional', model='fixture', platform='cli')


def test_disabled_initial_boot_does_not_start_watcher(runtime):
    home, events, manager = runtime
    _config(home, False)
    _load(manager)
    _start(manager)
    assert _events(events) == []
    assert 'started_at' not in _state(home)


def test_hosted_watcher_start_retry_disable_resume_and_unload(runtime):
    home, events, manager = runtime
    _config(home, True)
    _load(manager)
    _start(manager)
    _wait(lambda: 'transient_failure' in _events(events), 'first automatic poll')
    first_start = _state(home)['started_at']
    first_poll = _state(home)['last_poll']
    assert first_poll is not None
    _start(manager)
    assert _state(home)['started_at'] == first_start
    _wait(lambda: 'fixture' in _state(home).get('seen', {}), 'automatic retry on next poll')
    assert _events(events).count('/users/me/messages/fixture') == 2
    assert _state(home).get('fails', {}) == {}

    _config(home, False)
    _wait(lambda: 'watcher_done' in _events(events), 'watcher exits after disable')
    calls_after_disable = len(_events(events))
    assert _state(home)['started_at'] == first_start
    # A disabled lifecycle event must not create a new task or poll.
    _start(manager)
    assert len(_events(events)) == calls_after_disable

    _config(home, True)
    _start(manager)
    _wait(lambda: _state(home).get('started_at', 0) > first_start, 'resume after enable')
    second_start = _state(home)['started_at']
    _start(manager)
    assert _state(home)['started_at'] == second_start
    done_before = _events(events).count('watcher_done')
    manager.unload()
    _wait(lambda: _events(events).count('watcher_done') > done_before, 'owned task cancellation on unload')
    assert _state(home)['last_poll'] >= first_poll
    assert 'FORBIDDEN' not in _events(events)
