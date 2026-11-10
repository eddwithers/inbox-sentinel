"""Real imaplib/TLS connections to a scripted loopback IMAP fixture.

This is protocol integration, not a live Fastmail/iCloud/provider certification.
Only LLM and notification delivery are fakes; production transport is unchanged.
"""
import asyncio
from contextlib import contextmanager
from email.message import EmailMessage
import importlib.util
import shutil
import socketserver
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from typing import cast

import pytest
from conftest import ParsedBox, TextBox


class Mailbox:
    def __init__(self):
        self.messages = {}
        self.commands = []
        self.uidvalidity = 77
        self.fail_fetch_once = False
        self.login_ok = True
        self.examine_error = None
        self.size_fetch_responses = {}
        self.closed = threading.Event()


class Handler(socketserver.StreamRequestHandler):
    def finish(self):
        try:
            super().finish()
        finally:
            cast(Server, self.server).box.closed.set()

    def handle(self):
        self.connection.settimeout(5)
        box = cast(Server, self.server).box
        self.wfile.write(b'* OK Fictional IMAP fixture\r\n')
        while True:
            line = self.rfile.readline()
            if not line:
                return
            tag, _, rest = line.rstrip(b'\r\n').partition(b' ')
            command, _, args = rest.partition(b' ')
            command = command.upper()
            box.commands.append(command.decode())
            if command == b'CAPABILITY':
                self.wfile.write(b'* CAPABILITY IMAP4rev1\r\n' + tag + b' OK CAPABILITY\r\n')
            elif command == b'LOGIN':
                self.wfile.write(tag + (b' OK LOGIN\r\n' if box.login_ok else b' NO rejected\r\n'))
            elif command == b'EXAMINE':
                if box.examine_error is not None:
                    self.wfile.write(tag + b' ' + box.examine_error + b' private-fixture@example.test\r\n')
                    continue
                self.wfile.write(b'* FLAGS (\\Seen)\r\n* ' + str(len(box.messages)).encode() + b' EXISTS\r\n'
                                 + b'* OK [UIDVALIDITY ' + str(box.uidvalidity).encode() + b'] epoch\r\n'
                                 + tag + b' OK [READ-ONLY] EXAMINE\r\n')
            elif command == b'UID':
                subcommand, _, tail = args.partition(b' ')
                box.commands.append('UID ' + subcommand.decode())
                if subcommand.upper() == b'SEARCH':
                    low = 0 if tail == b'ALL' else int(tail.split()[1].split(b':')[0])
                    uids = [uid for uid in sorted(box.messages) if uid >= low]
                    self.wfile.write(b'* SEARCH ' + b' '.join(str(uid).encode() for uid in uids)
                                     + b'\r\n' + tag + b' OK SEARCH\r\n')
                elif subcommand.upper() == b'FETCH':
                    uid = int(tail.split()[0])
                    request = tail.decode('utf-8', 'ignore')
                    if b'RFC822.SIZE' in tail.upper():
                        size = box.size_fetch_responses.get(uid)
                        if size is None:
                            size = len(box.messages[uid]) if uid in box.messages else None
                        if size is None:
                            self.wfile.write(tag + b' NO missing size\r\n')
                        else:
                            self.wfile.write(b'* 1 FETCH (UID ' + str(uid).encode()
                                             + b' RFC822.SIZE ' + str(size).encode() + b')\r\n'
                                             + tag + b' OK FETCH\r\n')
                    else:
                        assert 'BODY.PEEK[]<0.262145>' in request
                        assert uid in box.messages
                        raw = box.messages[uid]
                        if box.fail_fetch_once:
                            box.fail_fetch_once = False
                            self.wfile.write(tag + b' NO temporary fixture failure\r\n')
                        else:
                            self.wfile.write(b'* 1 FETCH (UID ' + str(uid).encode()
                                             + b' BODY[]<0> {' + str(len(raw)).encode() + b'}\r\n'
                                             + raw + b')\r\n' + tag + b' OK FETCH\r\n')
                else:
                    self.wfile.write(tag + b' BAD unexpected UID operation\r\n')
            elif command == b'LOGOUT':
                self.wfile.write(b'* BYE fixture\r\n' + tag + b' OK LOGOUT\r\n')
                return
            else:
                self.wfile.write(tag + b' BAD forbidden operation\r\n')


class Server(socketserver.ThreadingTCPServer):
    box: Mailbox
    tls: ssl.SSLContext | None = None
    allow_reuse_address = True
    daemon_threads = True

    def get_request(self):
        sock, addr = super().get_request()
        if self.tls is not None:
            try:
                sock = self.tls.wrap_socket(sock, server_side=True)
            except ssl.SSLError:
                sock.close()
                raise
        return sock, addr


@contextmanager
def mailbox_server(tls=None):
    server = Server(('127.0.0.1', 0), Handler)
    server.box = Mailbox()
    server.tls = tls
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.fixture
def tls_cert(tmp_path):
    openssl = shutil.which('openssl')
    if not openssl:
        pytest.skip('openssl required for loopback TLS fixture certificate')
    config = tmp_path / 'openssl.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                      '[dn]\nCN=localhost\n[ext]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n'
                      'basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,digitalSignature,keyEncipherment\n')
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-config', str(config), '-keyout', str(key), '-out', str(cert)],
                   check=True, capture_output=True, timeout=10)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return cert, context


@pytest.fixture
def transport(plugin):
    spec = importlib.util.spec_from_file_location('wire_imap', Path(__file__).resolve().parents[1] / 'imap.py')
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._sentinel = plugin
    return module


def message(body='Would Tuesday at 10 work?', attached=False):
    msg = EmailMessage()
    msg['From'] = 'Demo <demo@example.test>'
    msg['To'] = 'reader@example.test'
    msg['Subject'] = 'Booking'
    msg.set_content(body)
    if attached:
        msg.add_attachment(b'fictional unread PDF', maintype='application', subtype='pdf', filename='details.pdf')
    return msg.as_bytes()


@contextmanager
def credentials():
    from agent.secret_scope import set_secret_scope, reset_secret_scope
    token = set_secret_scope({'INBOX_SENTINEL_IMAP_PASSWORD': 'fictional-test-password'})
    try:
        yield
    finally:
        reset_secret_scope(token)


def configure(ctx, server):
    ctx.config.update({'imap_host': '127.0.0.1', 'imap_port': server.server_address[1],
                       'imap_ssl': server.tls is not None, 'imap_user': 'reader@example.test',
                       'delivery_target': 'none'})


def test_tls_baseline_new_mail_retry_attachment_and_uidvalidity(transport, ctx, tls_cert, monkeypatch):
    cert, tls = tls_cert
    monkeypatch.setenv('SSL_CERT_FILE', str(cert))
    ctx.llm.structured_result = ParsedBox({'verdict': 'IMPORTANT', 'summary': 'Fictional booking request.'})
    ctx.llm.complete_result = TextBox('Tuesday works, thanks.')
    with mailbox_server(tls) as server, credentials():
        configure(ctx, server)
        server.box.messages[1] = message('Old baseline mail.')
        asyncio.run(transport.tick(ctx))
        assert ctx.state.get('imap_last_uid') == 1
        assert not ctx.llm.structured_calls
        server.box.messages[2] = message()
        server.box.fail_fetch_once = True
        asyncio.run(transport.tick(ctx))
        assert ctx.state.get('imap_last_uid') == 1
        assert ctx.state.get('fails') == {'imap:2': 1}
        asyncio.run(transport.tick(ctx))
        assert ctx.state.get('imap_last_uid') == 2
        assert len(ctx.llm.complete_calls) == 1
        assert ctx.state.get('fails') == {}
        server.box.messages[3] = message('Please read the attached details.', attached=True)
        asyncio.run(transport.tick(ctx))
        assert ctx.state.get('imap_last_uid') == 3
        assert len(ctx.llm.complete_calls) == 1  # unread attachment never drafted
        server.box.uidvalidity = 88
        server.box.messages = {1: message('New epoch baseline.')}
        asyncio.run(transport.tick(ctx))
        assert ctx.state.get('imap_last_uid') == 1
        assert ctx.state.get('imap_uidvalidity') == 88
        assert 'EXAMINE' in server.box.commands
        assert not {'SELECT', 'STORE', 'EXPUNGE', 'UID STORE'} & set(server.box.commands)
        assert not ctx.injected_messages


def test_untrusted_tls_certificate_is_rejected(transport, ctx, tls_cert, monkeypatch):
    _, tls = tls_cert
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    with mailbox_server(tls) as server, credentials():
        configure(ctx, server)
        with pytest.raises(ssl.SSLCertVerificationError):
            transport._connect(ctx)
        assert 'LOGIN' not in server.box.commands


def test_plaintext_remote_server_rejected_before_login(transport, ctx):
    ctx.config.update({'imap_host': 'mail.example.test', 'imap_user': 'reader@example.test',
                       'imap_ssl': False})
    with credentials(), pytest.raises(RuntimeError, match='loopback'):
        transport._connect(ctx)


def test_stalled_greeting_times_out(transport, ctx, monkeypatch):
    release = threading.Event()

    class SilentHandler(socketserver.BaseRequestHandler):
        def handle(self):
            release.wait(2)

    server = Server(('127.0.0.1', 0), SilentHandler)
    server.tls = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        configure(ctx, server)
        monkeypatch.setattr(transport, '_IMAP_TIMEOUT', 0.2, raising=False)
        with credentials(), pytest.raises(TimeoutError):
            transport._connect(ctx)
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_login_rejection_does_not_advance_cursor(transport, ctx):
    with mailbox_server() as server, credentials():
        configure(ctx, server)
        server.box.login_ok = False
        with pytest.raises(RuntimeError, match='imap login/select failed'):
            asyncio.run(transport.tick(ctx))
        assert ctx.state.get('imap_last_uid') is None
        assert 'EXAMINE' not in server.box.commands
        assert server.box.closed.wait(2)


@pytest.mark.parametrize('response', [b'NO', b'BAD'])
def test_examine_rejection_closes_socket_and_records_error(transport, plugin, ctx, monkeypatch, response):
    with mailbox_server() as server, credentials():
        configure(ctx, server)
        ctx.config.update({'provider': 'imap', 'enabled': True})
        server.box.examine_error = response

        async def tick_then_stop(current):
            try:
                await transport.tick(current)
            finally:
                current.config['enabled'] = False

        monkeypatch.setattr(plugin, '_tick', tick_then_stop)
        asyncio.run(plugin._watch_loop(ctx))
        assert ctx.state.get('last_error', '').startswith('RuntimeError')
        assert 'private-fixture' not in ctx.state.get('last_error', '')
        assert ctx.state.get('imap_last_uid') is None
        assert server.box.closed.wait(2)
        assert 'UID SEARCH' not in server.box.commands


def test_cleanup_failure_does_not_mask_login_failure(transport, ctx, monkeypatch):
    class BrokenClient:
        def login(self, user, password):
            raise transport.imaplib.IMAP4.error('private-fixture@example.test rejected')

        def shutdown(self):
            raise OSError('secondary socket cleanup failure')

    ctx.config.update({'imap_host': '127.0.0.1', 'imap_user': 'reader@example.test',
                       'imap_ssl': False})
    monkeypatch.setattr(transport.imaplib, 'IMAP4',
                        type('Factory', (), {'error': transport.imaplib.IMAP4.error,
                                             '__new__': lambda cls, *args, **kwargs: BrokenClient()}))
    with credentials(), pytest.raises(RuntimeError, match='imap login/select failed') as raised:
        transport._connect(ctx)
    assert isinstance(raised.value.__cause__, transport.imaplib.IMAP4.error)
    assert 'private-fixture' in str(raised.value.__cause__)
    assert 'private-fixture' not in str(raised.value)
