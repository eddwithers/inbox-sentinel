"""Generic IMAP provider for Inbox Sentinel.

A read-only, stdlib-only polling loop:

* fresh ``imaplib.IMAP4_SSL`` connection per tick (at 15 s this is cheap and
  avoids any dangling-connection failure modes),
* ``SELECT`` the configured folder **read-only** (BODY.PEEK, never a
  server-side flag write),
* on first tick, record the folder's current max UID as the baseline —
  pre-existing mail is never alerted,
* on each subsequent tick, ``UID SEARCH UID <baseline+1>:*`` then
  ``UID FETCH ... (BODY.PEEK[])`` the new ones, parse the RFC 822 bytes with
  the shared BytesParser helper, and hand each message to the same
  ``_run_pipeline`` the Gmail path uses.

The IMAP password is resolved through ``agent.secret_scope.get_secret`` so a
multiplexing gateway serves the right profile's credential; host and other
non-secret knobs come from ``ctx.get_config``.

No writes to the server (``STORE``/``EXPUNGE``/marked-seen flags) and no
network calls from the tests — the loop uses ``imaplib`` at module level so
tests substitute a fake via ``monkeypatch``.
"""
from __future__ import annotations

import asyncio
import imaplib
import logging
import re
import ssl
import time
from contextlib import suppress

logger = logging.getLogger("inbox_sentinel.imap")
_IMAP_TIMEOUT = 30
_MAX_UIDS_PER_TICK = 20
_RESOURCE_REASON = "Message too large or size unavailable; review original email."

# Populated by the parent ``__init__.py`` when it loads this module via
# ``spec_from_file_location``. Tests set it directly on the fresh module.
_sentinel = None  # type: ignore[assignment]


def _s():
    """Return the parent sentinel module (shared helpers live there)."""
    global _sentinel
    if _sentinel is None:
        import sys
        # Fall back to the standard package path when imported normally.
        _sentinel = sys.modules.get("inbox_sentinel") or sys.modules.get(
            __name__.rsplit(".", 1)[0]
        )
    if _sentinel is None:
        raise RuntimeError("inbox-sentinel imap module: parent not resolvable")
    return _sentinel


def _cfg(ctx, key, default):
    return _s()._cfg(ctx, key, default)


def _get_imap_password():
    """Resolve the IMAP password from the profile's secret scope.

    Catalog rule 11: plugins MUST go through ``agent.secret_scope.get_secret``
    so a multiplexing gateway serves the right profile's value (reading
    ``os.environ`` directly can leak another profile's secret). If the host
    cannot provide a secret scope, fail closed; never fall back to raw env.
    """
    try:
        from agent.secret_scope import get_secret
    except Exception:
        logger.warning("imap password lookup unavailable: secret scope import failed")
        return None
    try:
        return get_secret("INBOX_SENTINEL_IMAP_PASSWORD")
    except Exception as exc:
        logger.warning("imap password lookup failed (%s)", type(exc).__name__)
        return None


# ---------------------------------------------------------------- connection

def _connect(ctx):
    """Open, login, select — synchronous helper for direct tests."""
    return _connect_sync(ctx)


def _connect_sync(ctx):
    """Open, login, select — returns the connected ``imaplib`` client.

    Caller owns ``logout()`` in a ``finally`` so a mid-tick exception never
    leaks a socket or a half-authed session.
    """
    host = (_cfg(ctx, "imap_host", "") or "").strip()
    port = int(_cfg(ctx, "imap_port", 993))
    use_ssl = bool(_cfg(ctx, "imap_ssl", True))
    user = (_cfg(ctx, "imap_user", "") or "").strip()
    folder = _cfg(ctx, "imap_folder", "INBOX") or "INBOX"
    password = _get_imap_password()

    if not host:
        raise RuntimeError("imap_host is not configured")
    if not user:
        raise RuntimeError("imap_user is not configured")
    if password is None:
        raise RuntimeError("INBOX_SENTINEL_IMAP_PASSWORD is not set")

    if not use_ssl:
        from ipaddress import ip_address
        try:
            loopback = ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise RuntimeError("Plaintext IMAP is allowed only for a literal loopback address")

    if use_ssl:
        client = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(),
                                  timeout=_IMAP_TIMEOUT)
    else:
        client = imaplib.IMAP4(host, port, timeout=_IMAP_TIMEOUT)

    try:
        client.login(user, password)
        typ, _data = client.select(folder, readonly=True)
        if typ != "OK":
            raise RuntimeError(f"imap select failed: {typ}")
    except Exception as exc:
        with suppress(OSError):
            client.shutdown()
        if isinstance(exc, imaplib.IMAP4.error):
            raise RuntimeError("imap login/select failed") from exc
        raise
    return client


async def _connect_async(ctx):
    task = asyncio.create_task(asyncio.to_thread(_connect_sync, ctx))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        # A completed worker can race cancellation before the caller takes
        # ownership. Retrieve its result and close it on either side of that race.
        try:
            client = await asyncio.shield(task)
        except Exception:
            pass
        else:
            await _close_client_async(client)
        raise


async def _imap_call(operation, *args):
    task = asyncio.create_task(asyncio.to_thread(operation, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        # imaplib is not thread safe: finish the socket operation before the
        # tick's finally block performs logout. Socket timeout bounds the wait.
        with suppress(Exception):
            await asyncio.shield(task)
        raise


def _parse_rfc822(raw_bytes):
    """Parse a raw RFC 822 message with the same stdlib parser Gmail uses."""
    return _s()._parse_message_bytes(raw_bytes)


def _extract_body(parsed):
    return _s()._extract_message_content(parsed)["body"]


def _header(parsed, name, default=""):
    v = parsed.get(name)
    return str(v) if v is not None else default


# ---------------------------------------------------------------- tick

async def tick(ctx):
    """One IMAP poll: connect → list new UIDs → run the shared pipeline.

    Exceptions bubble up to the watch loop's generic handler (``last_error``
    is set, the loop survives, the next tick reconnects fresh).
    """
    if not _s()._gate_budget_available(ctx):
        raise _s().GateBudgetExhausted("Daily classification cap reached; pending mail deferred")
    state = ctx.state
    client = await _connect_async(ctx)
    try:
        last_uid = state.get("imap_last_uid")
        current_uidvalidity = _uidvalidity(client)
        stored_uidvalidity = state.get("imap_uidvalidity")
        if last_uid is not None and stored_uidvalidity is not None and current_uidvalidity != stored_uidvalidity:
            logger.warning("imap UIDVALIDITY changed %r -> %r — resetting cursor",
                           stored_uidvalidity, current_uidvalidity)
            last_uid = None
            state.set("fails", {})
        if last_uid is None:
            # Baseline: record the folder's current max UID so pre-existing
            # mail is never alerted. UID SEARCH ALL returns every UID in the
            # folder; the max is our starting cursor.
            typ, data = await _imap_call(client.uid, "SEARCH", None, "ALL")
            if typ != "OK":
                raise RuntimeError(f"imap SEARCH failed: {typ}")
            raw = data[0] if data else b""
            uids = [int(x) for x in (raw.split() if raw else [])]
            baseline = max(uids) if uids else 0
            state.set("imap_last_uid", baseline)
            state.set("imap_uidvalidity", current_uidvalidity)
            state.set("last_poll", time.time())
            logger.info("imap bootstrapped at uid %s (%s baseline msgs)",
                        baseline, len(uids))
            return

        # New mail: anything with UID > last_uid. ``UID SEARCH UID N:*``
        # always returns the message with the highest UID even when nothing
        # is strictly greater than N (standard quirk), so filter in Python.
        typ, data = await _imap_call(client.uid, "SEARCH", None,
                                            f"UID {int(last_uid) + 1}:*")
        if typ != "OK":
            raise RuntimeError(f"imap SEARCH failed: {typ}")
        raw = data[0] if data else b""
        uids = sorted(int(x) for x in (raw.split() if raw else []))
        new_uids = [u for u in uids if u > int(last_uid)]

        fails = state.get("fails", {})
        high_water = int(last_uid)
        try:
            for processed, uid in enumerate(new_uids):
                if processed >= _MAX_UIDS_PER_TICK:
                    break
                if not _s()._gate_budget_available(ctx):
                    break
                mid = f"imap:{uid}"
                try:
                    await _process_uid(ctx, client, uid)
                    high_water = max(high_water, uid)
                    fails.pop(mid, None)
                except _s().GateBudgetExhausted:
                    raise
                except Exception as exc:
                    fails[mid] = fails.get(mid, 0) + 1
                    logger.warning("imap processing failed (attempt %s, %s)",
                                   fails[mid], type(exc).__name__)
                    if fails[mid] >= _s().RETRY_CAP:
                        logger.error("giving up on %s after %s attempts — advancing cursor",
                                     mid, fails[mid])
                        try:
                            await _s()._deliver(ctx, "\n".join([
                                "EMAIL ALERT (delivery failed after retries)",
                                "",
                                f"The watcher gave up on this message after {fails[mid]} attempts.",
                                f"msgid: {mid}"]))
                        except Exception as exc2:
                            logger.warning("imap give-up notification failed (%s)", type(exc2).__name__)
                        high_water = max(high_water, uid)
                        fails.pop(mid, None)
                    else:
                        # Don't advance past a transient failure — retry on
                        # the next tick by leaving the cursor behind this UID.
                        break
        finally:
            if high_water > int(last_uid):
                state.set("imap_last_uid", high_water)
            state.set("imap_uidvalidity", current_uidvalidity)
            state.set("fails", fails)
            state.set("last_poll", time.time())
    finally:
        await _close_client_async(client)


async def _process_uid(ctx, client, uid):
    size = await _fetch_message_size(client, uid)
    if size is None or size < 0 or size > _s().MAX_MESSAGE_BYTES:
        await _s()._resource_notice(ctx, "imap", str(uid), _RESOURCE_REASON)
        return

    typ, data = await _imap_call(client.uid, "FETCH", str(uid), "(BODY.PEEK[]<0.262145>)")
    if typ != "OK":
        raise RuntimeError(f"imap FETCH {uid} failed: {typ}")
    raw_bytes = _extract_fetch_payload(data)
    if not raw_bytes or len(raw_bytes) > _s().MAX_MESSAGE_BYTES or len(raw_bytes) != size:
        await _s()._resource_notice(ctx, "imap", str(uid), _RESOURCE_REASON)
        return

    try:
        parsed = _parse_rfc822(raw_bytes)
    except ValueError:
        await _s()._resource_notice(ctx, "imap", str(uid), _RESOURCE_REASON)
        return

    sender = _header(parsed, "From")
    subject = _header(parsed, "Subject")
    recipient = _header(parsed, "To") + " " + _header(parsed, "Delivered-To")
    reply_to = _header(parsed, "Reply-To") or sender

    def _fetch_body():
        return _s()._extract_message_content(parsed)

    await _s()._run_pipeline(
        ctx,
        mid_prefix="imap",
        mid=str(uid),
        sender=sender,
        subject=subject,
        recipient=recipient,
        reply_to=reply_to,
        label_ids=[],  # IMAP has no Gmail category labels
        fetch_body=_fetch_body,
    )


async def _fetch_message_size(client, uid):
    typ, data = await _imap_call(client.uid, "FETCH", str(uid), "(RFC822.SIZE)")
    if typ != "OK":
        return None
    return _extract_fetch_size(data)


def _close_client_sync(client):
    if client is None:
        return
    with suppress(Exception):
        client.logout()
        return
    with suppress(Exception):
        client.shutdown()


async def _close_client_async(client):
    if client is None:
        return
    with suppress(asyncio.CancelledError, Exception):
        await asyncio.shield(asyncio.to_thread(_close_client_sync, client))


def _extract_fetch_size(data):
    if not data:
        return None
    for item in data:
        text = _fetch_item_text(item)
        match = re.search(r"RFC822\.SIZE\s+(\d+)", text, re.I)
        if match:
            return int(match.group(1))
    return None


def _fetch_item_text(item):
    if isinstance(item, tuple):
        parts = []
        for part in item:
            if isinstance(part, (bytes, bytearray)):
                parts.append(bytes(part).decode("utf-8", "ignore"))
            else:
                parts.append(str(part))
        return " ".join(parts)
    if isinstance(item, (bytes, bytearray)):
        return bytes(item).decode("utf-8", "ignore")
    return str(item)


def _uidvalidity(client):
    """Return the folder UIDVALIDITY if the server exposed one, else None."""
    try:
        resp = client.response("UIDVALIDITY")
    except Exception:
        return None
    if not resp:
        return None
    _code, data = resp
    for item in data or []:
        if isinstance(item, (bytes, bytearray)):
            item = item.decode("utf-8", "ignore")
        match = re.search(r"(\d+)", str(item))
        if match:
            return int(match.group(1))
    return None
def _extract_fetch_payload(data):
    """``imaplib`` returns a mixed list for FETCH responses — a tuple of
    ``(envelope, body_bytes)`` when the server sent literals, or a plain
    ``bytes`` entry. Walk it and return the first body bytes we see."""
    if not data:
        return b""
    for item in data:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
            return bytes(item[1])
        if isinstance(item, (bytes, bytearray)) and b"\r\n" in item and b" " not in item[:4]:
            # Rare: a server returned the body directly.
            return bytes(item)
    return b""

