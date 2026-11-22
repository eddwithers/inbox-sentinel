"""IS-StormShield — identical-repeat alert suppression (pre_gate).

Protects the alert channel itself: when the same sender blasts the same
message (same subject AND same body hash) repeatedly within a window, the
first arrivals still alert and only the repeats beyond the threshold are
suppressed. This is the interruption-management lesson of the Starling
storm — a notification channel that can be flooded is a channel the user
learns to ignore.

Safety invariants (host-enforced ordering plus module design):
- The first occurrence ALWAYS passes; suppression needs >= threshold
  identical arrivals inside the window (default: 3rd identical in 30 min).
- Different bodies never suppress each other — two genuine incidents with
  the same subject line both alert.
- Security warnings outrank suppression: the host honours force_alert
  outcomes before any drop, so a scam-shaped storm still warns.
- State is namespaced, bounded (200 keys, oldest evicted), and a garbage
  config degrades to host-default (no suppression) rather than misfiring.
"""

import hashlib
import time
from email.utils import getaddresses

NAME = "stormshield"
BRAND = "IS-StormShield"
VERSION = "1.0.0"
STAGES = ("pre_gate",)
PRIORITY = 110  # after the security modules; the host honours force_alert first anyway
DEFAULT_ENABLED = True

STATE_CAP = 200


def _clamp_int(value, default, lo, hi):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _storm_key(message):
    sender = str(message.get("sender", ""))
    try:
        address = getaddresses([sender])[0][1].lower()
    except (ValueError, IndexError):
        address = sender.lower()
    subject = " ".join(str(message.get("subject", "")).lower().split())[:300]
    body = str(message.get("body", ""))[:4000].encode("utf-8", "replace")
    key = f"{address}|{subject}|{hashlib.sha256(body).hexdigest()[:16]}"
    # Account-scoped (M2): identical mail to two accounts never suppresses
    # each other. Legacy single-account keys are unchanged.
    account_id = message.get("account_id")
    return f"{account_id}|{key}" if account_id else key


def pre_gate(message, api):
    window = _clamp_int(api.config_get("storm_window_minutes", 30), 30, 1, 1440) * 60
    threshold = _clamp_int(api.config_get("storm_threshold", 3), 3, 2, 100)
    now = time.time()
    storms = api.state_get("storms", {})
    if not isinstance(storms, dict):
        storms = {}
    key = _storm_key(message)
    mid = message.get("mid")
    entry = storms.get(key)
    if not (isinstance(entry, dict) and now - entry.get("first", 0) <= window):
        entry = {"count": 0, "first": now, "mids": []}
    entry["last"] = now
    mids = entry.get("mids")
    if mid is not None and isinstance(mids, list):
        # Count distinct arrivals only: a transport retry of the same mid is
        # not a new storm arrival.
        if mid not in mids:
            mids.append(mid)
            if len(mids) > 100:
                del mids[0]
            entry["count"] = int(entry.get("count", 0)) + 1
    else:
        entry["count"] = int(entry.get("count", 0)) + 1
    storms[key] = entry
    if len(storms) > STATE_CAP:
        oldest = sorted(storms, key=lambda k: storms[k].get("last", 0))
        for k in oldest[:len(storms) - STATE_CAP]:
            del storms[k]
    api.state_set("storms", storms)
    if entry["count"] >= threshold:
        return {"drop": True,
                "reason": f"storm suppressed ({entry['count']} identical messages in window)"}
    return None
