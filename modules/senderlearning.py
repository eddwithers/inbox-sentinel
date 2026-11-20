"""IS-SenderLearning — learned sender rules (first-party, prefilter + gate).

The user's own corrections, persisted by the host feedback tool: exact
addresses or @domain rules that are always noise (dropped locally, zero model
cost) or always important (rescued from the quiet labels and overruling a
NOISE gate verdict). Matching uses the host's canonical exact-address helper
— never display-name substrings; a matching From header is still not
authenticated identity.

Reads the legacy shared state keys written by inbox_sentinel_feedback; the
host grants access only to the keys declared in SHARED_STATE.
"""

NAME = "senderlearning"
BRAND = "IS-SenderLearning"
VERSION = "1.0.0"
STAGES = ("prefilter", "gate")
PRIORITY = 10
DEFAULT_ENABLED = True
SHARED_STATE = ("learned_blocked_senders", "learned_vip_senders")


def prefilter(message, api):
    sender = message.get("sender", "")
    blocked = api.shared_get("learned_blocked_senders", {})
    if any(api.sender_matches(sender, s) for s in blocked):
        return {"drop": True, "reason": "noise (learned rule)"}
    vip = api.shared_get("learned_vip_senders", {})
    if any(api.sender_matches(sender, s) for s in vip):
        return {"flags": {"vip": True}}
    return None


def gate(message, api):
    """Verdict hint: an exact always-important rule overrules NOISE."""
    if message.get("flags", {}).get("vip"):
        return {"force_important": True}
    return None
