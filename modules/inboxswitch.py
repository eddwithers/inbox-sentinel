"""IS-InboxSwitch — multi-account switching policy (M2).

The host owns the N provider connections: transport, grants, cursors and
budgets are host-only by design, and account selection at intake is host
core — a disabled account is never polled (no header/body reads). This
module owns the switching policy the stages can express: a defence-in-
depth drop for mail from a disabled account, and the alert tag that names
the account in multi-account alerts. The host consumes the tag with a
behaviour-identical fallback when this module is disabled or fails.

Per-account importance profiles are resolved host-side into the gate
instructions; learned sender rules stay profile-global (documented).
"""

NAME = "inboxswitch"
BRAND = "IS-InboxSwitch"
VERSION = "1.0.0"
STAGES = ("prefilter", "post_gate")
PRIORITY = 5  # before the noise filter: account policy first
DEFAULT_ENABLED = True


def prefilter(message, api):
    if message.get("account_id") and message.get("account_enabled") is False:
        return {"drop": True, "reason": "account disabled"}
    return None


def post_gate(message, api):
    if not message.get("account_id"):
        return None
    label = message.get("account_label") or message.get("account_id")
    return {"account_tag": api.safe_text(label, 60)}
