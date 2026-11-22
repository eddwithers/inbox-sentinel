"""IS-AlertShaper — normal EMAIL ALERT shaping as a post_gate module (M1b).

Builds the exact alert text the host built before modules existed —
byte-identical, pinned by tests against the host fallback. Untrusted fields
go through the host's safe_text helper; the module never sees transport,
credentials or delivery. The POSSIBLE SCAM warning path stays HOST-owned:
security shaping must not depend on a module being enabled or healthy.

Consumes IS-Drafter's in-stage flags (priority order guarantees the draft
is visible before shaping). Disabled/failing → the host's own shaping
applies unchanged.
"""

import time

NAME = "alertshaper"
BRAND = "IS-AlertShaper"
VERSION = "1.0.0"
STAGES = ("post_gate",)
PRIORITY = 20  # after IS-Drafter
DEFAULT_ENABLED = True


def post_gate(message, api):
    flags = message.get("flags") or {}
    draft = flags.get("draft")
    blocker = message.get("draft_blocker")
    lines = ["EMAIL ALERT", "",
             f"Subject: {api.safe_text(message.get('subject', ''), 300)}",
             f"From: {api.safe_text(message.get('sender', ''), 300)}",
             f"Time: {time.strftime('%H:%M')}", "",
             api.safe_text(message.get("summary", "")), ""]
    if blocker:
        lines += [f"No reply drafted — {blocker} Please review the original email."]
    elif draft and "NO REPLY NEEDED" not in draft.upper():
        lines += [f"Suggested reply (to {api.safe_text(message.get('reply_to', ''), 300)}):",
                  "```", api.safe_text(draft, 4000, multiline=True), "```"]
    elif draft:
        lines += ["No reply needed — flagged for your awareness."]
    else:
        lines += ["No reply drafted — draft generation unavailable or disabled; review the email."]
    lines += ["", f"msgid: {message.get('mid_prefix', '')}:{message.get('mid')}"]
    return {"alert_text": "\n".join(lines)}
