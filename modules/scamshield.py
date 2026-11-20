"""IS-ScamShield — deterministic scam-signal module (first-party, pre_gate).

Ported from the production push watcher after a fake order-confirmation lure
(password-protected PDF) passed as a clean alert. Zero model cost; runs before
the importance gate. A hit re-labels the alert, never suppresses the mail:
over-warn rather than under-warn, and keep the real summary so the user can
judge. Auth results are NOT scam evidence — the original lure passed
SPF/DKIM/DMARC because it came from the real company's own compromised
mailbox, so nothing here consults them.

Detection stays pure (no ctx, no alert shaping). The host owns alert shaping,
budgets, delivery and the read-only contract; this module only reports signals
and requests a forced alert, which the host grants via the pre_gate outcome.
"""

NAME = "scamshield"
BRAND = "IS-ScamShield"
VERSION = "1.0.0"
STAGES = ("pre_gate",)
DEFAULT_ENABLED = True

SCAM_SIGNALS = [
    ("password-protected attachment", "password protected", "pdf"),
    ("undisclosed recipients", "undisclosed-recipients", None),
]


def scam_signal_hits(subject, body, recipient):
    """Return human-readable scam-signal names for this mail (pure check)."""
    text = f"{subject}\n{body}\n{recipient}".lower()
    hits = []
    for name, first, second in SCAM_SIGNALS:
        if first in text and (second is None or second in text):
            hits.append(name)
    return hits


def pre_gate(message, api):
    """Stage handler: report signals and request a forced warning alert."""
    hits = scam_signal_hits(message.get("subject", ""), message.get("body", ""),
                            message.get("recipient", ""))
    if not hits:
        return None
    return {"force_alert": True, "signals": hits, "brand": BRAND}
