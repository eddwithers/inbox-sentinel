"""IS-NoiseFilter — local noise filtering (first-party, prefilter).

Zero-model-cost drops before any body fetch or gate call: recipient aliases
the user no longer watches, and Gmail quiet labels (promotions/social) unless
a keyword override or an exact always-important sender rule (vip flag from
IS-SenderLearning) rescues the mail. Config keys are the established host
keys, read through the bounded API so existing user configuration keeps
working unchanged.
"""

NAME = "noisefilter"
BRAND = "IS-NoiseFilter"
VERSION = "1.0.0"
STAGES = ("prefilter",)
PRIORITY = 20
DEFAULT_ENABLED = True


def prefilter(message, api):
    recipient = message.get("recipient", "")
    skip_words = [w.lower() for w in api.config_get("skip_recipient_keywords", [])]
    if any(w in recipient.lower() for w in skip_words):
        return {"drop": True, "reason": "skipped recipient alias"}
    if message.get("flags", {}).get("vip"):
        return None
    quiet_labels = set(api.config_get("quiet_labels",
                                      ["CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL"]))
    keywords = [k.lower() for k in api.config_get("keyword_overrides", [])]
    if quiet_labels & set(message.get("label_ids") or []):
        low = (message.get("subject") or "").lower()
        if not any(k in low for k in keywords):
            return {"drop": True, "reason": "noise (local filter)"}
    return None
