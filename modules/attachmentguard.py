"""IS-AttachmentGuard — deterministic attachment-risk signals (pre_gate).

Flags the attachment shapes phishing and malware lures actually use
(industry guidance converges on these): executables and scripts, double
extensions (invoice.pdf.exe), macro-enabled Office documents, HTML
attachments (credential-harvesting pages), and archives the body claims are
password-protected. Pure metadata heuristics — attachment CONTENTS are never
read, and a flag is a warning, not a verdict on the file.

False positives are expected and accepted (a legitimate .js asset or a
password-protected family archive will warn); over-warn rather than
under-warn, and the real summary stays in the alert so the user can judge.
"""

import re

NAME = "attachmentguard"
BRAND = "IS-AttachmentGuard"
VERSION = "1.0.0"
STAGES = ("pre_gate",)
DEFAULT_ENABLED = True

_EXEC_EXT = {
    ".exe", ".scr", ".pif", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs",
    ".vbe", ".ps1", ".psm1", ".msi", ".msp", ".jar", ".lnk", ".hta", ".cpl",
    ".iso", ".img", ".vhd", ".vhdx", ".dll", ".sys", ".reg", ".wsf", ".wsh",
    ".gadget", ".application", ".appref-ms",
}
_MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xltm", ".potm"}
_HTML_EXT = {".html", ".htm", ".shtml", ".xhtml"}
_ARCHIVE_EXT = {".zip", ".rar", ".7z"}
_EXEC_CONTENT_TYPES = {
    "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
    "application/x-executable", "application/javascript", "text/javascript",
    "application/x-sh", "application/x-bat", "application/x-msi",
}
# Linear pattern: a document/media extension followed by an executable one.
_DOUBLE_EXT = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|zip|mp3|mp4)"
    r"\.(?:exe|scr|pif|bat|cmd|com|js|jse|vbs|vbe|ps1|msi|jar|lnk|hta|cpl|iso|img)$",
    re.I,
)


def attachment_signals(attachments, body=""):
    """Ordered, de-duplicated signal names for the attachment metadata."""
    hits = []

    def add(name):
        if name not in hits:
            hits.append(name)

    for att in (attachments or [])[:100]:
        if not isinstance(att, dict):
            continue
        filename = str(att.get("filename", ""))[:255].strip().lower()
        content_type = str(att.get("content_type", "")).lower()
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
        if _DOUBLE_EXT.search(filename):
            add("double-extension attachment")
        elif ext in _EXEC_EXT or content_type in _EXEC_CONTENT_TYPES:
            add("executable attachment")
        if ext in _MACRO_EXT:
            add("macro-enabled document")
        if ext in _HTML_EXT:
            add("HTML attachment")
        if ext in _ARCHIVE_EXT and "password" in str(body).lower():
            add("password-protected archive")
    return hits


def pre_gate(message, api):
    hits = attachment_signals(message.get("attachments"), message.get("body", ""))
    if not hits:
        return None
    return {"force_alert": True, "signals": hits, "brand": BRAND}
