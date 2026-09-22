"""Post-filters for format PII (especially raw NER spans).

Rules already enforce checksum / service roles. RuBERT often emits
fragments or support contacts — drop those before discourse/resolve.
"""

from __future__ import annotations

import re

from app.pii.detect import Finding
from app.pii.ids.card import validate_card_digits
from app.pii.ids.inn import validate_inn12

_EMAIL_OK_RE = re.compile(
    r"(?i)^[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$"
)
_SERVICE_EMAIL_LOCALS = {
    "support",
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
    "info",
    "help",
    "admin",
    "abuse",
    "postmaster",
    "mailer-daemon",
    "robot",
    "bot",
    "notifications",
    "notify",
}
_SERVICE_EMAIL_DOMAINS = {
    "bank.ru",
    "support.bank.ru",
    "example.invalid",
}
_SUPPORT_CUE_RE = re.compile(
    r"(?i)(?:почта\s+поддержк|поддержк\w*|колл[\-\s]?центр|noreply|no[\-\s]?reply)"
)
_PERSONAL_EMAIL_CUE_RE = re.compile(
    r"(?i)(?:почта\s+клиент|email\s+клиент|e-?mail\s+клиент|моя\s+почта|мой\s+email)"
)


def _digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def accept_format_finding(text: str, f: Finding) -> bool:
    """False → drop finding (invalid / service / not personal format evidence)."""
    value = text[f.start : f.end]
    left = text[max(0, f.start - 80) : f.start]

    if f.type == "EMAIL":
        if "@@" in value or ".." in value or not _EMAIL_OK_RE.match(value.strip()):
            return False
        local, _, domain = value.partition("@")
        local_l, domain_l = local.lower(), domain.lower()
        personal = bool(_PERSONAL_EMAIL_CUE_RE.search(left))
        if (
            local_l in _SERVICE_EMAIL_LOCALS or domain_l in _SERVICE_EMAIL_DOMAINS
        ) and not personal:
            return False
        if _SUPPORT_CUE_RE.search(left) and not personal:
            return False
        return True

    if f.type == "INN":
        return validate_inn12(value)

    if f.type == "PAYMENT_CARD":
        d = _digits(value)
        if not (13 <= len(d) <= 19):
            return False
        # Strict Luhn for ML / residual spans — no keyword bypass here.
        return validate_card_digits(d)

    if f.type == "PHONE":
        d = _digits(value)
        if value.strip().startswith("+"):
            return 10 <= len(d) <= 15
        return len(d) in {10, 11}

    if f.type == "CVV":
        d = _digits(value)
        return len(d) in {3, 4} and d == value.strip()

    if f.type == "PIN":
        d = _digits(value)
        return 4 <= len(d) <= 6 and d == value.strip()

    return True


def sanitize_format_findings(text: str, findings: list[Finding]) -> list[Finding]:
    """Drop invalid/service spans from ML; leave rule detectors as-is."""
    out: list[Finding] = []
    for f in findings:
        det = (f.detector or "").lower()
        is_ml = (
            det == "ml"
            or det.startswith("ml")
            or "ner" in det
            or "rubert" in det
        )
        if not is_ml or accept_format_finding(text, f):
            out.append(f)
    return out
