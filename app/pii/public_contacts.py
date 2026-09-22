"""Public / service contacts that must NOT be treated as personal PII.

These are not «celebrity lists» — they are bank-owned published contacts
(hotline, support) that appear in open sources and customer chats.
"""

from __future__ import annotations

import re

from app.pii.rules import _digits_only

# Alfa Bank published support / office lines (normalized to digits, RU 11-digit).
# Source: publicly listed hotlines — extend as needed.
ALFA_PUBLIC_PHONES_RAW: tuple[str, ...] = (
    "88002000000",
    "8 800 200-00-00",
    "8 800 200 00 00",
    "+7 800 200-00-00",
    "78002000000",
    "84957888878",
    "+7 495 788-88-78",
    "8 495 788-88-78",
    "74957888878",
    "88001002000",  # common secondary lines — verify in prod
    "88001007733",
)

SERVICE_PHONE_LOCAL_CUES = (
    r"поддержк",
    r"колл[\-\s]?центр",
    r"call[\-\s]?center",
    r"горяч\w*\s+лин",
    r"телефон\s+банк",
    r"телефон\s+офис",
    r"телефон\s+отделен",
    r"контакт[\-\s]?центр",
    r"справочн\w*\s+служб",
    r"служб\w*\s+поддержк",
    r"альфа[\-\s]?банк\w*\s+(?:поддерж|телефон|лин)",
    r"\balfa[\-\s]?bank\b",
)


def _norm_phone(value: str) -> str:
    digits = _digits_only(value)
    if digits.startswith("8") and len(digits) == 11:
        digits = "7" + digits[1:]
    return digits


PUBLIC_PHONE_DIGITS: set[str] = {_norm_phone(p) for p in ALFA_PUBLIC_PHONES_RAW if _norm_phone(p)}

SERVICE_PHONE_CUE_RE = re.compile(
    "(?i)(?:" + "|".join(SERVICE_PHONE_LOCAL_CUES) + ")"
)


def is_public_service_phone(value: str) -> bool:
    return _norm_phone(value) in PUBLIC_PHONE_DIGITS


def has_service_phone_context(text: str, start: int, end: int, window: int = 100) -> bool:
    ctx = text[max(0, start - window) : min(len(text), end + window)]
    return bool(SERVICE_PHONE_CUE_RE.search(ctx))
