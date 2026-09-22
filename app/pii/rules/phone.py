"""Phone rule detector (RU-oriented parser)."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import digits_only, has_any, window

# +7 / 8 / 7 with separators
PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+?7|8)"
    r"[\s\-\(\)]*"
    r"\d{3}"
    r"[\s\-\(\)]*"
    r"\d{3}"
    r"[\s\-]*"
    r"\d{2}"
    r"[\s\-]*"
    r"\d{2}"
    r"(?!\d)"
)

NEGATIVE = [
    r"колл[\-\s]?центр",
    r"call[\-\s]?center",
    r"горяч\w*\s+лин",
    r"телефон\s+поддержк",
]


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in PHONE_RE.finditer(text):
        raw = m.group(0)
        digits = digits_only(raw)
        if digits.startswith("8") and len(digits) == 11:
            digits = "7" + digits[1:]
        if not (len(digits) == 11 and digits.startswith("7")):
            continue
        ctx = window(text, m.start(), m.end())
        if has_any(ctx, NEGATIVE):
            continue
        out.append(
            Finding(
                type="PHONE",
                start=m.start(),
                end=m.end(),
                score=0.98,
                detector="phone_rule_v1",
            )
        )
    return out
