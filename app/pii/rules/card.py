"""Payment card detector with Luhn checksum."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import digits_only

CARD_RE = re.compile(
    r"(?<!\d)"
    r"(?:\d[ \-]*?){13,19}"
    r"(?!\d)"
)


def _luhn_ok(number: str) -> bool:
    if not number.isdigit() or not 13 <= len(number) <= 19:
        return False
    total = 0
    reverse = number[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CARD_RE.finditer(text):
        digits = digits_only(m.group(0))
        if not _luhn_ok(digits):
            continue
        # Avoid matching plain INN/phone-like if already validated elsewhere —
        # cards are typically 16 digits; accept 13-19 with Luhn.
        out.append(
            Finding(
                type="PAYMENT_CARD",
                start=m.start(),
                end=m.end(),
                score=0.99,
                detector="card_rule_v1",
            )
        )
    return out
