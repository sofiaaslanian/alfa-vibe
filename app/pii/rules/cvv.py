"""CVV detector — short digits only with CVV/CVC anchor."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import has_any, window

CVV_RE = re.compile(r"(?<!\d)\d{3,4}(?!\d)")
POS = [r"\bcvv2?\b", r"\bcvc2?\b"]
NEG = [r"код\s+офис", r"пин", r"\bpin\b"]


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CVV_RE.finditer(text):
        ctx = window(text, m.start(), m.end(), size=30)
        if not has_any(ctx, POS):
            continue
        if has_any(ctx, NEG):
            continue
        out.append(
            Finding(
                type="CVV",
                start=m.start(),
                end=m.end(),
                score=0.97,
                detector="cvv_rule_v1",
            )
        )
    return out
