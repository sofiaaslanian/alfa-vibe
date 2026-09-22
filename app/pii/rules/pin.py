"""PIN detector — digits with PIN/card context."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import has_any, window

PIN_RE = re.compile(r"(?<!\d)\d{4,6}(?!\d)")
POS = [r"\bpin\b", r"пин[\-\s]?код", r"\bпин\b"]
NEG = [r"код\s+двер", r"код\s+офис", r"\bcvv", r"\bcvc"]


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in PIN_RE.finditer(text):
        ctx = window(text, m.start(), m.end(), size=40)
        if not has_any(ctx, POS):
            continue
        if has_any(ctx, NEG):
            continue
        out.append(
            Finding(
                type="PIN",
                start=m.start(),
                end=m.end(),
                score=0.96,
                detector="pin_rule_v1",
            )
        )
    return out
