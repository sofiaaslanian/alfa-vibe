"""Driver license series/number detector."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import has_any, window

VU_RE = re.compile(r"(?<!\d)(\d{2}\s?\d{2})[\s\-]*(\d{6})(?!\d)")
POS = [r"водительск", r"\bву\b", r"удостоверен", r"права"]
NEG = [r"заявк", r"номер\s+заказ"]


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in VU_RE.finditer(text):
        ctx = window(text, m.start(), m.end())
        if not has_any(ctx, POS):
            continue
        if has_any(ctx, NEG):
            continue
        out.append(
            Finding(
                type="DRIVER_LICENSE",
                start=m.start(),
                end=m.end(),
                score=0.95,
                detector="driver_license_rule_v1",
            )
        )
    return out
