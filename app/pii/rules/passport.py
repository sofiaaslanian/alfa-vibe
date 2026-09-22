"""Passport series/number detector."""

from __future__ import annotations

import re

from app.pii.contract import Finding
from app.pii.rules._common import has_any, window

# 4 digits series + 6 digits number; allow «серия/номер» words between
PASSPORT_RE = re.compile(
    r"(?<!\d)(\d{2}\s?\d{2})"
    r"(?:\s*(?:серия|номер)?\s*)?"
    r"[\s\-]*"
    r"(?:номер\s+)?"
    r"(\d{6})(?!\d)",
    re.IGNORECASE,
)

POS = [r"паспорт", r"серия", r"номер\s+паспорт"]
NEG = [r"номер\s+заказ", r"заявк", r"номер\s+договор"]


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in PASSPORT_RE.finditer(text):
        ctx = window(text, m.start(), m.end())
        if not has_any(ctx, POS):
            continue
        if has_any(ctx, NEG):
            continue
        out.append(
            Finding(
                type="PASSPORT",
                start=m.start(),
                end=m.end(),
                score=0.96,
                detector="passport_rule_v1",
            )
        )
    return out
