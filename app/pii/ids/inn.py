"""INN detector matching the pre-group-1 baseline behavior."""

from __future__ import annotations

import re

from app.pii import checksums
from app.pii.detect import Finding
from app.pii.ids import has_any, left, neg_wins

INN_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")

INN_POS_HINTS = [
    r"\bинн\b",
    r"мой\s+инн",
    r"инн\s+клиента",
    r"идентификационн\w*\s+номер\s+налогоплательщик",
    r"inn\b",
    r"taxpayer",
]

INN_NEG_ROLES = [
    r"id\s+операц",
    r"идентификатор\s+операц",
    r"номер\s+договор",
    r"номер\s+заказ",
    r"заказ[ае]?\s*№",
    r"номер\s+заявк",
    r"номер\s+сч[её]т",
    r"серийн\w*\s+код",
    r"серийн\w*\s+номер",
    r"артикул",
    r"штрих[\-\s]?код",
    r"barcode",
    r"tracking",
    r"трек[\-\s]?номер",
    r"номер\s+посылк",
]


def validate_inn12(value: str) -> bool:
    return checksums.inn12(value)


def detect_inn(text: str) -> list[Finding]:
    out: list[Finding] = []
    for match in INN_RE.finditer(text):
        value = match.group(1)
        if not validate_inn12(value):
            continue
        left_ctx = left(text, match.start())
        if neg_wins(left_ctx, INN_NEG_ROLES, INN_POS_HINTS):
            continue
        score = 0.97
        if has_any(left_ctx, INN_POS_HINTS):
            score = 0.995
        out.append(
            Finding("INN", match.start(), match.end(), score, "inn_rule_v2")
        )
    return out
