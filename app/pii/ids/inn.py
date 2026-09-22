"""INN (person, 12 digits): format-first rules.

Contract (jury: miss > excess mask):
  1) Candidate = exactly 12 digits (not inside a longer digit run).
  2) ФНС checksum must pass → MASK by default.
  3) Label («ИНН», «договор», «заказ») does NOT drop a valid INN —
     a checksum-valid 12-digit string is treated as person INN even under
     a decoy label (org: excess masks are cheaper than misses).
  4) Hard rejects: bad checksum, 10-digit org INN, spaced/fragmented forms
     that are not a contiguous 12-digit token.
"""

from __future__ import annotations

import re

from app.pii import checksums
from app.pii.detect import Finding
from app.pii.ids import has_any, left

INN_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")

INN_POS_HINTS = [
    r"\bинн\b",
    r"мой\s+инн",
    r"инн\s+клиент",
    r"идентификационн\w*\s+номер\s+налогоплательщик",
    r"\binn\b",
    r"taxpayer",
]


def validate_inn12(value: str) -> bool:
    return checksums.inn12(value)


def detect_inn(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in INN_RE.finditer(text):
        value = m.group(1)
        if not validate_inn12(value):
            continue
        score = 0.98
        if has_any(left(text, m.start()), INN_POS_HINTS):
            score = 0.995
        out.append(Finding("INN", m.start(), m.end(), score, "inn_rule_v3"))
    return out
