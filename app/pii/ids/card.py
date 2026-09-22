"""PAYMENT_CARD: format-first Luhn rules.

Contract (jury: miss > excess mask):
  1) Candidate = 13–19 digit run (spaces/dashes/NBSP allowed between groups).
  2) Luhn OK → MASK by default (even under «заказ» / «операция» labels).
  3) Luhn FAIL → mask only if an explicit card keyword sits immediately
     before the PAN (typo / synthetic PAN fallback).
  4) Never emit a span that is a strict substring of a longer digit run
     (handled by extract boundaries).
"""

from __future__ import annotations

import re

from app.pii import checksums
from app.pii.detect import Finding
from app.pii.ids import has_any, left, window

CARD_SEP = r"[ \-\u00a0\u202f]"
CARD_RE = re.compile(rf"(?<!\d)(?:\d{CARD_SEP}*){{12,18}}\d(?!\d)")

CARD_POS_HINTS = [
    r"карт",
    r"card",
    r"\bпан\b",
    r"\bpan\b",
    r"visa",
    r"mastercard",
    r"master[\-\s]?card",
    r"мир\b",
    r"\bamex\b",
    r"american\s+express",
]

# Keyword immediately before PAN (Cloud.ru credit-card.context idea).
CARD_KEYWORD_GATE_RE = re.compile(
    r"(?i)(?:карт[аеуы]|карточк[аеиуой]|card|visa|mastercard|maestro|маэстро)"
    r"[\s:.,;№#()\-/]{1,4}$"
)


def _card_digit_span(text: str, m_start: int, m_end: int) -> tuple[int, int, str] | None:
    raw = text[m_start:m_end]
    digit_offsets: list[int] = []
    for i, ch in enumerate(raw):
        if ch.isdigit():
            digit_offsets.append(m_start + i)
    if not digit_offsets:
        return None
    digits = "".join(text[i] for i in digit_offsets)
    return digit_offsets[0], digit_offsets[-1] + 1, digits


def validate_card_digits(digits: str) -> bool:
    return checksums.luhn(digits)


def detect_card(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[int, int]] = set()
    for m in CARD_RE.finditer(text):
        parsed = _card_digit_span(text, m.start(), m.end())
        if not parsed:
            continue
        start, end, digits = parsed
        span = (start, end)
        if span in seen:
            continue
        left_frag = left(text, start)
        ctx = window(text, start, end)
        luhn_ok = validate_card_digits(digits)
        keyword_ok = bool(CARD_KEYWORD_GATE_RE.search(left_frag))
        if not luhn_ok:
            if not (keyword_ok and checksums.looks_like_card_pan(digits)):
                continue
            score = 0.9
            det = "card_rule_no_luhn_v1"
        else:
            score = 0.97
            if has_any(ctx, CARD_POS_HINTS) or keyword_ok:
                score = 0.995
            elif re.search(CARD_SEP, text[start:end]):
                score = 0.98
            det = "card_rule_v3"
        seen.add(span)
        out.append(Finding("PAYMENT_CARD", start, end, score, det))
    return out
