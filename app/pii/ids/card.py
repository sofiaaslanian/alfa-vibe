"""Payment-card detector matching the pre-group-1 baseline behavior."""

from __future__ import annotations

import re

from app.pii import checksums
from app.pii.detect import Finding
from app.pii.ids import has_any, left, neg_wins, window

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

CARD_NEG_ROLES = [
    r"идентификатор\s+операц",
    r"id\s+операц",
    r"номер\s+заказ",
    r"номер\s+договор",
    r"номер\s+заявк",
    r"номер\s+сч[её]т",
    r"артикул",
    r"штрих[\-\s]?код",
    r"tracking",
    r"трек[\-\s]?номер",
    r"imei",
    r"номер\s+посылк",
]

CARD_KEYWORD_GATE_RE = re.compile(
    r"(?i)(?:карт[аеуы]|карточк[аеиуой]|card|visa|mastercard|maestro|маэстро)"
    r"[\s:.,;№#()\-/]{1,4}$"
)


def _card_digit_span(
    text: str,
    match_start: int,
    match_end: int,
) -> tuple[int, int, str] | None:
    raw = text[match_start:match_end]
    digit_offsets = [
        match_start + offset
        for offset, char in enumerate(raw)
        if char.isdigit()
    ]
    if not digit_offsets:
        return None
    digits = "".join(text[offset] for offset in digit_offsets)
    return digit_offsets[0], digit_offsets[-1] + 1, digits


def validate_card_digits(digits: str) -> bool:
    return checksums.luhn(digits)


def detect_card(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[int, int]] = set()
    for match in CARD_RE.finditer(text):
        parsed = _card_digit_span(text, match.start(), match.end())
        if not parsed:
            continue
        start, end, digits = parsed
        span = (start, end)
        if span in seen:
            continue

        left_ctx = left(text, start)
        full_ctx = window(text, start, end)
        if neg_wins(left_ctx, CARD_NEG_ROLES, CARD_POS_HINTS) or neg_wins(
            full_ctx,
            CARD_NEG_ROLES,
            CARD_POS_HINTS,
        ):
            continue

        luhn_ok = validate_card_digits(digits)
        keyword_ok = bool(CARD_KEYWORD_GATE_RE.search(left_ctx))
        if not luhn_ok:
            if not (keyword_ok and checksums.looks_like_card_pan(digits)):
                continue
            score = 0.9
            detector = "card_rule_no_luhn_v1"
        else:
            score = 0.97
            if has_any(full_ctx, CARD_POS_HINTS) or keyword_ok:
                score = 0.995
            elif re.search(CARD_SEP, text[start:end]):
                score = 0.98
            detector = "card_rule_v2"

        seen.add(span)
        out.append(Finding("PAYMENT_CARD", start, end, score, detector))
    return out
