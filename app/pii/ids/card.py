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
    r"код\s+операц",
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
    r"серийн\w*\s+номер",
    r"инвентарн\w*\s+номер",
    r"код\s+парт",
    r"номер\s+парт",
    r"код\s+издел",
    r"номер\s+оборуд",
    r"тестов\w*\s+пример",
    r"пример\s+карт",
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


def _blocked_card_context(left_ctx: str, full_ctx: str) -> bool:
    return neg_wins(left_ctx, CARD_NEG_ROLES, CARD_POS_HINTS) or neg_wins(
        full_ctx,
        CARD_NEG_ROLES,
        CARD_POS_HINTS,
    )


def _card_score_and_detector(
    text: str,
    start: int,
    end: int,
    digits: str,
    left_ctx: str,
    full_ctx: str,
) -> tuple[float, str] | None:
    keyword_ok = bool(CARD_KEYWORD_GATE_RE.search(left_ctx))
    if not validate_card_digits(digits):
        if not (keyword_ok and checksums.looks_like_card_pan(digits)):
            return None
        return 0.9, "card_rule_no_luhn_v1"

    score = 0.97
    if has_any(full_ctx, CARD_POS_HINTS) or keyword_ok:
        score = 0.995
    elif re.search(CARD_SEP, text[start:end]):
        score = 0.98
    return score, "card_rule_v2"


def _card_finding(text: str, match) -> Finding | None:
    parsed = _card_digit_span(text, match.start(), match.end())
    if not parsed:
        return None
    start, end, digits = parsed
    left_ctx = left(text, start)
    full_ctx = window(text, start, end)
    if _blocked_card_context(left_ctx, full_ctx):
        return None
    scored = _card_score_and_detector(
        text,
        start,
        end,
        digits,
        left_ctx,
        full_ctx,
    )
    if not scored:
        return None
    score, detector = scored
    return Finding("PAYMENT_CARD", start, end, score, detector)


def detect_card(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[int, int]] = set()
    for match in CARD_RE.finditer(text):
        finding = _card_finding(text, match)
        if not finding:
            continue
        span = (finding.start, finding.end)
        if span in seen:
            continue
        seen.add(span)
        out.append(finding)
    return out
