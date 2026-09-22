"""Russian identifier checksums + Luhn.

Adapted from brikkoAI/presidio-ru-recognizers (MIT):
https://github.com/brikkoAI/presidio-ru-recognizers

Algorithms are public regulator procedures (ФНС / ПФР); this module is stdlib-only.
"""

from __future__ import annotations

import re
from typing import Final

_NON_DIGIT_RE: Final = re.compile(r"\D")

_INN10_WEIGHTS: Final = (2, 4, 10, 3, 5, 9, 4, 6, 8)
_INN12_WEIGHTS_11: Final = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
_INN12_WEIGHTS_12: Final = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)


def digits_only(s: str) -> str:
    return _NON_DIGIT_RE.sub("", s)


def inn10(s: str) -> bool:
    d = digits_only(s)
    if len(d) != 10:
        return False
    checksum = sum(int(d[i]) * _INN10_WEIGHTS[i] for i in range(9)) % 11 % 10
    return checksum == int(d[9])


def inn12(s: str) -> bool:
    d = digits_only(s)
    if len(d) != 12:
        return False
    c11 = sum(int(d[i]) * _INN12_WEIGHTS_11[i] for i in range(10)) % 11 % 10
    if c11 != int(d[10]):
        return False
    c12 = sum(int(d[i]) * _INN12_WEIGHTS_12[i] for i in range(11)) % 11 % 10
    return c12 == int(d[11])


def snils(s: str) -> bool:
    """СНИЛС: 9 significant digits + 2-digit checksum (mod 101, early-issue edge)."""
    d = digits_only(s)
    if len(d) != 11:
        return False
    first9 = d[:9]
    given = int(d[9:11])
    if int(first9) <= 1001998:
        return given == 0
    s_sum = sum(int(first9[i]) * (9 - i) for i in range(9))
    if s_sum < 100:
        expected = s_sum
    elif s_sum in (100, 101):
        expected = 0
    else:
        r = s_sum % 101
        expected = 0 if r in (100, 101) else r
    return expected == given


def ogrn(s: str) -> bool:
    d = digits_only(s)
    if len(d) != 13:
        return False
    return (int(d[:12]) % 11) % 10 == int(d[12])


def ogrnip(s: str) -> bool:
    d = digits_only(s)
    if len(d) != 15:
        return False
    return (int(d[:14]) % 13) % 10 == int(d[14])


def luhn(s: str) -> bool:
    d = digits_only(s)
    if not 13 <= len(d) <= 19:
        return False
    digs = [int(c) for c in reversed(d)]
    total = 0
    for i, x in enumerate(digs):
        if i % 2 == 1:
            doubled = x * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += x
    return total % 10 == 0


# Visa / MC / Mir / Amex / Discover / UnionPay brand prefixes (Cloud.ru idea).
_CARD_BRAND_RE: Final = re.compile(
    r"^(?:"
    r"4|"  # Visa
    r"5[1-5]|"  # Mastercard
    r"2(?:2(?:2[1-9]|[3-9]\d)|[3-6]\d{2}|7(?:0\d|20))|"  # Mir / Mastercard 2-series
    r"3[47]|"  # Amex
    r"6011|64[4-9]|65|"  # Discover
    r"62|"  # UnionPay
    r"220[0-4]"  # Mir
    r")"
)


def looks_like_card_pan(s: str) -> bool:
    """Brand + length only — used for keyword-gated no-Luhn fallback."""
    d = digits_only(s)
    return 13 <= len(d) <= 19 and bool(_CARD_BRAND_RE.match(d))
