"""Shared role helpers for format ID detectors (INN, card)."""

from __future__ import annotations

import re

ROLE_WINDOW = 120


def left(text: str, start: int, window: int = ROLE_WINDOW) -> str:
    return text[max(0, start - window) : start]


def right(text: str, end: int, window: int = ROLE_WINDOW) -> str:
    return text[end : min(len(text), end + window)]


def window(text: str, start: int, end: int, size: int = ROLE_WINDOW) -> str:
    return text[max(0, start - size) : min(len(text), end + size)]


def has_any(fragment: str, patterns: list[str]) -> bool:
    return any(re.search(p, fragment, re.I) for p in patterns)


def nearest_match_end(fragment: str, patterns: list[str]) -> int | None:
    """Rightmost match end offset inside fragment, or None."""
    best: int | None = None
    for p in patterns:
        for m in re.finditer(p, fragment, re.I):
            if best is None or m.end() > best:
                best = m.end()
    return best


def neg_wins(left_frag: str, neg: list[str], pos: list[str]) -> bool:
    """True if nearest negative role is closer (later) than nearest positive."""
    n = nearest_match_end(left_frag, neg)
    if n is None:
        return False
    p = nearest_match_end(left_frag, pos)
    if p is None:
        return True
    return n >= p
