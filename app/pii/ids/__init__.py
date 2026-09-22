"""Shared helpers for format ID detectors (INN, card)."""

from __future__ import annotations

import re

ROLE_WINDOW = 120


def left(text: str, start: int, window_size: int = ROLE_WINDOW) -> str:
    return text[max(0, start - window_size) : start]


def window(
    text: str,
    start: int,
    end: int,
    window_size: int = ROLE_WINDOW,
) -> str:
    return text[
        max(0, start - window_size) : min(len(text), end + window_size)
    ]


def has_any(fragment: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, fragment, re.IGNORECASE) for pattern in patterns)


def nearest_match_end(fragment: str, patterns: list[str]) -> int:
    """End offset of the rightmost matching role, or -1."""
    best = -1
    for pattern in patterns:
        for match in re.finditer(pattern, fragment, re.IGNORECASE):
            best = max(best, match.end())
    return best


def neg_wins(fragment: str, negative: list[str], positive: list[str]) -> bool:
    """True when a negative role is closer than any positive role."""
    neg_end = nearest_match_end(fragment, negative)
    if neg_end < 0:
        return False
    pos_end = nearest_match_end(fragment, positive)
    return pos_end < 0 or neg_end >= pos_end
