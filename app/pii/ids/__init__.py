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
