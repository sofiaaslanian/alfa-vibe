"""Shared helpers for rule detectors."""

from __future__ import annotations

import re


def window(text: str, start: int, end: int, size: int = 60) -> str:
    return text[max(0, start - size) : min(len(text), end + size)]


def has_any(ctx: str, patterns: list[str]) -> bool:
    return any(re.search(p, ctx, re.IGNORECASE) for p in patterns)


def digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)
