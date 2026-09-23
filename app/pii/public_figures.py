"""Deprecated celebrity lexicon — discourse gate replaced it.

Kept as a thin shim so old imports do not break. Do not add names here.
"""

from __future__ import annotations

from app.pii.discourse import should_skip_person as should_skip_person_as_public


def is_public_figure_name(value: str) -> bool:
    """Removed. Always False — fame is not a decision signal."""
    _ = value
    return False
