"""Единый detector contract."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    type: str
    start: int
    end: int
    score: float
    detector: str

    @property
    def value_span(self) -> tuple[int, int]:
        return self.start, self.end

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "score": self.score,
            "detector": self.detector,
        }
