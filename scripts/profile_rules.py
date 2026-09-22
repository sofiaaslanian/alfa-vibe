#!/usr/bin/env python3
"""Profile individual rule detectors on the hackathon load payloads."""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.pii.rules import RULE_DETECTORS
from scripts.load_smoke import build_payload


def profile(profile: str) -> None:
    text, approx_tokens = build_payload(profile)
    print(f"profile={profile} chars={len(text)} approx_tokens={approx_tokens}")
    total = 0.0
    for detector in RULE_DETECTORS:
        t0 = time.perf_counter()
        findings = detector(text)
        elapsed = (time.perf_counter() - t0) * 1000
        total += elapsed
        print(
            f"{detector.__name__}: {elapsed:.3f}ms findings={len(findings)}"
        )
    print(f"sum_detector_ms={total:.3f}")


def main() -> None:
    profile("default")
    profile("100k")


if __name__ == "__main__":
    main()
