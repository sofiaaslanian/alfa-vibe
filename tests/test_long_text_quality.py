from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.masking import apply_dev_redact
from app.pii.detect import detect_pii


CASES = json.loads(
    Path("docs/acceptance_cases.json").read_text(encoding="utf-8")
)["cases"]

POSITIVE_CASES = [
    c for c in CASES
    if c.get("expected_findings")
    and c.get("kind") in {"positive", "variant_positive"}
]


@pytest.mark.parametrize("case", POSITIVE_CASES, ids=lambda c: c["id"])
def test_positive_acceptance_survives_long_text_fast_path(case):
    """Long-text performance gates must not suppress known positive PII."""
    prefix = ("Служебный нейтральный контекст без персональных данных. " * 400)
    payload = prefix + "\n" + case["payload"]

    findings = detect_pii(payload, enable_ner=False)
    masked = apply_dev_redact(payload, findings)

    # Validate the exact values the acceptance fixture expects to protect.
    for expected in case["expected_findings"]:
        value = expected["value"]
        assert value not in masked[len(prefix):], (
            case["id"],
            expected["type"],
            value,
        )
