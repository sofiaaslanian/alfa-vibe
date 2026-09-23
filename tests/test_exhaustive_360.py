"""360-case exhaustive PII masking contract.

Purpose:
- expose false negatives that small acceptance sets miss;
- test all 17 required PII types with positive + hard-negative contexts;
- verify exact mask boundaries, not only the detected type;
- add mixed payloads with real PII next to service/public decoys.

The contract is intentionally recall-first: per organizer Q&A, extra masking is
penalized less than missed PII. Expected answers are test data, not something
production code may rewrite to get green.

This file uses the current AlfaSonar-like rules path (NER disabled).
"""

from __future__ import annotations

from collections import Counter

import pytest

from app.masking import apply_dev_redact
from app.pii.detect import Finding, detect_pii
from tests.conftest import findings_cover_span, overlaps, span_text
from tests.exhaustive_cases_1 import CASES as CASES_1
from tests.exhaustive_cases_2 import CASES as CASES_2
from tests.exhaustive_cases_3 import CASES as CASES_3
from tests.exhaustive_cases_4 import CASES as CASES_4
from tests.exhaustive_cases_mixed import CASES as MIXED_CASES

CASES = CASES_1 + CASES_2 + CASES_3 + CASES_4 + MIXED_CASES

INTERNAL_TO_CASE = {
    "PERSON": "PERSON_NAME",
    "PASSPORT": "PASSPORT_NUMBER",
    "DRIVER_LICENSE": "DRIVER_LICENSE_NUMBER",
    "SUBDIVISION_CODE": "PASSPORT_DIVISION_CODE",
    "PIN": "CARD_PIN",
}
CASE_TO_INTERNAL = {v: k for k, v in INTERNAL_TO_CASE.items()}

REQUIRED_TYPES = {
    "PERSON_NAME",
    "PLACE_OF_BIRTH",
    "CITIZENSHIP",
    "PASSPORT_ISSUER",
    "ADDRESS",
    "CARDHOLDER_NAME",
    "BIRTH_DATE",
    "PASSPORT_NUMBER",
    "PASSPORT_DIVISION_CODE",
    "PASSPORT_ISSUE_DATE",
    "DRIVER_LICENSE_NUMBER",
    "CVV",
    "CARD_PIN",
    "EMAIL",
    "PHONE",
    "INN",
    "PAYMENT_CARD",
}


def _case_type(internal: str) -> str:
    return INTERNAL_TO_CASE.get(internal, internal)


def _internal_type(case_type: str) -> str:
    return CASE_TO_INTERNAL.get(case_type, case_type)


def _detect(text: str, enabled_types: list[str]) -> tuple[list[Finding], list[dict]]:
    wanted = {_internal_type(t) for t in enabled_types}
    raw = [
        f
        for f in detect_pii(text, enable_ner=False)
        if getattr(f, "decision", "mask") == "mask" and f.type in wanted
    ]
    public = []
    for finding in raw:
        item = finding.to_dict()
        item["type"] = _case_type(finding.type)
        public.append(item)
    return raw, public


def _nth_index(text: str, value: str, occurrence: int = 1) -> int:
    start = 0
    idx = -1
    for _ in range(occurrence):
        idx = text.find(value, start)
        assert idx >= 0, (
            f"Cannot find occurrence #{occurrence} of {value!r} in {text!r}"
        )
        start = idx + len(value)
    return idx


def _assert_expected(text: str, findings: list[dict], expected: dict) -> None:
    value = expected["value"]
    occurrence = expected.get("occurrence", 1)
    start = _nth_index(text, value, occurrence)
    end = start + len(value)
    candidates = [f for f in findings if f["type"] == expected["type"]]
    assert candidates, (
        f"FN: expected {expected['type']}={value!r}; got "
        f"{[(f['type'], span_text(text, f), f.get('detector')) for f in findings]}"
    )
    assert findings_cover_span(text, candidates, start, end), (
        f"Boundary error for {expected['type']}={value!r}; got "
        f"{[(f['start'], f['end'], span_text(text, f)) for f in candidates]}"
    )


def _assert_masked(text: str, masked: str, expected: dict) -> None:
    value = expected["value"]
    start = _nth_index(text, value, expected.get("occurrence", 1))
    end = start + len(value)
    alnum = [i for i in range(start, end) if text[i].isalnum()]
    assert alnum, f"Expected value has no alphanumeric characters: {value!r}"
    unmasked = [i for i in alnum if masked[i] != "*"]
    assert not unmasked, (
        f"Mask leak for {expected['type']}={value!r}: "
        f"{masked[start:end]!r}; open chars="
        f"{''.join(text[i] for i in unmasked)!r}"
    )


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_exhaustive_360_detection_and_masking(case):
    raw, findings = _detect(case["text"], case["enabled_types"])

    for finding in findings:
        assert 0 <= finding["start"] < finding["end"] <= len(case["text"])
        assert 0.0 <= finding["score"] <= 1.0

    for expected in case["expected"]:
        _assert_expected(case["text"], findings, expected)

    for forbidden_type in case.get("forbidden_types", []):
        bad = [f for f in findings if f["type"] == forbidden_type]
        assert not bad, (
            f"{case['id']}: FP {forbidden_type}: "
            f"{[(f['type'], span_text(case['text'], f), f.get('detector')) for f in bad]}"
        )

    for forbidden_value in case.get("must_not_cover_values", []):
        start = case["text"].index(forbidden_value)
        end = start + len(forbidden_value)
        bad = [f for f in findings if overlaps(f["start"], f["end"], start, end)]
        assert not bad, (
            f"{case['id']}: masks public/service decoy {forbidden_value!r}: "
            f"{[(f['type'], span_text(case['text'], f)) for f in bad]}"
        )

    masked = apply_dev_redact(case["text"], raw)
    for expected in case["expected"]:
        _assert_masked(case["text"], masked, expected)

    for forbidden_value in case.get("must_not_cover_values", []):
        start = case["text"].index(forbidden_value)
        end = start + len(forbidden_value)
        assert masked[start:end] == case["text"][start:end], (
            f"{case['id']}: forbidden value changed by mask: "
            f"{case['text'][start:end]!r} -> {masked[start:end]!r}"
        )


def test_exhaustive_contract_shape():
    assert len(CASES) == 360
    assert len({c["id"] for c in CASES}) == 360

    singles = [c for c in CASES if len(c["enabled_types"]) == 1 and c not in MIXED_CASES]
    counts = Counter(c["enabled_types"][0] for c in singles)
    assert set(counts) == REQUIRED_TYPES
    assert counts == Counter({typ: 20 for typ in REQUIRED_TYPES})

    for case in CASES:
        assert set(case["enabled_types"]) <= REQUIRED_TYPES
        for expected in case["expected"]:
            assert expected["type"] in case["enabled_types"]
            assert expected["value"] in case["text"]


def test_recall_first_person_contract_is_explicit():
    """The key regression: an ordinary bare two-part FIO must not leak."""
    case = next(c for c in CASES if c["id"] == "person_bare_first_last")
    _, findings = _detect(case["text"], case["enabled_types"])
    _assert_expected(case["text"], findings, case["expected"][0])
