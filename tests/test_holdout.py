"""Independent holdout + mixed-type checks (not the open 68 fixtures)."""

from __future__ import annotations

import json
from pathlib import Path

from app.masking import apply_dev_redact, canonical
from app.pii.detect import detect_pii

ROOT = Path(__file__).resolve().parents[1]
HOLDOUT = ROOT / "docs" / "holdout_cases.json"

DETECT_TO_ACCEPT = {
    "PERSON": "PERSON_NAME",
    "PASSPORT": "PASSPORT_NUMBER",
    "DRIVER_LICENSE": "DRIVER_LICENSE_NUMBER",
    "PIN": "CARD_PIN",
    "INN": "INN_PERSON",
}


def _acc_type(t: str) -> str:
    t = canonical(t)
    return DETECT_TO_ACCEPT.get(t, t)


def _filter(findings, enabled: list[str]):
    want = {canonical(x) for x in enabled} | set(enabled)
    out = []
    for f in findings:
        if canonical(f.type) in want or _acc_type(f.type) in want or f.type in want:
            out.append(f)
    return out


def test_holdout_cases():
    data = json.loads(HOLDOUT.read_text(encoding="utf-8"))
    failures = []
    for case in data["cases"]:
        raw = detect_pii(case["payload"], enable_ner=False)
        got = _filter(raw, case["enabled_types"])
        got_types = {_acc_type(f.type) for f in got}
        if "expect_types" in case:
            exp = set(case["expect_types"])
            if got_types != exp:
                # allow supersets only when expect is non-empty? no — exact type set
                if got_types != exp:
                    failures.append(f"{case['id']}: types {got_types} != {exp}")
        if "expect_min_findings" in case:
            if len(got) < case["expect_min_findings"]:
                failures.append(
                    f"{case['id']}: findings {len(got)} < {case['expect_min_findings']}"
                )
        # round-trip shape via redact
        masked = apply_dev_redact(case["payload"], got)
        if case.get("expect_types") and not any(ch == "*" for ch in masked) and case["expect_types"]:
            failures.append(f"{case['id']}: expected some masking, got {masked!r}")
    assert not failures, "\n".join(failures)


def test_mixed_person_email_ner_off():
    text = "Клиент Иванов Иван, почта ivan@test.ru"
    f = detect_pii(text, enable_ner=False)
    types = {x.type for x in f}
    assert "PERSON" in types and "EMAIL" in types
    masked = apply_dev_redact(text, f)
    assert "Иванов" not in masked and "ivan@" not in masked


def test_client_pushkin_protected_poet_skipped():
    client = "Клиент Александр Пушкин просит перевыпуск карты"
    poet = "Александр Пушкин — русский поэт"
    c = detect_pii(client, enable_ner=False)
    p = detect_pii(poet, enable_ner=False)
    assert any(x.type == "PERSON" and getattr(x, "decision", "mask") == "mask" for x in c)
    assert not any(x.type == "PERSON" and getattr(x, "decision", "mask") == "mask" for x in p)
