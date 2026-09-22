from __future__ import annotations

import os

import pytest

from app.pii.ner.mapper import map_entity, merge_adjacent_person
from app.pii.contract import Finding


def test_map_name_parts():
    e = map_entity({"entity_group": "FIRST_NAME", "start": 0, "end": 4, "score": 0.9})
    assert e is not None and e.type == "PERSON"


def test_map_ignores_email_label():
    assert map_entity({"entity_group": "EMAIL", "start": 0, "end": 5, "score": 0.9}) is None


def test_merge_ivan_petrov():
    parts = [
        Finding("PERSON", 11, 15, 0.98, "ml"),
        Finding("PERSON", 16, 22, 0.99, "ml"),
    ]
    merged = merge_adjacent_person(parts)
    assert len(merged) == 1
    assert merged[0].start == 11 and merged[0].end == 22


@pytest.mark.ner
def test_rubert_fio_live():
    """Requires transformers + model download. Skip if NER deps missing."""
    pytest.importorskip("transformers")
    os.environ["NER_ENABLED"] = "1"
    os.environ["NER_LOCAL"] = "1"
    os.environ["NER_FAIL_CLOSED"] = "0"

    # reset singleton
    import app.pii.pipeline as pipeline

    pipeline._ner = None

    from app.pii.pipeline import detect_pii

    text = "Меня зовут Иван Петров, я живу в Москве."
    findings = detect_pii(text, enable_ner=True)
    persons = [f for f in findings if f.type == "PERSON"]
    assert persons, f"expected PERSON in {findings}"
    span = text[persons[0].start : persons[0].end]
    assert "Иван" in span and "Петров" in span

    # poet trap still not masked as client PII context... eligibility may keep or drop
    poet = detect_pii("Александр Пушкин — русский поэт", enable_ner=True)
    poet_persons = [f for f in poet if f.type == "PERSON"]
    # if model tags it, eligibility should drop due to «поэт»
    assert poet_persons == []
