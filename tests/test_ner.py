from __future__ import annotations

import os

import pytest

from app.pii.detect import Finding
from app.pii.ner import map_entity, merge_adjacent_person


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
    pytest.importorskip("transformers")
    os.environ["NER_ENABLED"] = "1"
    os.environ["NER_LOCAL"] = "1"
    os.environ["NER_FAIL_CLOSED"] = "0"
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    import app.pii.detect as detect_mod

    detect_mod._ner = None
    from app.pii.detect import detect_pii
    from app.pii.ner import PiiNerModel

    try:
        PiiNerModel()
    except Exception as e:
        pytest.skip(f"RuBERT unavailable offline: {e}")

    text = "Меня зовут Иван Петров, я живу в Москве."
    persons = [f for f in detect_pii(text, enable_ner=True) if f.type == "PERSON"]
    assert persons
    span = text[persons[0].start : persons[0].end]
    assert "Иван" in span and "Петров" in span
    poet = detect_pii("Александр Пушкин — русский поэт", enable_ner=True)
    assert not any(f.type == "PERSON" for f in poet)
