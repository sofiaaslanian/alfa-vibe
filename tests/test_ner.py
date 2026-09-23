from __future__ import annotations

import os

import pytest

from app.pii.detect import Finding
from app.pii.ner import expand_span_to_word, map_entity, merge_adjacent_person


def test_map_name_parts():
    e = map_entity({"entity_group": "FIRST_NAME", "start": 0, "end": 4, "score": 0.9})
    assert e is not None
    assert e.type == "PERSON"


def test_expand_clipped_surname():
    text = "Василий васильевич Пупкие заказл карта"
    # RuBERT often tags only «Пу» — snap to full token «Пупкие»
    s, e = expand_span_to_word(text, 0, 21)
    assert text[s:e] == "Василий васильевич Пупкие"


def test_attach_pushkin_surname():
    from app.pii.detect import Finding
    from app.pii.ner import attach_following_name_tokens

    text = "Александр Пушкин — русский поэт"
    # Model often returns only FIRST_NAME → attach emits separate part spans
    raw = [Finding("PERSON", 0, 9, 0.99, "ml")]
    glued = attach_following_name_tokens(text, raw)
    assert len(glued) == 2
    assert {text[f.start : f.end] for f in glued} == {"Александр", "Пушкин"}
    assert {f.part for f in glued} == {"first", "last"}


def test_map_phone_and_email():
    phone = map_entity({"entity_group": "PHONE", "start": 0, "end": 12, "score": 0.9})
    assert phone is not None
    assert phone.type == "PHONE"
    email = map_entity({"entity_group": "EMAIL", "start": 0, "end": 5, "score": 0.9})
    assert email is not None
    assert email.type == "EMAIL"


def test_map_ignores_geopolitical_country():
    assert map_entity({"entity_group": "COUNTRY", "start": 0, "end": 6, "score": 0.9}) is None

def test_merge_ivan_petrov():
    # Same part only (subword glue). Distinct FIO parts stay separate.
    parts = [
        Finding("PERSON", 11, 15, 0.98, "ml", part="first"),
        Finding("PERSON", 16, 22, 0.99, "ml", part="last"),
    ]
    merged = merge_adjacent_person(parts)
    assert len(merged) == 2
    sub = [
        Finding("PERSON", 11, 13, 0.98, "ml", part="last"),
        Finding("PERSON", 13, 18, 0.99, "ml", part="last"),
    ]
    glued = merge_adjacent_person(sub)
    assert len(glued) == 1
    assert glued[0].start == 11
    assert glued[0].end == 18


@pytest.mark.ner
def test_rubert_fio_live(monkeypatch):
    pytest.importorskip("transformers")
    monkeypatch.setenv("NER_ENABLED", "1")
    monkeypatch.setenv("NER_LOCAL", "1")
    monkeypatch.setenv("NER_FAIL_CLOSED", "0")
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
    joined = text[min(f.start for f in persons) : max(f.end for f in persons)]
    assert "Иван" in joined
    assert "Петров" in joined
    poet = detect_pii("Александр Пушкин — русский поэт", enable_ner=True)
    poet_mask = [f for f in poet if f.type == "PERSON" and getattr(f, "decision", "mask") == "mask"]
    poet_allow = [f for f in poet if f.type == "PERSON" and getattr(f, "decision", "") == "allow"]
    assert not poet_mask
    assert poet_allow  # underlined in UI, not masked
