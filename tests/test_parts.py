"""Composite PII parts: FIO / passport / address / cardholder."""

from app.pii import rules
from app.pii.detect import detect_pii
from app.pii.parts import classify_fio_parts, split_address_span, split_person_span
from app.pii.structural import normalize_structures


def test_classify_fio_official_order():
    assert classify_fio_parts(["Иванов", "Иван", "Иванович"]) == [
        "last",
        "first",
        "middle",
    ]


def test_classify_fio_spoken_order():
    assert classify_fio_parts(["Иван", "Иванович", "Петров"]) == [
        "first",
        "middle",
        "last",
    ]


def test_person_label_splits_parts():
    text = "ФИО клиента: Иванов Иван Иванович"
    f = normalize_structures(text, rules.detect_person_labelled(text))
    parts = {x.part: text[x.start : x.end] for x in f}
    assert parts == {"last": "Иванов", "first": "Иван", "middle": "Иванович"}


def test_passport_series_number_parts():
    text = "Паспорт клиента: серия 4510, номер 123456"
    f = normalize_structures(text, rules.detect_passport(text))
    by_part = {x.part: text[x.start : x.end] for x in f}
    assert by_part["series"] == "4510"
    assert by_part["number"] == "123456"


def test_driver_license_parts():
    text = "Водительское удостоверение: серия 77 11, номер 123456"
    f = normalize_structures(text, rules.detect_driver_license(text))
    assert {x.part for x in f} >= {"series", "number"}


def test_cardholder_splits_first_last():
    text = "Имя держателя карты: IVAN IVANOV"
    f = normalize_structures(text, rules.detect_cardholder_name(text))
    parts = {x.part: text[x.start : x.end] for x in f}
    assert parts == {"first": "IVAN", "last": "IVANOV"}


def test_address_component_parts():
    text = "Адрес проживания клиента: Москва, ул. Тверская, д. 10, кв. 15"
    f = normalize_structures(text, rules.detect_address(text))
    parts = {x.part: text[x.start : x.end] for x in f if x.part}
    assert parts.get("city") == "Москва"
    assert "Тверская" in (parts.get("street") or "")
    assert "10" in (parts.get("house") or "")
    assert "15" in (parts.get("flat") or "")


def test_split_person_span_unit():
    text = "xxx Иванов Иван yyy"
    out = split_person_span(text, 4, 15, 0.9, "t")
    assert [x.part for x in out] == ["first", "last"]
    assert [text[x.start : x.end] for x in out] == ["Иванов", "Иван"]


def test_pipeline_person_parts_masked():
    text = "ФИО клиента: Иванов Иван Иванович"
    f = detect_pii(text, enable_ner=False)
    persons = [x for x in f if x.type == "PERSON" and x.decision == "mask"]
    assert {x.part for x in persons} == {"last", "first", "middle"}
