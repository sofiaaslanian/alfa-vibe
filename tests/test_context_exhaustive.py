"""Role-first contextual types: PERSON, PLACE_OF_BIRTH, CITIZENSHIP,
PASSPORT_ISSUER, ADDRESS, CARDHOLDER_NAME.

Matrix contract: value alone ≠ PII; positive role required; negatives win.
"""

from __future__ import annotations

import pytest

from app.pii import rules
from app.pii.detect import detect_pii
from tests.conftest import joined_mask_vals


def _vals(text: str, typ: str) -> list[str]:
    return joined_mask_vals(text, typ)


# ── PERSON ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("ФИО клиента: Иванов Иван Иванович", "Иванов Иван Иванович"),
        ("Клиент Петрова Анна просит ответить.", "Петрова Анна"),
        ("меня зовут Соня Асланян", "Соня Асланян"),
        ("Меня зовут София Асланян", "София Асланян"),
        ("мое имя Иван Петров", "Иван Петров"),
        ("Клиент Александр Пушкин просит перевыпуск карты", "Александр Пушкин"),
        ("Напиши письмо клиенту Иванову Ивану на ivan@example.com", "Иванову Ивану"),
        ("Свяжитесь с Иваном Петровым.", "Иваном Петровым"),
        ("письмо для Анны Сергеевой", "Анны Сергеевой"),
    ],
)
def test_person_role_positive(text, expected):
    assert expected in _vals(text, "PERSON")


@pytest.mark.parametrize(
    "text",
    [
        "Александр Пушкин — русский поэт",
        "В тексте указан роман «Евгений Онегин».",
        "Докладчик: Иван Петров",
    ],
)
def test_person_role_negative(text):
    assert _vals(text, "PERSON") == []


# ── PLACE_OF_BIRTH ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Место рождения: Москва", "Москва"),
        ("Клиент родился в Казани.", "Казани"),
        ("родился в г. Санкт-Петербурге", "г. Санкт-Петербурге"),
        ("Место рождения клиента — Казань", "Казань"),
    ],
)
def test_place_positive(text, expected):
    assert expected in _vals(text, "PLACE_OF_BIRTH")


@pytest.mark.parametrize(
    "text",
    [
        "Конференция пройдёт в Москве",
        "Место проведения встречи: Казань",
        "Москва",  # bare city
    ],
)
def test_place_negative(text):
    assert _vals(text, "PLACE_OF_BIRTH") == []


# ── CITIZENSHIP ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Гражданство клиента: РФ", "РФ"),
        ("Клиент — гражданин Казахстана.", "Казахстана"),
        ("гражданство: Россия", "Россия"),
    ],
)
def test_citizen_positive(text, expected):
    assert expected in _vals(text, "CITIZENSHIP")


@pytest.mark.parametrize(
    "text",
    [
        "Для участия гражданство РФ не требуется",
        "Правила получения гражданства Казахстана опубликованы.",
        "РФ",  # bare
    ],
)
def test_citizen_negative(text):
    assert _vals(text, "CITIZENSHIP") == []


# ── PASSPORT_ISSUER ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Паспорт выдан ГУ МВД России по г. Москве", "ГУ МВД России по г. Москве"),
        ("Кем выдан паспорт: ОМВД России по району Арбат", "ОМВД России по району Арбат"),
    ],
)
def test_issuer_positive(text, expected):
    assert expected in _vals(text, "PASSPORT_ISSUER")


@pytest.mark.parametrize(
    "text",
    [
        "ГУ МВД России по г. Москве указано в справочнике организаций",
        "Новость опубликована ОМВД России по району Арбат.",
    ],
)
def test_issuer_negative(text):
    assert _vals(text, "PASSPORT_ISSUER") == []


# ── ADDRESS ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "Адрес проживания клиента: Москва, ул. Тверская, д. 10, кв. 15",
            "Москва, ул. Тверская, д. 10, кв. 15",
        ),
        ("Клиент проживает: ул. Лесная, д. 5", "ул. Лесная, д. 5"),
        ("мой адрес: г. Москва, ул. Тверская, д. 1, кв. 5", "г. Москва, ул. Тверская, д. 1, кв. 5"),
        ("г. Москва, ул. Тверская, д. 1, кв. 5", "г. Москва, ул. Тверская, д. 1, кв. 5"),
        ("Москва, ул. Тверская, д. 10", "Москва, ул. Тверская, д. 10"),
    ],
)
def test_address_positive(text, expected):
    vals = _vals(text, "ADDRESS")
    assert any(expected in v or v in expected for v in vals), vals


@pytest.mark.parametrize(
    "text",
    [
        "Адрес отделения Банка: Москва, ул. Тверская, д. 10",
        "Адрес офиса компании: ул. Лесная, д. 5",
    ],
)
def test_address_negative(text):
    assert _vals(text, "ADDRESS") == []


# ── CARDHOLDER ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Имя держателя карты: IVAN IVANOV", "IVAN IVANOV"),
        ("держатель карты PETROV IVAN", "PETROV IVAN"),
        ("имя на карте: IVAN I.", "IVAN I"),  # may trim — check below separately
    ],
)
def test_cardholder_positive(text, expected):
    vals = _vals(text, "CARDHOLDER_NAME")
    assert vals, f"expected finding in {text!r}"
    assert expected in vals[0] or vals[0].startswith(expected[:4])


def test_cardholder_negative():
    assert _vals("Докладчик: IVAN IVANOV", "CARDHOLDER_NAME") == []
    assert _vals("IVAN IVANOV", "CARDHOLDER_NAME") == []


def test_matrix_smoke_pipeline():
    text = (
        "ФИО клиента: Иванов Иван Иванович. "
        "Место рождения: Москва. Гражданство клиента: РФ. "
        "Паспорт выдан ГУ МВД России по г. Москве. "
        "Адрес проживания клиента: Москва, ул. Тверская, д. 10, кв. 15. "
        "Имя держателя карты: IVAN IVANOV."
    )
    types = {f.type for f in detect_pii(text, enable_ner=False)}
    assert {
        "PERSON",
        "PLACE_OF_BIRTH",
        "CITIZENSHIP",
        "PASSPORT_ISSUER",
        "ADDRESS",
        "CARDHOLDER_NAME",
    } <= types
