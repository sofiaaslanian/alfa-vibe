"""Regression tests for the architectural fixes discovered in stage 1/2.

These tests encode role classes and structural invariants, not the evaluation
strings themselves.
"""

import pytest

from app.masking import apply_dev_redact
from app.pii.detect import detect_pii


def _mask_findings(text: str, typ: str):
    return [
        f
        for f in detect_pii(text, enable_ner=False)
        if f.type == typ and getattr(f, "decision", "mask") == "mask"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "Встретимся по адресу: Казань, ул. Баумана, д. 7.",
        "Музей расположен по адресу: Санкт-Петербург, Невский проспект, д. 20.",
        "Офис компании находится по адресу: Самара, ул. Ленина, д. 5.",
    ],
)
def test_public_location_role_beats_generic_address_phrase(text):
    assert _mask_findings(text, "ADDRESS") == []


@pytest.mark.parametrize(
    "text",
    [
        "Мой адрес: Москва, ул. Лесная, д. 10, кв. 5.",
        "Адрес проживания клиента: Казань, ул. Баумана, д. 7.",
        "Доставьте карту по адресу: Екатеринбург, ул. Малышева, д. 15, кв. 8.",
    ],
)
def test_explicit_personal_address_role_is_kept(text):
    assert _mask_findings(text, "ADDRESS")


@pytest.mark.parametrize(
    "text,typ",
    [
        ("Шаблон user@example.org используется в документации.", "EMAIL"),
        ("Номер офиса: +7 (812) 111-22-33.", "PHONE"),
        ("Контакт отделения: +7 343 222-11-00.", "PHONE"),
        ("Серийный номер 4012888888881881.", "PAYMENT_CARD"),
        ("Код партии 4222222222222.", "PAYMENT_CARD"),
    ],
)
def test_valid_format_is_not_enough_without_personal_role(text, typ):
    assert _mask_findings(text, typ) == []


@pytest.mark.parametrize(
    "text,typ",
    [
        ("Email клиента: user@example.org.", "EMAIL"),
        ("Телефон клиента: +7 (812) 111-22-33.", "PHONE"),
        ("Номер карты клиента: 4012888888881881.", "PAYMENT_CARD"),
    ],
)
def test_explicit_personal_role_overrides_generic_format_ambiguity(text, typ):
    assert _mask_findings(text, typ)


@pytest.mark.parametrize(
    "text,typ",
    [
        ("Клиентка является гражданкой Армении.", "CITIZENSHIP"),
        ("Паспорт выдан отделом УФМС России по Санкт-Петербургу.", "PASSPORT_ISSUER"),
        ("На карте указано имя держателя Сергей Кузнецов.", "CARDHOLDER_NAME"),
        ("Серия паспорта 4511, номер 654321.", "PASSPORT"),
        ("Дата выдачи: 2018-07-21.", "PASSPORT_ISSUE_DATE"),
    ],
)
def test_role_grammar_covers_inflection_and_distributed_cues(text, typ):
    assert _mask_findings(text, typ)


def test_generic_issue_date_does_not_beat_specific_non_passport_role():
    assert _mask_findings("Дата выдачи заказа: 2018-07-21.", "PASSPORT_ISSUE_DATE") == []


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "Мой адрес: Москва, ул. Лесная, д. 10, кв. 5.",
            "Мой адрес: ******, ул. ******, д. **, кв. *.",
        ),
        (
            "Я живу в Самаре на улице Ленина 5.",
            "Я живу в ****** на улице ****** *.",
        ),
        (
            "Адрес регистрации: 190000, Санкт-Петербург, Невский проспект, д. 20.",
            "Адрес регистрации: ******, *****-*********, ******* проспект, д. **.",
        ),
    ],
)
def test_address_mask_hides_values_but_preserves_structure(text, expected):
    masked = apply_dev_redact(text, detect_pii(text, enable_ner=False))
    assert masked == expected
