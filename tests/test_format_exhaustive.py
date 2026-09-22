"""Exhaustive surface forms for format-only types: EMAIL, PHONE, INN, PAYMENT_CARD.

These are NOT copies of acceptance phrasing — they check format-first behaviour:
valid format → find; explicit negative role / invalid format → skip.
"""

from __future__ import annotations

import pytest

from app.pii import rules
from app.pii.detect import detect_pii


def _vals(text: str, typ: str) -> list[str]:
    return [text[f.start : f.end] for f in rules.detect_all_rules(text) if f.type == typ]


def _make_valid_inn12() -> str:
    base = [5, 0, 0, 1, 0, 0, 7, 3, 2, 2]
    coeffs1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    coeffs2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    d11 = sum(c * base[i] for i, c in enumerate(coeffs1)) % 11 % 10
    body = base + [d11]
    d12 = sum(c * body[i] for i, c in enumerate(coeffs2)) % 11 % 10
    return "".join(str(x) for x in body + [d12])


# ── EMAIL ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("напиши мне на sofia@gmail.com пожалуйста", "sofia@gmail.com"),
        ("Contact: Anna.Petrov+tag@example.com.", "Anna.Petrov+tag@example.com"),
        ("почта ivanov@mail.ru", "ivanov@mail.ru"),
        ("📧 sofia.aslanian@yandex.ru", "sofia.aslanian@yandex.ru"),
        ("e-mail: a@b.co", "a@b.co"),
        ("MAILTO:user_name@corp-mail.org;", "user_name@corp-mail.org"),
        ("sofia@alfabank.ru", "sofia@alfabank.ru"),
    ],
)
def test_email_freeform_positive(text, expected):
    assert expected in _vals(text, "EMAIL")


@pytest.mark.parametrize(
    "text",
    [
        "Почта поддержки: support@bank.ru",
        "noreply@alfabank.ru",
        "Email клиента: ivanov@@example.ru",
        "пример почты: demo@example.com",
        "не email: user@",
        "не email: @domain.ru",
    ],
)
def test_email_negatives(text):
    assert _vals(text, "EMAIL") == []


def test_email_client_overrides_service_blacklist():
    assert _vals("Email клиента: support@bank.ru", "EMAIL") == ["support@bank.ru"]
    assert _vals("support@bank.ru", "EMAIL") == []


# ── PHONE ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("позвони на +79991234567", "+79991234567"),
        ("мой номер 89991234567", "89991234567"),
        ("тел. +7 999 123-45-67", "+7 999 123-45-67"),
        ("8 (999) 123 45 67 ок", "8 (999) 123 45 67"),
        ("+7-999-123-45-67", "+7-999-123-45-67"),
        ("7 999 123 45 67", "7 999 123 45 67"),
        ("8(999)1234567", "8(999)1234567"),
        ("телефон:+7.999.123.45.67", "+7.999.123.45.67"),
        ("intl +380501234567", "+380501234567"),
    ],
)
def test_phone_freeform_positive(text, expected):
    assert expected in _vals(text, "PHONE")


@pytest.mark.parametrize(
    "text",
    [
        "Телефон колл-центра: +7 999 123-45-67",
        "Номер заказа: 99912",
        "артикул 89991234567",
        "телефон офиса: +7 495 123-45-67",
    ],
)
def test_phone_negatives(text):
    assert _vals(text, "PHONE") == []


# ── INN ────────────────────────────────────────────────────────────────────


def test_inn_without_label():
    inn = _make_valid_inn12()
    text = f"вот мои данные {inn} дальше текст"
    assert _vals(text, "INN") == [inn]


def test_inn_acceptance_value_freeform():
    # Known valid from acceptance set — no «ИНН» word required.
    text = "клиент 123456789047 ждёт"
    assert _vals(text, "INN") == ["123456789047"]


def test_inn_with_label_and_newline():
    assert _vals("ИНН физического лица:\n123456789047", "INN") == ["123456789047"]


@pytest.mark.parametrize(
    "text",
    [
        "Номер договора: 123456789047",
        "ИНН клиента: 123456789048",  # bad checksum
        "номер заказа 123456789047",
        "артикул 123456789047",
    ],
)
def test_inn_negatives(text):
    assert _vals(text, "INN") == []


# ── PAYMENT_CARD ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("просто 4111111111111111", "4111111111111111"),
        ("оплата 4111 1111 1111 1111", "4111 1111 1111 1111"),
        ("5555-5555-5555-4444", "5555-5555-5555-4444"),
        ("карта:4111111111111111", "4111111111111111"),
        ("pan 4111\u00a01111\u00a01111\u00a01111", "4111\u00a01111\u00a01111\u00a01111"),
    ],
)
def test_card_freeform_positive(text, expected):
    assert expected in _vals(text, "PAYMENT_CARD")


@pytest.mark.parametrize(
    "text",
    [
        "Идентификатор операции: 4111111111111111",
        "Номер карты клиента: 4111 1111 1111 1112",  # bad Luhn
        "номер заказа 4111111111111111",
        "артикул 4111111111111111",
    ],
)
def test_card_negatives(text):
    assert _vals(text, "PAYMENT_CARD") == []


def test_format_mix_chat_style():
    inn = "123456789047"
    text = (
        f"привет, пиши на sofia@gmail.com или звони +7 916 123-45-67, "
        f"инн если надо {inn}, карта 4111 1111 1111 1111"
    )
    types = {f.type for f in detect_pii(text, enable_ner=False)}
    assert {"EMAIL", "PHONE", "INN", "PAYMENT_CARD"} <= types
