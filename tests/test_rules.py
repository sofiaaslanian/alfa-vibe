from __future__ import annotations

import pytest

from app.pii.pipeline import detect_pii
from app.pii.rules import card, email, inn, phone


def test_email_positive():
    text = "Клиент: ivanov@mail.ru написал письмо"
    f = email.detect(text)
    assert len(f) == 1
    assert text[f[0].start : f[0].end] == "ivanov@mail.ru"


def test_email_service_negative():
    assert email.detect("Пишите на support@bank.ru") == []


def test_phone_positive():
    text = "Телефон клиента: +7 999 123-45-67"
    f = phone.detect(text)
    assert len(f) == 1


def test_card_luhn():
    text = "Карта 4111 1111 1111 1111"
    f = card.detect(text)
    assert len(f) == 1
    assert f[0].type == "PAYMENT_CARD"


def test_card_invalid_luhn():
    assert card.detect("Карта 4111 1111 1111 1112") == []


def _make_valid_inn12() -> str:
    # Build valid 12-digit INN
    base = [5, 0, 0, 1, 0, 0, 7, 3, 2, 2]
    coeffs1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    coeffs2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    d11 = sum(c * base[i] for i, c in enumerate(coeffs1)) % 11 % 10
    body = base + [d11]
    d12 = sum(c * body[i] for i, c in enumerate(coeffs2)) % 11 % 10
    return "".join(str(x) for x in body + [d12])


def test_inn_checksum():
    value = _make_valid_inn12()
    text = f"ИНН клиента: {value}"
    f = inn.detect(text)
    assert len(f) == 1


def test_pipeline_format_mix():
    inn_v = _make_valid_inn12()
    text = f"Email ivan@test.ru, телефон +7 900 111-22-33, ИНН {inn_v}, карта 4111111111111111"
    findings = detect_pii(text, enable_ner=False)
    types = {f.type for f in findings}
    assert "EMAIL" in types
    assert "PHONE" in types
    assert "INN" in types
    assert "PAYMENT_CARD" in types


def test_passport_context():
    from app.pii.rules import passport

    pos = passport.detect("Паспорт клиента: серия 4510 номер 123456")
    assert len(pos) == 1
    neg = passport.detect("Номер заказа: 4510 123456")
    assert neg == []


def test_cvv_requires_anchor():
    from app.pii.rules import cvv

    assert cvv.detect("код офиса: 123") == []
    assert len(cvv.detect("CVV карты: 123")) == 1
