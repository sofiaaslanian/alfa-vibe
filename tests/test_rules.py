from __future__ import annotations

from app.pii.detect import detect_pii
from app.pii import rules


def test_email_positive():
    text = "Клиент: ivanov@mail.ru написал письмо"
    f = rules.detect_email(text)
    assert len(f) == 1
    assert text[f[0].start : f[0].end] == "ivanov@mail.ru"


def test_email_service_negative():
    assert rules.detect_email("Пишите на support@bank.ru") == []


def test_phone_positive():
    assert len(rules.detect_phone("Телефон клиента: +7 999 123-45-67")) == 1


def test_card_luhn():
    f = rules.detect_card("Карта 4111 1111 1111 1111")
    assert len(f) == 1 and f[0].type == "PAYMENT_CARD"


def test_card_invalid_luhn_without_keyword():
    # Bare invalid PAN must not match.
    assert rules.detect_card("Идентификатор 4111 1111 1111 1112") == []


def test_card_invalid_luhn_with_keyword_fallback():
    # Cloud.ru-style: after «карта» typo PAN still protected.
    f = rules.detect_card("Карта 4111 1111 1111 1112")
    assert len(f) == 1 and f[0].type == "PAYMENT_CARD"
    assert f[0].detector == "card_rule_no_luhn_v1"


def _make_valid_inn12() -> str:
    base = [5, 0, 0, 1, 0, 0, 7, 3, 2, 2]
    coeffs1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    coeffs2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    d11 = sum(c * base[i] for i, c in enumerate(coeffs1)) % 11 % 10
    body = base + [d11]
    d12 = sum(c * body[i] for i, c in enumerate(coeffs2)) % 11 % 10
    return "".join(str(x) for x in body + [d12])


def test_inn_checksum():
    value = _make_valid_inn12()
    assert len(rules.detect_inn(f"ИНН клиента: {value}")) == 1


def test_pipeline_format_mix():
    inn_v = _make_valid_inn12()
    text = f"Email ivan@test.ru, телефон +7 900 111-22-33, ИНН {inn_v}, карта 4111111111111111"
    types = {f.type for f in detect_pii(text, enable_ner=False)}
    assert {"EMAIL", "PHONE", "INN", "PAYMENT_CARD"} <= types


def test_passport_context():
    # labelled series/number → two digit spans (no «номер» service word)
    text = "Паспорт клиента: серия 4510, номер 123456"
    f = rules.detect_passport(text)
    assert len(f) >= 2
    vals = {text[x.start : x.end] for x in f}
    assert "4510" in vals
    assert "123456" in vals
    assert all("номер" not in text[x.start : x.end] for x in f)
    assert rules.detect_passport("Номер заказа: 4510 123456") == []


def test_labelled_contextual():
    assert rules.detect_place_of_birth("Место рождения: Москва")[0].type == "PLACE_OF_BIRTH"
    assert rules.detect_citizenship("Гражданство клиента: РФ")
    assert rules.detect_passport_issuer("Паспорт выдан ГУ МВД России по г. Москве")
    assert rules.detect_cardholder_name("Имя держателя карты: IVAN IVANOV")
    assert rules.detect_place_of_birth("Конференция пройдёт в Москве") == []
    assert rules.detect_citizenship("Для участия гражданство РФ не требуется") == []


def test_textual_dates_and_negatives():
    assert rules.detect_birth_date("Клиент родился 3 мая 1998 года.")
    assert rules.detect_birth_date("Дата публикации: 3 мая 1998 года") == []
    assert rules.detect_pin("PIN SIM-карты: 9057") == []
    assert rules.detect_address("Адрес офиса компании: ул. Лесная, д. 5") == []
    assert rules.detect_inn("Номер договора: 123456789047")
    assert rules.detect_card("Идентификатор операции: 4111111111111111")
    assert rules.detect_email("📧 Почта клиента: anna.petrov+test@example.com")


def test_cvv_requires_anchor():
    assert rules.detect_cvv("код офиса: 123") == []
    assert len(rules.detect_cvv("CVV карты: 123")) == 1
    assert len(rules.detect_cvv("мой CVC код 532")) == 1
    assert rules.detect_cvv("мой CVC код 532")[0].start == (
        "мой CVC код 532".index("532")
    )
    assert len(rules.detect_cvv("CVC: 532")) == 1
    assert rules.detect_cvv("заказ код 532") == []