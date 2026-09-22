"""Self-ID variants + banking intent classification catalog."""

from __future__ import annotations

import pytest

from app.pii.claims import classify_banking_intents, has_banking_intent
from app.pii.detect import detect_pii
from tests.conftest import joined_mask_vals


def _persons(text: str) -> list[str]:
    return joined_mask_vals(text, "PERSON")


# ── Self-ID surface forms ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("меня зовут Ваня Дмитриенко", "Ваня Дмитриенко"),
        ("Ваня Дмитриенко меня зовут", "Ваня Дмитриенко"),
        ("зовут меня Ваня Дмитриенко", "Ваня Дмитриенко"),
        ("мое имя Ваня Дмитриенко", "Ваня Дмитриенко"),
        ("моё имя Ваня Дмитриенко", "Ваня Дмитриенко"),
        ("Ваня Дмитриенко, меня зовут", "Ваня Дмитриенко"),
        # common typos
        ("меня завут Ваня Дмитриенко", "Ваня Дмитриенко"),
        ("Ваня Дмитриенко меня завут", "Ваня Дмитриенко"),
        ("представлюсь: Ваня Дмитриенко", "Ваня Дмитриенко"),
        ("я — Ваня Дмитриенко", "Ваня Дмитриенко"),
        ("Клиента зовут Ваня Дмитриенко", "Ваня Дмитриенко"),
        ("ФИО клиента: Ваня Дмитриенко", "Ваня Дмитриенко"),
    ],
)
def test_self_id_variants(text, expected):
    assert expected in _persons(text)


# ── Banking intents ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,intent",
    [
        ("хочу заказать карту", "card_issue"),
        ("оформить карту пожалуйста", "card_issue"),
        ("перевыпустите карту", "card_reissue"),
        ("карта утеряна, нужен перевыпуск", "card_reissue"),
        ("заблокируйте карту", "card_block"),
        ("открыть счёт", "account_open"),
        ("хочу кредит", "credit"),
        ("оформить ипотеку", "mortgage"),
        ("сделайте перевод", "transfer"),
        ("перезвоните мне", "callback"),
        ("где моя заявка", "status"),
        ("Клиент Иван просит перевыпуск карты", "card_reissue"),
    ],
)
def test_banking_intent_classify(text, intent):
    assert intent in classify_banking_intents(text)
    assert has_banking_intent(text)


def test_client_plus_card_request_masks_name():
    text = "Клиент Ваня Дмитриенко. Хочу заказать карту"
    assert "Ваня Дмитриенко" in _persons(text)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("я живу Волгоградский проспект, 23", "Волгоградский проспект, 23"),
        ("я живу на Волгоградском проспекте, 23", "Волгоградском проспекте, 23"),
        ("мой адрес: Волгоградский пр-т, 23", "Волгоградский пр-т, 23"),
        (
            "Адрес проживания клиента: Москва, ул. Тверская, д. 10, кв. 15",
            "Москва, ул. Тверская, д. 10, кв. 15",
        ),
    ],
)
def test_personal_address_masked(text, expected):
    vals = joined_mask_vals(text, "ADDRESS")
    assert any(expected in v or v in expected for v in vals), vals


@pytest.mark.parametrize(
    "text",
    [
        "Магазин на Волгоградском проспекте, 23",
        "Адрес отделения Банка: Москва, ул. Тверская, д. 10",
        "встретимся на Тверской улице, д. 5",
    ],
)
def test_public_address_not_masked(text):
    vals = joined_mask_vals(text, "ADDRESS")
    assert vals == [], vals


def test_third_party_still_skipped():
    assert _persons("Илон Маск купил Twitter") == []
    assert _persons("Александр Пушкин — русский поэт") == []
