from app.pii import rules


def _vals(text, findings):
    return [text[f.start:f.end] for f in findings]


def test_p4a_passport_keeps_real_and_drops_operation_decoy():
    real = "Паспорт клиента: 45 11 123456"
    assert _vals(real, rules.detect_passport(real))

    decoy = "Паспорт уже проверен. ID операции 45 11 123456"
    assert rules.detect_passport(decoy) == []


def test_p4a_driver_keeps_real_and_drops_order_decoy():
    real = "В/У № 77 11 123456"
    assert _vals(real, rules.detect_driver_license(real))

    decoy = "Водительское удостоверение проверено. Номер заказа 77 11 123456"
    assert rules.detect_driver_license(decoy) == []


def test_p4a_subdivision_keeps_real_and_drops_examples():
    real = "Код подразделения: 770-002"
    assert _vals(real, rules.detect_subdivision(real)) == ["770-002"]

    assert rules.detect_subdivision("Пример кода подразделения: 770-002") == []
    assert rules.detect_subdivision("Формат кода подразделения: 770-002") == []
