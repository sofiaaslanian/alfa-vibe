"""Exhaustive PII cases 3/4: subdivision, passport issue date, driver license, CVV."""

from tests.exhaustive_case_helpers import pos, neg

CASES = []

# PASSPORT_DIVISION_CODE — 20
T = "PASSPORT_DIVISION_CODE"
CASES += [
    pos("subdiv_basic", T, "Код подразделения: 770-001", "770-001"),
    pos("subdiv_linebreak", T, "Код подразделения\n770-002", "770-002"),
    pos("subdiv_passport", T, "Паспорт: код подразделения 500-101", "500-101"),
    pos("subdiv_yaml", T, "division_code: 770-003", "770-003"),
    pos("subdiv_json", T, '{"division_code":"770-004"}', "770-004"),
    pos("subdiv_issued", T, "Код подразделения органа выдачи — 780-001", "780-001"),
    pos("subdiv_in_sentence", T, "В анкете указан код подразделения 770-005.", "770-005"),
    pos("subdiv_tabs", T, "Код подразделения:\t770-006", "770-006"),
    pos("subdiv_nbsp", T, "Код подразделения:\u00a0770-007", "770-007"),
    pos("subdiv_after", T, "770-008 — код подразделения паспорта", "770-008"),
    pos("subdiv_upper_field", T, "PASSPORT DIVISION CODE: 770-009", "770-009"),
    pos("subdiv_multiple", T, "Код подразделения 770-010, прежний код подразделения 770-011", "770-010", "770-011"),
    neg("subdiv_office_code", T, "Код офиса: 770-001"),
    neg("subdiv_product_code", T, "Код товара: 770-002"),
    neg("subdiv_route", T, "Маршрут 770-003"),
    neg("subdiv_bare", T, "770-004"),
    neg("subdiv_ticket", T, "Номер билета 770-005"),
    neg("subdiv_batch", T, "Партия товара: 770-006"),
    neg("subdiv_system", T, "Системный код 770-007"),
    neg("subdiv_warehouse", T, "Индекс секции склада 770-008"),
]

# PASSPORT_ISSUE_DATE — 20
T = "PASSPORT_ISSUE_DATE"
CASES += [
    pos("issue_basic", T, "Дата выдачи паспорта: 03.04.2015", "03.04.2015"),
    pos("issue_dash", T, "Дата выдачи паспорта: 03-04-2015", "03-04-2015"),
    pos("issue_slash", T, "Дата выдачи паспорта: 03/04/2015", "03/04/2015"),
    pos("issue_iso", T, "Дата выдачи паспорта: 2015-04-03", "2015-04-03"),
    pos("issue_iso_dot", T, "Дата выдачи паспорта: 2015.04.03", "2015.04.03"),
    pos("issue_text", T, "Паспорт выдан 3 апреля 2015 года.", "3 апреля 2015 года"),
    pos("issue_label_short", T, "Паспорт. Выдан: 03.04.2015", "03.04.2015"),
    pos("issue_yaml", T, "passport_issue_date: 2015-04-03", "2015-04-03"),
    pos("issue_json", T, '{"passport_issue_date":"2015-04-03"}', "2015-04-03"),
    pos("issue_linebreak", T, "Дата выдачи паспорта\n03.04.2015", "03.04.2015"),
    pos("issue_sentence", T, "Паспорт клиента был выдан 03.04.2015.", "03.04.2015"),
    pos("issue_with_passport", T, "Паспорт 4510 123456, дата выдачи 03.04.2015.", "03.04.2015"),
    neg("issue_birth", T, "Дата рождения: 03.04.2015"),
    neg("issue_driver", T, "ВУ выдано 03.04.2015"),
    neg("issue_contract", T, "Договор выдан 03.04.2015"),
    neg("issue_publication", T, "Дата публикации: 03.04.2015"),
    neg("issue_expiry", T, "Паспорт действителен до 03.04.2035"),
    neg("issue_meeting", T, "Дата встречи 03.04.2015"),
    neg("issue_bare", T, "03.04.2015"),
    neg("issue_report", T, "Дата отчёта 03.04.2015"),
]

# DRIVER_LICENSE_NUMBER — 20
T = "DRIVER_LICENSE_NUMBER"
CASES += [
    pos("vu_basic", T, "ВУ: 77 01 123456", "77 01 123456"),
    pos("vu_label_full", T, "Водительское удостоверение: 77 01 123456", "77 01 123456"),
    pos("vu_rights", T, "Права: 77 01 123456", "77 01 123456"),
    pos("vu_series_number", T, "ВУ серия 77 01 номер 123456", "77 01", "123456"),
    pos("vu_compact", T, "ВУ 7701123456", "7701123456"),
    pos("vu_linebreak", T, "Водительское удостоверение\n77 01 123456", "77 01 123456"),
    pos("vu_yaml", T, "driver_license: 77 01 123456", "77 01 123456"),
    pos("vu_json", T, '{"driver_license":"77 01 123456"}', "77 01 123456"),
    pos("vu_in_sentence", T, "Номер водительского удостоверения клиента 77 01 123456.", "77 01 123456"),
    pos("vu_number_sign", T, "ВУ серия 77 01 № 123456", "77 01", "123456"),
    pos("vu_quoted", T, 'Права клиента: «77 01 123456»', "77 01 123456"),
    pos("vu_multiple", T, "ВУ 77 01 123456, старое ВУ 50 05 654321", "77 01 123456", "50 05 654321"),
    neg("vu_passport", T, "Паспорт: 45 10 123456"),
    neg("vu_order", T, "Номер заказа 77 01 123456"),
    neg("vu_bare", T, "77 01 123456"),
    neg("vu_equipment", T, "Серийный номер 7701123456"),
    neg("vu_contract", T, "Договор № 77 01 123456"),
    neg("vu_account", T, "Лицевой счёт 7701123456"),
    neg("vu_tracking", T, "Tracking 77 01 123456"),
    neg("vu_example", T, "Пример ВУ: 00 00 000000"),
]

# CVV — 20
T = "CVV"
CASES += [
    pos("cvv_basic", T, "CVV: 123", "123"),
    pos("cvv_cvc", T, "CVC: 532", "532"),
    pos("cvv_cvv2", T, "CVV2 карты: 777", "777"),
    pos("cvv_cvc2", T, "CVC2: 456", "456"),
    pos("cvv_back", T, "Три цифры на обороте карты 321", "321"),
    pos("cvv_security", T, "Код безопасности карты: 654", "654"),
    pos("cvv_json", T, '{"card":"4111111111111111","cvv":"123"}', "123"),
    pos("cvv_yaml", T, "cvv: 987", "987"),
    pos("cvv_linebreak", T, "CVV\n246", "246"),
    pos("cvv_four_digit", T, "CVV карты: 1234", "1234"),
    pos("cvv_in_sentence", T, "У карты CVV 159.", "159"),
    pos("cvv_card_near", T, "Карта 4111 1111 1111 1111, CVC 753", "753"),
    neg("cvv_office_code", T, "Код офиса: 123"),
    neg("cvv_order_code", T, "Код заказа: 532"),
    neg("cvv_otp", T, "Код подтверждения: 777"),
    neg("cvv_sms", T, "Код из СМС: 456"),
    neg("cvv_bare", T, "123"),
    neg("cvv_room", T, "Номер комнаты: 321"),
    neg("cvv_year", T, "Год: 2026"),
    neg("cvv_pin", T, "PIN-код карты: 1234"),
]

assert len(CASES) == 80
