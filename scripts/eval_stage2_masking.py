"""Stage 2: masking + demasking quality on frozen MVP v1.

Primary score is conditional on correct type identification from stage 1, so
the same identification error is not counted twice.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.config import SystemConfig, load_config
from app.process import ProcessService
from app.state import MemoryStateStore
from eval_stage1_identification import CASES

# Exact sensitive VALUE spans expected to be protected. Service words such as
# "серия", "номер", "ул.", "д.", "кв." are intentionally outside these spans.
VALUES = {
    "PERSON": [
        ["Иван Петров"],
        ["Мария Соколова"],
        ["Смирнов Алексей Андреевич"],
        ["Анна Викторовна Орлова"],
        ["Сергей Кузнецов"],
    ],
    "PLACE_OF_BIRTH": [
        ["Казань"], ["Самаре"], ["Нижний Новгород"], ["Туле"], ["Владивосток"],
    ],
    "CITIZENSHIP": [
        ["Россия"], ["РФ"], ["Казахстана"], ["Армении"], ["Беларусь"],
    ],
    "PASSPORT_ISSUER": [
        ["ГУ МВД России по г. Москве"],
        ["ОМВД России по району Арбат"],
        ["УМВД России по Тверской области"],
        ["отделом УФМС России по Санкт-Петербургу"],
        ["МВД России по Республике Татарстан"],
    ],
    "ADDRESS": [
        ["Москва", "Лесная", "10", "5"],
        ["Казань", "Баумана", "7"],
        ["Самаре", "Ленина", "5"],
        ["190000", "Санкт-Петербург", "Невский проспект", "20"],
        ["Екатеринбург", "Малышева", "15", "8"],
    ],
    "CARDHOLDER_NAME": [
        ["IVAN PETROV"], ["Мария Соколова"], ["ALEXEY SMIRNOV"], ["ANNA ORLOVA"], ["Сергей Кузнецов"],
    ],
    "BIRTH_DATE": [
        ["12.04.1995"], ["03.11.1988"], ["1990-02-01"], ["7 января 1992 года"], ["15/06/2000"],
    ],
    "PASSPORT": [
        ["45 10", "123456"],
        ["4511", "654321"],
        ["40 05", "112233"],
        ["4509", "987654"],
        ["77 12", "345678"],
    ],
    "SUBDIVISION_CODE": [
        ["770-001"], ["500-123"], ["780-045"], ["660-007"], ["160-002"],
    ],
    "PASSPORT_ISSUE_DATE": [
        ["12.05.2015"], ["03.11.2020"], ["2018-07-21"], ["5 марта 2019 года"], ["01/09/2017"],
    ],
    "DRIVER_LICENSE": [
        ["77 11 123456"], ["50 09 654321"], ["99 12 112233"], ["16 08 445566"], ["63 10 778899"],
    ],
    "CVV": [["123"], ["456"], ["789"], ["321"], ["654"]],
    "PIN": [["1234"], ["9876"], ["4455"], ["6611"], ["7722"]],
    "EMAIL": [
        ["ivan.petrov@mail.ru"],
        ["maria.sokolova@example.com"],
        ["alexey+bank@domain.ru"],
        ["user_2026@test-bank.ru"],
        ["anna.orlova@company.org"],
    ],
    "PHONE": [
        ["+7 (999) 123-45-67"],
        ["8(916)555-44-33"],
        ["+79991112233"],
        ["+7 495 111 22 33"],
        ["+7.903.222.11.00"],
    ],
    "INN": [
        ["500100732259"], ["415345080525"], ["123456789047"], ["366406939705"], ["772746592401"],
    ],
    "PAYMENT_CARD": [
        ["4111 1111 1111 1111"],
        ["5555 5555 5555 4444"],
        ["4000 0000 0000 0002"],
        ["4012 8888 8888 1881"],
        ["4222 2222 2222 2"],
    ],
}

MIXED = [
    {
        "id": "mixed_1",
        "text": "Клиент Иван Петров, email ivan.petrov@mail.ru, телефон +7 (999) 123-45-67, карта 4111 1111 1111 1111.",
        "values": ["Иван Петров", "ivan.petrov@mail.ru", "+7 (999) 123-45-67", "4111 1111 1111 1111"],
    },
    {
        "id": "mixed_2",
        "text": "Паспорт 45 10 123456, код подразделения 770-001, дата выдачи 12.05.2015.",
        "values": ["45 10", "123456", "770-001", "12.05.2015"],
    },
    {
        "id": "mixed_3",
        "text": "Клиентка Мария Соколова родилась 7 января 1992 года, адрес проживания: Казань, ул. Баумана, д. 7.",
        "values": ["Мария Соколова", "7 января 1992 года", "Казань", "Баумана", "7"],
    },
    {
        "id": "mixed_4",
        "text": "Держатель карты IVAN PETROV, карта 4111 1111 1111 1111, CVV 123, PIN 9876.",
        "values": ["IVAN PETROV", "4111 1111 1111 1111", "123", "9876"],
    },
    {
        "id": "mixed_5",
        "text": "ИНН клиента 500100732259, гражданство Россия, место рождения Самара.",
        "values": ["500100732259", "Россия", "Самара"],
    },
]

assert set(VALUES) == set(CASES)
assert all(len(v) == 5 for v in VALUES.values())


def expected_mask(text: str, values: list[str]) -> str:
    protected = [False] * len(text)
    cursor_by_value: dict[str, int] = {}
    for value in values:
        start_at = cursor_by_value.get(value, 0)
        start = text.find(value, start_at)
        if start < 0:
            raise AssertionError(f"Expected value {value!r} not found in {text!r}")
        cursor_by_value[value] = start + len(value)
        for i in range(start, start + len(value)):
            protected[i] = True

    chars = list(text)
    for i, ch in enumerate(chars):
        if protected[i] and ch.isalnum():
            chars[i] = "*"
    return "".join(chars)


def target_found(svc: ProcessService, text: str, target: str) -> bool:
    return any(
        f.type == target and getattr(f, "decision", "mask") == "mask"
        for f in svc.detect(text, "autotest")
    )


def run_single_cases():
    cfg = load_config("config.yaml")
    base_svc = ProcessService(cfg, MemoryStateStore())

    details = []
    evaluated = 0
    mask_ok = 0
    demask_ok = 0
    skipped_stage1 = 0

    for target, group in CASES.items():
        for idx, text in enumerate(group["positive"], 1):
            if not target_found(base_svc, text, target):
                skipped_stage1 += 1
                details.append({
                    "type": target,
                    "n": idx,
                    "text": text,
                    "status": "skipped_stage1_fn",
                })
                continue

            evaluated += 1
            case_cfg = load_config("config.yaml")
            case_cfg.systems["stage2"] = SystemConfig(
                name="stage2",
                enabled=True,
                pd_types=[target],
                allow_demask=True,
                mask_style="dev_redact",
                use_context_ml=True,
                use_ner=True,
            )
            svc = ProcessService(case_cfg, MemoryStateStore())
            pid = f"stage2-{target}-{idx}"
            masked = svc.process(text, pid, "stage2")
            expected = expected_mask(text, VALUES[target][idx - 1])
            this_mask_ok = masked == expected
            restored = svc.process(masked, pid, "stage2")
            this_demask_ok = restored == text
            mask_ok += int(this_mask_ok)
            demask_ok += int(this_demask_ok)

            details.append({
                "type": target,
                "n": idx,
                "text": text,
                "status": "evaluated",
                "expected_mask": expected,
                "actual_mask": masked,
                "mask_ok": this_mask_ok,
                "restored": restored,
                "demask_ok": this_demask_ok,
            })

    return {
        "eligible_positive_cases": evaluated,
        "skipped_stage1_fn": skipped_stage1,
        "mask_passed": mask_ok,
        "demask_passed": demask_ok,
        "mask_accuracy": mask_ok / evaluated if evaluated else 0,
        "demask_accuracy": demask_ok / evaluated if evaluated else 0,
        "details": details,
    }


def run_mixed_cases():
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())
    out = []
    for i, case in enumerate(MIXED, 1):
        pid = f"stage2-mixed-{i}"
        masked = svc.process(case["text"], pid, "autotest")
        expected = expected_mask(case["text"], case["values"])
        restored = svc.process(masked, pid, "autotest")
        out.append({
            "id": case["id"],
            "text": case["text"],
            "expected_mask": expected,
            "actual_mask": masked,
            "mask_ok": masked == expected,
            "demask_ok": restored == case["text"],
            "restored": restored,
        })
    return out


def main():
    single = run_single_cases()
    mixed = run_mixed_cases()
    result = {
        "stage": 2,
        "product_version": "MVP v1 frozen after stage 1",
        "method": "mask quality conditional on successful stage-1 type identification; exact round-trip demask",
        "single": single,
        "mixed": mixed,
    }
    Path("stage2_mask_demask_results.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    e = single["eligible_positive_cases"]
    print("STAGE2_ELIGIBLE", e)
    print("STAGE2_SKIPPED_STAGE1", single["skipped_stage1_fn"])
    print("STAGE2_MASK", f'{single["mask_passed"]}/{e}', f'{100*single["mask_accuracy"]:.1f}%')
    print("STAGE2_DEMASK", f'{single["demask_passed"]}/{e}', f'{100*single["demask_accuracy"]:.1f}%')
    mask_fails = [x for x in single["details"] if x.get("status") == "evaluated" and not x["mask_ok"]]
    demask_fails = [x for x in single["details"] if x.get("status") == "evaluated" and not x["demask_ok"]]
    print("MASK_FAILURES", len(mask_fails))
    for x in mask_fails:
        print("MASK_FAIL", x["type"], x["n"], "|", x["text"])
        print(" EXPECTED:", x["expected_mask"])
        print(" ACTUAL  :", x["actual_mask"])
    print("DEMASK_FAILURES", len(demask_fails))
    for x in demask_fails:
        print("DEMASK_FAIL", x["type"], x["n"], "|", x["text"])
    print("MIXED", sum(1 for x in mixed if x["mask_ok"]), "/", len(mixed), "mask;",
          sum(1 for x in mixed if x["demask_ok"]), "/", len(mixed), "demask")
    for x in mixed:
        if not x["mask_ok"] or not x["demask_ok"]:
            print("MIXED_FAIL", x["id"], "mask=", x["mask_ok"], "demask=", x["demask_ok"])
            print(" EXPECTED:", x["expected_mask"])
            print(" ACTUAL  :", x["actual_mask"])


if __name__ == "__main__":
    main()
