#!/usr/bin/env python3
"""Run Dani's 68 acceptance cases + local latency/throughput smoke.

Reports exact-span TP/FP/FN per type, mask accuracy, round-trip, and timing.
Does not mutate expected spans/results to pass.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Prefer NER for contextual types; allow override via env.
os.environ.setdefault("NER_ENABLED", "1")
os.environ.setdefault("NER_LOCAL", "1")
os.environ.setdefault("NER_FAIL_CLOSED", "0")
os.environ.setdefault("STORAGE_BACKEND", "memory")

from app.config import load_config
from app.masking import TYPE_ALIASES, apply_dev_redact, canonical
from app.pii.detect import Finding, detect_pii
from app.process import ProcessService
from app.state import MemoryStateStore

CASES_PATH = ROOT / "docs" / "acceptance_cases.json"
OUT_PATH = ROOT / "docs" / "acceptance_eval_report.json"

# Our detector emits PERSON/PASSPORT/...; acceptance uses PERSON_NAME/PASSPORT_NUMBER/...
DETECT_TO_CANON = {v: k for k, v in TYPE_ALIASES.items() if k != v}
DETECT_TO_CANON.update(
    {
        "PERSON": "PERSON_NAME",
        "PASSPORT": "PASSPORT_NUMBER",
        "DRIVER_LICENSE": "DRIVER_LICENSE_NUMBER",
        "PIN": "CARD_PIN",
        "INN": "INN_PERSON",
    }
)


def to_acceptance_type(t: str) -> str:
    t = canonical(t)
    return DETECT_TO_CANON.get(t, t)


def filter_enabled(findings: list[Finding], enabled: list[str]) -> list[Finding]:
    want = {canonical(x) for x in enabled}
    # also accept detector-native names that map into want
    out = []
    for f in findings:
        ct = canonical(f.type)
        at = to_acceptance_type(f.type)
        if ct in want or at in want or f.type in want:
            out.append(f)
    return out


def span_key(typ: str, start: int, end: int) -> tuple[str, int, int]:
    return (to_acceptance_type(typ), start, end)


def evaluate_case(case: dict, *, enable_ner: bool) -> dict:
    text = case["payload"]
    enabled = case["enabled_types"]
    expected = [
        span_key(e["type"], e["start"], e["end"]) for e in case["expected_findings"]
    ]
    t0 = time.perf_counter()
    raw = detect_pii(text, enable_ner=enable_ner)
    dt = time.perf_counter() - t0
    filtered = filter_enabled(raw, enabled)
    got = [span_key(f.type, f.start, f.end) for f in filtered]

    exp_set = set(expected)
    got_set = set(got)
    tp = sorted(exp_set & got_set)
    fp = sorted(got_set - exp_set)
    fn = sorted(exp_set - got_set)

    masked = apply_dev_redact(text, filtered)
    mask_ok = masked == case["expected_result"]

    # Round-trip only meaningful when we found something or expected nothing
    cfg = load_config(str(ROOT / "config.yaml"))
    svc = ProcessService(cfg, MemoryStateStore())
    pid = f"acc-{case['id']}-{uuid.uuid4().hex[:8]}"
    # Bypass system filter: inject findings via detect override is hard;
    # use process on raw text — may detect extra types. For RT use our filtered mask.
    rt_ok = None
    try:
        # Manual round-trip with store using filtered mask path
        from app.crypto_util import encrypt, hmac_hex
        from app.process import NS_AUTOTEST
        from app.state import OperationState

        live_masked = masked
        aad = f"{NS_AUTOTEST}:{pid}"
        state = OperationState(
            payload_id=pid,
            namespace=NS_AUTOTEST,
            original_fp=hmac_hex(text),
            masked_fp=hmac_hex(live_masked),
            masked_enc=encrypt(live_masked, aad),
            original_enc=encrypt(text, aad),
            system="",
            mask_strategy="dev_redact_v1",
        )
        svc.store.create_atomic(state)
        demasked = svc.process(live_masked, pid)
        rt_ok = demasked == text
    except Exception as e:
        rt_ok = False
        rt_err = str(e)
    else:
        rt_err = None

    case_pass = (
        len(fp) == 0
        and len(fn) == 0
        and mask_ok
        and (rt_ok is True or (not expected and mask_ok))
    )

    return {
        "id": case["id"],
        "target_type": case["target_type"],
        "kind": case["kind"],
        "pass": case_pass,
        "span_exact": len(fp) == 0 and len(fn) == 0,
        "mask_ok": mask_ok,
        "roundtrip_ok": rt_ok,
        "latency_ms": round(dt * 1000, 2),
        "tp": [{"type": a, "start": b, "end": c} for a, b, c in tp],
        "fp": [{"type": a, "start": b, "end": c, "value": text[b:c]} for a, b, c in fp],
        "fn": [{"type": a, "start": b, "end": c} for a, b, c in fn],
        "got": [
            {
                "type": to_acceptance_type(f.type),
                "detect_type": f.type,
                "start": f.start,
                "end": f.end,
                "value": text[f.start : f.end],
                "detector": f.detector,
            }
            for f in filtered
        ],
        "expected_result": case["expected_result"],
        "actual_result": masked,
        "roundtrip_error": rt_err,
        "unsupported_type": case["target_type"]
        in {
            "PLACE_OF_BIRTH",
            "CITIZENSHIP",
            "PASSPORT_ISSUER",
            "CARDHOLDER_NAME",
        }
        and not any(
            to_acceptance_type(f.type) == case["target_type"] for f in filtered
        )
        and bool(expected),
    }


def f1(tp: int, fp: int, fn: int) -> dict:
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f, 4),
    }


def detector_throughput(payloads: list[str], n: int, concurrency: int, enable_ner: bool) -> dict:
    latencies: list[float] = []

    def one(i: int) -> float:
        text = payloads[i % len(payloads)]
        t0 = time.perf_counter()
        detect_pii(text, enable_ner=enable_ner)
        return time.perf_counter() - t0

    # warmup
    one(0)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(one, i) for i in range(n)]
        for fut in as_completed(futs):
            latencies.append(fut.result())
    wall = time.perf_counter() - t0
    latencies.sort()

    def pct(p: float) -> float:
        return latencies[min(int(len(latencies) * p), len(latencies) - 1)] * 1000

    return {
        "n": n,
        "concurrency": concurrency,
        "enable_ner": enable_ner,
        "wall_s": round(wall, 3),
        "rps": round(n / wall, 1),
        "latency_ms": {
            "p50": round(pct(0.5), 2),
            "p95": round(pct(0.95), 2),
            "p99": round(pct(0.99), 2),
            "mean": round(statistics.mean(latencies) * 1000, 2),
        },
    }


def http_process_throughput(url: str, n: int, concurrency: int) -> dict | None:
    try:
        import httpx
    except ImportError:
        return None
    payload = (
        "Клиент ivanov@mail.ru, тел +7 999 123-45-67, "
        "карта 4111 1111 1111 1111, паспорт клиента серия 4510 номер 123456"
    )

    def one(client: httpx.Client) -> float:
        pid = str(uuid.uuid4())
        t0 = time.perf_counter()
        r = client.post(
            f"{url}/process",
            json={"payload": payload, "payload_id": pid},
            timeout=30.0,
        )
        r.raise_for_status()
        masked = r.json()["result"]
        r2 = client.post(
            f"{url}/process",
            json={"payload": masked, "payload_id": pid},
            timeout=30.0,
        )
        r2.raise_for_status()
        return time.perf_counter() - t0

    latencies: list[float] = []
    try:
        with httpx.Client() as client:
            one(client)
            t0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futs = [pool.submit(one, client) for _ in range(n)]
                for fut in as_completed(futs):
                    latencies.append(fut.result())
            wall = time.perf_counter() - t0
    except Exception as e:
        return {"error": str(e), "url": url}

    latencies.sort()

    def pct(p: float) -> float:
        return latencies[min(int(len(latencies) * p), len(latencies) - 1)] * 1000

    return {
        "url": url,
        "n": n,
        "concurrency": concurrency,
        "note": "mask+demask pair counted as one op; server NER typically off",
        "wall_s": round(wall, 3),
        "rps": round(n / wall, 1),
        "latency_ms": {
            "p50": round(pct(0.5), 2),
            "p95": round(pct(0.95), 2),
            "p99": round(pct(0.99), 2),
            "mean": round(statistics.mean(latencies) * 1000, 2),
        },
        "targets": {"rps": 1000, "p95_ms": 500},
        "gap": {
            "rps_shortfall": max(0, 1000 - round(n / wall, 1)),
            "p95_over_ms": max(0, round(pct(0.95) - 500, 2)),
        },
    }


def main() -> None:
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    cases = data["cases"]
    assert len(cases) == 68, f"expected 68 cases, got {len(cases)}"

    enable_ner = os.getenv("NER_ENABLED", "1") == "1"
    print(f"Running {len(cases)} cases NER_ENABLED={enable_ner} ...", flush=True)

    # Warm NER once
    if enable_ner:
        print("Warming NER model...", flush=True)
        detect_pii("ФИО клиента: Иванов Иван Иванович", enable_ner=True)

    results = []
    for i, case in enumerate(cases, 1):
        print(f"[{i}/68] {case['id']}", flush=True)
        results.append(evaluate_case(case, enable_ner=enable_ner))

    by_type: dict[str, dict] = {}
    span_tp = span_fp = span_fn = 0
    for r in results:
        t = r["target_type"]
        bucket = by_type.setdefault(
            t,
            {
                "cases": 0,
                "passed": 0,
                "span_tp": 0,
                "span_fp": 0,
                "span_fn": 0,
                "mask_ok": 0,
                "roundtrip_ok": 0,
                "failed_ids": [],
            },
        )
        bucket["cases"] += 1
        if r["pass"]:
            bucket["passed"] += 1
        else:
            bucket["failed_ids"].append(r["id"])
        bucket["span_tp"] += len(r["tp"])
        bucket["span_fp"] += len(r["fp"])
        bucket["span_fn"] += len(r["fn"])
        span_tp += len(r["tp"])
        span_fp += len(r["fp"])
        span_fn += len(r["fn"])
        if r["mask_ok"]:
            bucket["mask_ok"] += 1
        if r["roundtrip_ok"]:
            bucket["roundtrip_ok"] += 1

    type_metrics = {}
    for t, b in by_type.items():
        m = f1(b["span_tp"], b["span_fp"], b["span_fn"])
        type_metrics[t] = {
            **b,
            **m,
            "case_pass_rate": round(b["passed"] / b["cases"], 4),
            "mask_accuracy": round(b["mask_ok"] / b["cases"], 4),
            "roundtrip_rate": round(b["roundtrip_ok"] / b["cases"], 4),
        }

    overall_cases_passed = sum(1 for r in results if r["pass"])
    latencies = [r["latency_ms"] for r in results]

    # Throughput: rules-only and NER (if enabled)
    pos_payloads = [c["payload"] for c in cases if c["kind"] != "hard_negative"]
    print("Measuring detector throughput (rules-only)...", flush=True)
    thr_rules = detector_throughput(pos_payloads, n=200, concurrency=20, enable_ner=False)
    thr_ner = None
    if enable_ner:
        print("Measuring detector throughput (NER on, smaller n)...", flush=True)
        thr_ner = detector_throughput(pos_payloads, n=40, concurrency=4, enable_ner=True)

    http_url = os.getenv("EVAL_URL", "http://127.0.0.1:8080")
    print(f"Measuring HTTP /process at {http_url}...", flush=True)
    http_thr = http_process_throughput(http_url, n=100, concurrency=20)

    # Jury gap estimate (honest, evidence-based)
    missing_types = [
        t
        for t in type_metrics
        if type_metrics[t]["recall"] == 0 and type_metrics[t]["span_fn"] > 0
    ]
    weak_types = [
        t
        for t, m in type_metrics.items()
        if m["f1"] < 0.8 and t not in missing_types
    ]

    report = {
        "version": data.get("version"),
        "cases_total": 68,
        "cases_passed": overall_cases_passed,
        "cases_failed": 68 - overall_cases_passed,
        "case_pass_rate": round(overall_cases_passed / 68, 4),
        "span_metrics": f1(span_tp, span_fp, span_fn),
        "mask_accuracy": round(sum(1 for r in results if r["mask_ok"]) / 68, 4),
        "roundtrip_rate": round(sum(1 for r in results if r["roundtrip_ok"]) / 68, 4),
        "per_case_latency_ms": {
            "p50": round(statistics.median(latencies), 2),
            "p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 2),
            "mean": round(statistics.mean(latencies), 2),
            "max": round(max(latencies), 2),
        },
        "by_type": type_metrics,
        "failed_cases": [r for r in results if not r["pass"]],
        "passed_ids": [r["id"] for r in results if r["pass"]],
        "throughput": {
            "detector_rules_only": thr_rules,
            "detector_ner": thr_ner,
            "http_process": http_thr,
        },
        "jury_gap": {
            "criterion_3_1_id_mask": {
                "max": 6,
                "estimate": None,
                "evidence": {
                    "types_17": 17,
                    "types_with_zero_recall": missing_types,
                    "types_weak_f1_lt_0_8": weak_types,
                    "case_pass": f"{overall_cases_passed}/68",
                    "mask_accuracy": round(sum(1 for r in results if r["mask_ok"]) / 68, 4),
                },
                "why": "Балл режется за систематические пропуски целых типов и неточные spans.",
            },
            "criterion_3_2_demask": {
                "max": 3,
                "estimate": None,
                "evidence": {
                    "roundtrip_rate": round(
                        sum(1 for r in results if r["roundtrip_ok"]) / 68, 4
                    )
                },
                "why": "Demask через state есть; оценка зависит от стабильного round-trip на демо.",
            },
            "criterion_3_3_precision_variations": {
                "max": 4,
                "estimate": None,
                "evidence": {
                    "span_f1": f1(span_tp, span_fp, span_fn)["f1"],
                    "hard_negatives_failed": [
                        r["id"]
                        for r in results
                        if r["kind"] == "hard_negative" and not r["pass"]
                    ],
                },
                "why": "Ловушки (Пушкин, банк-адрес, вариации) + FP на negatives.",
            },
            "criterion_3_5_perf": {
                "max": 4,
                "target": "p95<=500ms @ RPS>=1000",
                "evidence": {"http": http_thr, "rules": thr_rules, "ner": thr_ner},
                "why": "Цель жюри 1000 RPS / p95 0.5s; локальный smoke не заменяет RU-server load.",
            },
        },
        "results": results,
    }

    # Fill numeric estimates after evidence is known
    miss_n = len(missing_types)
    # Rough: full coverage ~6; each missing contextual type ~ -0.5 to -1; case fail rate cuts more
    est_31 = max(0, min(6, round(6 * (overall_cases_passed / 68) - miss_n * 0.35, 1)))
    report["jury_gap"]["criterion_3_1_id_mask"]["estimate"] = est_31
    report["jury_gap"]["criterion_3_1_id_mask"]["shortfall"] = round(6 - est_31, 1)

    rt = report["roundtrip_rate"]
    est_32 = 3 if rt >= 0.95 else (2 if rt >= 0.8 else (1 if rt >= 0.5 else 0))
    report["jury_gap"]["criterion_3_2_demask"]["estimate"] = est_32
    report["jury_gap"]["criterion_3_2_demask"]["shortfall"] = 3 - est_32

    f1_all = report["span_metrics"]["f1"]
    hn_fail = len(report["jury_gap"]["criterion_3_3_precision_variations"]["evidence"]["hard_negatives_failed"])
    est_33 = max(0, min(4, round(4 * f1_all - hn_fail * 0.15, 1)))
    report["jury_gap"]["criterion_3_3_precision_variations"]["estimate"] = est_33
    report["jury_gap"]["criterion_3_3_precision_variations"]["shortfall"] = round(4 - est_33, 1)

    http = http_thr or {}
    rps = http.get("rps") if isinstance(http, dict) else None
    p95 = (http.get("latency_ms") or {}).get("p95") if isinstance(http, dict) else None
    if rps is None:
        est_35 = 1  # architecture only
        why35 = "HTTP load не измерен или сервер недоступен → балл снижен, не 0."
    elif rps >= 1000 and p95 is not None and p95 <= 500:
        est_35 = 4
        why35 = "Цель достигнута на локальном smoke (не RU-server)."
    elif rps >= 200 and p95 is not None and p95 <= 1000:
        est_35 = 2
        why35 = f"Локально RPS≈{rps}, p95≈{p95}ms — далеко от 1000/@0.5s."
    else:
        est_35 = 1
        why35 = f"Локально RPS≈{rps}, p95≈{p95}ms — сильно ниже цели."
    report["jury_gap"]["criterion_3_5_perf"]["estimate"] = est_35
    report["jury_gap"]["criterion_3_5_perf"]["shortfall"] = 4 - est_35
    report["jury_gap"]["criterion_3_5_perf"]["why"] = why35

    OUT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n=== SUMMARY ===")
    print(f"cases: {overall_cases_passed}/68 ({report['case_pass_rate']})")
    print(f"span F1: {report['span_metrics']}")
    print(f"mask_accuracy: {report['mask_accuracy']}  roundtrip: {report['roundtrip_rate']}")
    print("per type:")
    for t, m in sorted(type_metrics.items()):
        print(
            f"  {t}: pass {m['passed']}/{m['cases']} F1={m['f1']} "
            f"P={m['precision']} R={m['recall']} fail={m['failed_ids']}"
        )
    print(f"throughput rules: {thr_rules}")
    print(f"throughput ner: {thr_ner}")
    print(f"http: {http_thr}")
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
