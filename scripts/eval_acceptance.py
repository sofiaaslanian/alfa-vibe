#!/usr/bin/env python3
"""Run Dani's 68 acceptance cases + local latency/throughput smoke.

Reports exact-span TP/FP/FN per type, mask accuracy, round-trip, and timing.
Does not mutate expected spans/results to pass.
"""

from __future__ import annotations

import json
import os
import re
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
        if getattr(f, "decision", "mask") != "mask":
            continue  # ALLOW ≠ expected masked span
        ct = canonical(f.type)
        at = to_acceptance_type(f.type)
        if ct in want or at in want or f.type in want:
            out.append(f)
    return out


def span_key(typ: str, start: int, end: int) -> tuple[str, int, int]:
    return (to_acceptance_type(typ), start, end)


# Baseline fixtures often list one composite span; detector may emit parts.
COMPOSITE_ACCEPT = {
    "PERSON_NAME",
    "ADDRESS",
    "CARDHOLDER_NAME",
    "PASSPORT_NUMBER",
    "DRIVER_LICENSE_NUMBER",
}

_ADDR_LABEL_RE = re.compile(
    r"(?i)\b(?:ул|улица|пр|пр\-т|проспект|пер|переулок|ш|шоссе|б\-р|бульвар|"
    r"наб|пл|площадь|д|дом|кв|квартира|корп|корпус|стр|г|город)\b\.?"
)


def _alnum_offsets(text: str, start: int, end: int, *, typ: str = "") -> set[int]:
    need = {i for i in range(start, end) if text[i].isalnum()}
    if typ != "ADDRESS":
        return need
    # Labels «ул.»/«д.» are intentional leftovers (org: excess if masked).
    for m in _ADDR_LABEL_RE.finditer(text[start:end]):
        for i in range(start + m.start(), start + m.end()):
            need.discard(i)
    return need


def _cover_expected_composites(
    text: str,
    fn_candidates: set[tuple[str, int, int]],
    fp_candidates: set[tuple[str, int, int]],
) -> tuple[list[tuple[str, int, int]], set[tuple[str, int, int]], list[tuple[str, int, int]]]:
    still_fn: list[tuple[str, int, int]] = []
    covered_got: set[tuple[str, int, int]] = set()
    promoted_tp: list[tuple[str, int, int]] = []
    for typ, start, end in sorted(fn_candidates):
        need = _alnum_offsets(text, start, end, typ=typ)
        parts = [
            got
            for got in fp_candidates
            if got[0] == typ and got[1] >= start and got[2] <= end
        ]
        covered = set().union(
            *(_alnum_offsets(text, part_start, part_end, typ=typ)
              for _, part_start, part_end in parts)
        ) if parts else set()
        is_covered = typ in COMPOSITE_ACCEPT and bool(need) and need <= covered
        if is_covered:
            promoted_tp.append((typ, start, end))
            covered_got.update(parts)
        else:
            still_fn.append((typ, start, end))
    return still_fn, covered_got, promoted_tp


def _remaining_false_positives(
    expected: list[tuple[str, int, int]],
    fp_candidates: set[tuple[str, int, int]],
    covered_got: set[tuple[str, int, int]],
) -> list[tuple[str, int, int]]:
    out: list[tuple[str, int, int]] = []
    for finding in sorted(fp_candidates - covered_got):
        typ, start, end = finding
        inside_expected = (
            typ in COMPOSITE_ACCEPT
            and any(
                exp_type == typ and start >= exp_start and end <= exp_end
                for exp_type, exp_start, exp_end in expected
            )
        )
        if not inside_expected:
            out.append(finding)
    return out


def match_spans(
    text: str,
    expected: list[tuple[str, int, int]],
    got: list[tuple[str, int, int]],
) -> tuple[list, list, list]:
    """Exact match, with composite cover: parts may replace one baseline span."""
    exp_set = set(expected)
    got_set = set(got)
    tp = sorted(exp_set & got_set)
    fp_candidates = got_set - exp_set
    fn_candidates = exp_set - got_set

    still_fn, covered_got, promoted_tp = _cover_expected_composites(
        text,
        fn_candidates,
        fp_candidates,
    )
    tp.extend(promoted_tp)
    still_fp = _remaining_false_positives(expected, fp_candidates, covered_got)
    return sorted(set(tp)), still_fp, still_fn


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

    tp, fp, fn = match_spans(text, expected, got)

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
    headers = {}
    api_key = os.getenv("PROXY_API_KEYS", "").split(",")[0].strip()
    if api_key:
        headers["X-API-Key"] = api_key

    def one(client: httpx.Client) -> float:
        pid = str(uuid.uuid4())
        t0 = time.perf_counter()
        r = client.post(
            f"{url}/process",
            json={"payload": payload, "payload_id": pid},
            headers=headers,
            timeout=30.0,
        )
        r.raise_for_status()
        masked = r.json()["result"]
        r2 = client.post(
            f"{url}/process",
            json={"payload": masked, "payload_id": pid},
            headers=headers,
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


def _run_cases(cases: list[dict], enable_ner: bool) -> list[dict]:
    if enable_ner:
        print("Warming NER model...", flush=True)
        detect_pii("ФИО клиента: Иванов Иван Иванович", enable_ner=True)

    results: list[dict] = []
    for index, case in enumerate(cases, 1):
        print(f"[{index}/68] {case['id']}", flush=True)
        results.append(evaluate_case(case, enable_ner=enable_ner))
    return results


def _empty_type_bucket() -> dict:
    return {
        "cases": 0,
        "passed": 0,
        "span_tp": 0,
        "span_fp": 0,
        "span_fn": 0,
        "mask_ok": 0,
        "roundtrip_ok": 0,
        "failed_ids": [],
    }


def _aggregate_results(results: list[dict]) -> tuple[dict[str, dict], int, int, int]:
    by_type: dict[str, dict] = {}
    span_tp = span_fp = span_fn = 0
    for result in results:
        bucket = by_type.setdefault(result["target_type"], _empty_type_bucket())
        bucket["cases"] += 1
        bucket["passed"] += int(result["pass"])
        if not result["pass"]:
            bucket["failed_ids"].append(result["id"])
        bucket["span_tp"] += len(result["tp"])
        bucket["span_fp"] += len(result["fp"])
        bucket["span_fn"] += len(result["fn"])
        bucket["mask_ok"] += int(result["mask_ok"])
        bucket["roundtrip_ok"] += int(result["roundtrip_ok"])
        span_tp += len(result["tp"])
        span_fp += len(result["fp"])
        span_fn += len(result["fn"])
    return by_type, span_tp, span_fp, span_fn


def _type_metrics(by_type: dict[str, dict]) -> dict[str, dict]:
    metrics: dict[str, dict] = {}
    for typ, bucket in by_type.items():
        span_metrics = f1(bucket["span_tp"], bucket["span_fp"], bucket["span_fn"])
        metrics[typ] = {
            **bucket,
            **span_metrics,
            "case_pass_rate": round(bucket["passed"] / bucket["cases"], 4),
            "mask_accuracy": round(bucket["mask_ok"] / bucket["cases"], 4),
            "roundtrip_rate": round(bucket["roundtrip_ok"] / bucket["cases"], 4),
        }
    return metrics


def _measure_throughput(cases: list[dict], enable_ner: bool) -> tuple[dict, dict | None, dict]:
    positive_payloads = [case["payload"] for case in cases if case["kind"] != "hard_negative"]
    print("Measuring detector throughput (rules-only)...", flush=True)
    rules = detector_throughput(positive_payloads, n=200, concurrency=20, enable_ner=False)

    ner = None
    if enable_ner:
        print("Measuring detector throughput (NER on, smaller n)...", flush=True)
        ner = detector_throughput(positive_payloads, n=40, concurrency=4, enable_ner=True)

    http_url = os.getenv("EVAL_URL", "http://127.0.0.1:8080")
    print(f"Measuring HTTP /process at {http_url}...", flush=True)
    http = http_process_throughput(http_url, n=100, concurrency=20)
    return rules, ner, http


def _jury_type_lists(type_metrics: dict[str, dict]) -> tuple[list[str], list[str]]:
    missing = [
        typ
        for typ, metrics in type_metrics.items()
        if metrics["recall"] == 0 and metrics["span_fn"] > 0
    ]
    weak = [
        typ
        for typ, metrics in type_metrics.items()
        if metrics["f1"] < 0.8 and typ not in missing
    ]
    return missing, weak


def _build_report(
    data: dict,
    results: list[dict],
    type_metrics: dict[str, dict],
    spans: tuple[int, int, int],
    throughput: tuple[dict, dict | None, dict],
) -> dict:
    span_tp, span_fp, span_fn = spans
    thr_rules, thr_ner, http_thr = throughput
    passed = sum(1 for result in results if result["pass"])
    latencies = [result["latency_ms"] for result in results]
    missing_types, weak_types = _jury_type_lists(type_metrics)
    mask_accuracy = round(sum(1 for result in results if result["mask_ok"]) / 68, 4)
    roundtrip_rate = round(sum(1 for result in results if result["roundtrip_ok"]) / 68, 4)
    hard_negative_failures = [
        result["id"]
        for result in results
        if result["kind"] == "hard_negative" and not result["pass"]
    ]

    return {
        "version": data.get("version"),
        "cases_total": 68,
        "cases_passed": passed,
        "cases_failed": 68 - passed,
        "case_pass_rate": round(passed / 68, 4),
        "span_metrics": f1(span_tp, span_fp, span_fn),
        "mask_accuracy": mask_accuracy,
        "roundtrip_rate": roundtrip_rate,
        "per_case_latency_ms": {
            "p50": round(statistics.median(latencies), 2),
            "p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 2),
            "mean": round(statistics.mean(latencies), 2),
            "max": round(max(latencies), 2),
        },
        "by_type": type_metrics,
        "failed_cases": [result for result in results if not result["pass"]],
        "passed_ids": [result["id"] for result in results if result["pass"]],
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
                    "case_pass": f"{passed}/68",
                    "mask_accuracy": mask_accuracy,
                },
                "why": "Балл режется за систематические пропуски целых типов и неточные spans.",
            },
            "criterion_3_2_demask": {
                "max": 3,
                "estimate": None,
                "evidence": {"roundtrip_rate": roundtrip_rate},
                "why": "Demask через state есть; оценка зависит от стабильного round-trip на демо.",
            },
            "criterion_3_3_precision_variations": {
                "max": 4,
                "estimate": None,
                "evidence": {
                    "span_f1": f1(span_tp, span_fp, span_fn)["f1"],
                    "hard_negatives_failed": hard_negative_failures,
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


def _perf_estimate(http_thr: dict) -> tuple[int, str]:
    rps = http_thr.get("rps") if isinstance(http_thr, dict) else None
    p95 = (http_thr.get("latency_ms") or {}).get("p95") if isinstance(http_thr, dict) else None
    if rps is None:
        return 1, "HTTP load не измерен или сервер недоступен → балл снижен, не 0."
    if rps >= 1000 and p95 is not None and p95 <= 500:
        return 4, "Цель достигнута на локальном smoke (не RU-server)."
    if rps >= 200 and p95 is not None and p95 <= 1000:
        return 2, f"Локально RPS≈{rps}, p95≈{p95}ms — далеко от 1000/@0.5s."
    return 1, f"Локально RPS≈{rps}, p95≈{p95}ms — сильно ниже цели."


def _fill_jury_estimates(report: dict) -> None:
    jury = report["jury_gap"]
    missing_n = len(jury["criterion_3_1_id_mask"]["evidence"]["types_with_zero_recall"])
    est_31 = max(0, min(6, round(6 * report["case_pass_rate"] - missing_n * 0.35, 1)))
    jury["criterion_3_1_id_mask"].update(estimate=est_31, shortfall=round(6 - est_31, 1))

    roundtrip = report["roundtrip_rate"]
    est_32 = 3 if roundtrip >= 0.95 else (2 if roundtrip >= 0.8 else (1 if roundtrip >= 0.5 else 0))
    jury["criterion_3_2_demask"].update(estimate=est_32, shortfall=3 - est_32)

    hn_failures = len(jury["criterion_3_3_precision_variations"]["evidence"]["hard_negatives_failed"])
    est_33 = max(0, min(4, round(4 * report["span_metrics"]["f1"] - hn_failures * 0.15, 1)))
    jury["criterion_3_3_precision_variations"].update(
        estimate=est_33,
        shortfall=round(4 - est_33, 1),
    )

    est_35, why_35 = _perf_estimate(report["throughput"]["http_process"])
    jury["criterion_3_5_perf"].update(
        estimate=est_35,
        shortfall=4 - est_35,
        why=why_35,
    )


def _print_summary(report: dict) -> None:
    print("\n=== SUMMARY ===")
    print(f"cases: {report['cases_passed']}/68 ({report['case_pass_rate']})")
    print(f"span F1: {report['span_metrics']}")
    print(f"mask_accuracy: {report['mask_accuracy']}  roundtrip: {report['roundtrip_rate']}")
    print("per type:")
    for typ, metrics in sorted(report["by_type"].items()):
        print(
            f"  {typ}: pass {metrics['passed']}/{metrics['cases']} F1={metrics['f1']} "
            f"P={metrics['precision']} R={metrics['recall']} fail={metrics['failed_ids']}"
        )
    throughput = report["throughput"]
    print(f"throughput rules: {throughput['detector_rules_only']}")
    print(f"throughput ner: {throughput['detector_ner']}")
    print(f"http: {throughput['http_process']}")
    print(f"wrote {OUT_PATH}")


def main() -> None:
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    cases = data["cases"]
    assert len(cases) == 68, f"expected 68 cases, got {len(cases)}"

    enable_ner = os.getenv("NER_ENABLED", "1") == "1"
    print(f"Running {len(cases)} cases NER_ENABLED={enable_ner} ...", flush=True)
    results = _run_cases(cases, enable_ner)
    by_type, span_tp, span_fp, span_fn = _aggregate_results(results)
    metrics = _type_metrics(by_type)
    throughput = _measure_throughput(cases, enable_ner)
    report = _build_report(
        data,
        results,
        metrics,
        (span_tp, span_fp, span_fn),
        throughput,
    )
    _fill_jury_estimates(report)
    OUT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_summary(report)


if __name__ == "__main__":
    main()
