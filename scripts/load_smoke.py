#!/usr/bin/env python3
"""Local / RU-server load smoke for /process — Latency / RPS / TPS.

Usage (local):
  STORAGE_BACKEND=memory NER_ENABLED=0 uvicorn app.main:app --port 8080
  python scripts/load_smoke.py --url http://127.0.0.1:8080 --n 500 --concurrency 50

RU-server (after deploy):
  python scripts/load_smoke.py --url https://<ru-host> --n 2000 --concurrency 100
  python scripts/load_smoke.py --url https://<ru-host> --profile 100k --n 20 --concurrency 4

Profiles:
  default — short PII mix (~80 chars)
  2k / 32k / 256k — padded UTF-8 payloads by approximate size
  100k — ~100_000 tokens (chars/4 heuristic) with sparse PII anchors
"""

from __future__ import annotations

import argparse
import os
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

DEFAULT_PAYLOAD = (
    "Клиент ivanov@mail.ru, тел +7 999 123-45-67, "
    "карта 4111 1111 1111 1111, паспорт клиента серия 4510 номер 123456"
)

FILLER = (
    "Клиент обратился в поддержку по вопросу обслуживания счёта. "
    "Оператор уточнил детали операции и предложил проверить выписку. "
)


def build_payload(profile: str) -> tuple[str, int]:
    """Return (text, approx_token_count using chars/4)."""
    if profile == "default":
        return DEFAULT_PAYLOAD, max(len(DEFAULT_PAYLOAD) // 4, 1)
    if profile == "100k":
        target_tokens = 100_000
        target_chars = target_tokens * 4
        body = FILLER * (target_chars // len(FILLER) + 1)
        body = body[: target_chars - 120]
        body += (
            " Email клиента: user@mail.ru."
            " Телефон: +7 900 111-22-33."
            " Карта: 4111 1111 1111 1111."
        )
        return body, len(body) // 4
    size_map = {"2k": 2_000, "32k": 32_000, "256k": 256_000}
    if profile not in size_map:
        raise SystemExit(f"unknown profile {profile}")
    n = size_map[profile]
    body = (FILLER * (n // len(FILLER) + 1))[: n - 80]
    body += " Контакт: a@b.ru +7 900 111-22-33"
    return body, len(body) // 4


def _post_with_retry(
    client: httpx.Client,
    url: str,
    *,
    payload: str,
    payload_id: str,
    headers: dict[str, str],
) -> tuple[httpx.Response, int]:
    throttles = 0
    for attempt in range(3):
        r = client.post(
            f"{url}/process",
            json={"payload": payload, "payload_id": payload_id},
            headers=headers,
        )
        if r.status_code != 429:
            r.raise_for_status()
            return r, throttles
        throttles += 1
        if attempt < 2:
            try:
                delay = float(r.headers.get("Retry-After", "0.05"))
            except ValueError:
                delay = 0.05
            time.sleep(min(max(delay, 0.01), 1.0))
    r.raise_for_status()
    raise RuntimeError("unreachable")


def one_call(
    client: httpx.Client,
    url: str,
    payload: str,
    *,
    demask: bool,
) -> tuple[float, int]:
    pid = str(uuid.uuid4())
    headers = {}
    api_key = os.getenv("PROXY_API_KEYS", "").split(",")[0].strip()
    if api_key:
        headers["X-API-Key"] = api_key
    t0 = time.perf_counter()
    r, throttles = _post_with_retry(
        client, url, payload=payload, payload_id=pid, headers=headers
    )
    if demask:
        masked = r.json()["result"]
        _, demask_throttles = _post_with_retry(
            client, url, payload=masked, payload_id=pid, headers=headers
        )
        throttles += demask_throttles
    return time.perf_counter() - t0, throttles


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument(
        "--profile",
        default="default",
        choices=["default", "2k", "32k", "256k", "100k"],
    )
    ap.add_argument(
        "--mode",
        default="pair",
        choices=["pair", "create"],
        help="pair=mask+demask as one op; create=mask only",
    )
    args = ap.parse_args()

    payload, approx_tokens = build_payload(args.profile)
    demask = args.mode == "pair"
    latencies: list[float] = []
    errors = 0
    throttles = 0

    limits = httpx.Limits(max_connections=200, max_keepalive_connections=100)
    with httpx.Client(timeout=120.0, limits=limits) as client:
        one_call(client, args.url, payload, demask=demask)
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futs = [
                pool.submit(one_call, client, args.url, payload, demask=demask)
                for _ in range(args.n)
            ]
            for f in as_completed(futs):
                try:
                    latency, call_throttles = f.result()
                    latencies.append(latency)
                    throttles += call_throttles
                except Exception:
                    errors += 1
        total = time.perf_counter() - t0

    if not latencies:
        raise SystemExit(f"all requests failed errors={errors}")
    latencies.sort()

    def pct(p: float) -> float:
        idx = min(int(len(latencies) * p), len(latencies) - 1)
        return latencies[idx] * 1000

    ok = len(latencies)
    op_rps = ok / total
    http_requests = ok * (2 if demask else 1)
    http_rps = http_requests / total
    tps = op_rps * approx_tokens
    print(
        f"profile={args.profile} mode={args.mode} n={args.n} ok={ok} errors={errors} "
        f"concurrency={args.concurrency} url={args.url}"
    )
    print(
        f"payload_chars={len(payload)} approx_tokens={approx_tokens} "
        f"(tokenizer=chars/4 heuristic)"
    )
    print(
        f"wall={total:.3f}s  op_RPS≈{op_rps:.1f}  http_RPS≈{http_rps:.1f} "
        f"TPS≈{tps:.0f}  429_retries={throttles}"
    )
    print(
        f"latency_ms: p50={pct(0.50):.1f} p95={pct(0.95):.1f} p99={pct(0.99):.1f} "
        f"mean={statistics.mean(latencies)*1000:.1f}"
    )
    print(
        "Targets: HTTP RPS≥1000, p95≤500ms (jury). "
        "RU-server: re-run this script against the deployed URL; local numbers are not evidence."
    )


if __name__ == "__main__":
    main()
