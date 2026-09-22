#!/usr/bin/env python3
"""Local load smoke for /process — prints Latency/RPS/TPS estimates.

Usage:
  uvicorn app.main:app --port 8080
  python scripts/load_smoke.py --url http://127.0.0.1:8080 --n 200 --concurrency 20
"""

from __future__ import annotations

import argparse
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx


PAYLOAD = (
    "Клиент ivanov@mail.ru, тел +7 999 123-45-67, "
    "карта 4111 1111 1111 1111, паспорт клиента серия 4510 номер 123456"
)


def one_call(client: httpx.Client, url: str) -> float:
    pid = str(uuid.uuid4())
    t0 = time.perf_counter()
    r = client.post(f"{url}/process", json={"payload": PAYLOAD, "payload_id": pid}, timeout=30.0)
    r.raise_for_status()
    # demask
    masked = r.json()["result"]
    r2 = client.post(f"{url}/process", json={"payload": masked, "payload_id": pid}, timeout=30.0)
    r2.raise_for_status()
    return time.perf_counter() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--concurrency", type=int, default=10)
    args = ap.parse_args()

    latencies: list[float] = []
    t0 = time.perf_counter()
    with httpx.Client() as client:
        # warmup
        one_call(client, args.url)
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futs = [pool.submit(one_call, client, args.url) for _ in range(args.n)]
            for f in as_completed(futs):
                latencies.append(f.result())
    total = time.perf_counter() - t0
    latencies.sort()

    def pct(p: float) -> float:
        idx = min(int(len(latencies) * p), len(latencies) - 1)
        return latencies[idx] * 1000

    rps = args.n / total
    avg_tokens = len(PAYLOAD) / 4
    tps = rps * avg_tokens
    print(f"n={args.n} concurrency={args.concurrency} url={args.url}")
    print(f"wall={total:.3f}s  RPS≈{rps:.1f}  TPS≈{tps:.0f}")
    print(
        f"latency_ms: p50={pct(0.50):.1f} p95={pct(0.95):.1f} p99={pct(0.99):.1f} "
        f"mean={statistics.mean(latencies)*1000:.1f}"
    )
    print("Note: local smoke only; RU-server load must be run on the deployment host.")


if __name__ == "__main__":
    main()
