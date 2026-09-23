#!/usr/bin/env python3
"""Run reconstructed 170 stage-1 cases against the public /demo/run endpoint.

Uses the hybrid ML + rules path (demo system, context ML on) to match the
stage-1 report methodology. Positive passes when target type is present among
mask-findings; negative passes when absent.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from collections import defaultdict

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://alfagen.tech"
API_KEY = sys.argv[2] if len(sys.argv) > 2 else "demo-key"

# Reuse the case list from the local eval script.
sys.path.insert(0, ".")
from scripts.eval_stage1_170 import CASES  # noqa: E402


def run_case(text: str) -> list[dict]:
    body = json.dumps({"text": text, "skip_llm": True}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}/demo/run",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
            "X-System": "demo",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("findings", [])


def main() -> None:
    by_type: dict[str, dict] = defaultdict(
        lambda: {"pos": 0, "neg": 0, "pos_ok": 0, "neg_ok": 0, "errors": []}
    )
    total_ok = 0

    for i, (typ, text, is_pos) in enumerate(CASES, 1):
        try:
            findings = run_case(text)
        except Exception as e:
            print(f"[{i}/170] {typ}: HTTP ERROR {e}", flush=True)
            continue
        has_type = any(
            f.get("type") == typ and f.get("decision", "mask") == "mask"
            for f in findings
        )
        ok = has_type if is_pos else not has_type
        bucket = by_type[typ]
        if is_pos:
            bucket["pos"] += 1
            if ok:
                bucket["pos_ok"] += 1
            else:
                bucket["errors"].append(("FN", text))
        else:
            bucket["neg"] += 1
            if ok:
                bucket["neg_ok"] += 1
            else:
                bucket["errors"].append(("FP", text))
        if ok:
            total_ok += 1

    print(f"=== STAGE-1 RECONSTRUCTED 170 CASES (via {BASE}) ===")
    print(f"Total: {total_ok}/170 = {total_ok/170*100:.1f}%")
    print(f"Errors: {170-total_ok}")
    print()
    print(f"{'Type':<20}{'Pos':>5}{'Neg':>5}{'PosOK':>7}{'NegOK':>7}{'Total':>7}")
    for typ in sorted(by_type):
        b = by_type[typ]
        t = b["pos_ok"] + b["neg_ok"]
        print(f"{typ:<20}{b['pos']:>5}{b['neg']:>5}{b['pos_ok']:>7}{b['neg_ok']:>7}{t:>7}/10")
    print()
    print("=== ERRORS ===")
    for typ in sorted(by_type):
        for kind, text in by_type[typ]["errors"]:
            print(f"  [{typ}] {kind}: {text}")


if __name__ == "__main__":
    main()