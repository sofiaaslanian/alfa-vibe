#!/usr/bin/env python3
"""Profile ProcessService stages without HTTP client overhead."""

from __future__ import annotations

import json
import os
import time
import uuid

from app.config import load_config
from app.process import ProcessService
from app.state import build_store
from scripts.load_smoke import build_payload


def main() -> None:
    cfg = load_config(os.getenv("CONFIG_PATH", "config.yaml"))
    store = build_store()
    svc = ProcessService(cfg, store)
    payload, approx_tokens = build_payload("100k")
    pid = f"profile-{uuid.uuid4()}"

    trace_mask: dict[str, object] = {}
    t0 = time.perf_counter()
    masked = svc.process(payload, pid, trace=trace_mask)
    wall_mask = (time.perf_counter() - t0) * 1000

    trace_demask: dict[str, object] = {}
    t0 = time.perf_counter()
    restored = svc.process(masked, pid, trace=trace_demask)
    wall_demask = (time.perf_counter() - t0) * 1000

    live = store.get_live("autotest", pid)
    state_bytes = len(live.to_json().encode("utf-8")) if live else None

    print(
        json.dumps(
            {
                "profile": "100k",
                "chars": len(payload),
                "approx_tokens": approx_tokens,
                "mask_wall_ms": round(wall_mask, 2),
                "demask_wall_ms": round(wall_demask, 2),
                "mask_trace": trace_mask,
                "demask_trace": trace_demask,
                "state_bytes": state_bytes,
                "roundtrip_ok": restored == payload,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
