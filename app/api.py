"""HTTP API: /process, /proxy, /health, /ready, /metrics, demo UI."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.config import Config, load_config
from app.crypto_util import decrypt
from app.llm import AlfaGenClient
from app.masking import restore_scoped_tokens
from app.process import ProcessError, ProcessService
from app.state import build_store

log = logging.getLogger("alfa.api")
log.setLevel(logging.INFO)

ROOT = Path(__file__).resolve().parents[1]
UI_DIR = ROOT / "ui"
DOCS_DIR = ROOT / "docs"

LATENCY = Histogram("alfa_process_latency_seconds", "Latency", ["route", "mode"])
RPS = Counter("alfa_process_total", "Total requests", ["route", "mode", "status"])
TPS = Counter("alfa_tokens_total", "Estimated tokens", ["route"])

# Sync load clients ≈200; reject excess with 429 (not an SLA error per org Q&A).
_process_sem: asyncio.Semaphore | None = None


def _process_semaphore() -> asyncio.Semaphore:
    global _process_sem
    if _process_sem is None:
        _process_sem = asyncio.Semaphore(int(os.getenv("PROCESS_CONCURRENCY", "48")))
    return _process_sem


class ProcessRequest(BaseModel):
    payload: str = Field(...)
    payload_id: str = Field(..., min_length=1)


class ProcessResponse(BaseModel):
    result: str


class ProxyRequest(BaseModel):
    text: str = Field(..., min_length=1)
    operation_id: str | None = None


class ProxyResponse(BaseModel):
    operation_id: str
    masked_prompt: str
    answer: str
    restored: str | None = None


class DemoRunRequest(BaseModel):
    text: str = Field(..., min_length=1)
    skip_llm: bool = False
    operation_id: str | None = None


class HealthResponse(BaseModel):
    status: str
    systems: int
    pd_types: int
    storage: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = load_config(os.getenv("CONFIG_PATH", "config.yaml"))
    store = build_store()
    app.state.config = cfg
    app.state.store = store
    app.state.process = ProcessService(cfg, store)
    app.state.llm = AlfaGenClient()
    if os.getenv("NER_ENABLED", "0") == "1":
        from app.pii.detect import get_ner

        ner = get_ner()
        try:
            if ner.use_local and not ner.base_url:
                ner._ensure_local()
        except Exception:
            log.exception("NER preload failed")
    log.info("started storage=%s systems=%d", os.getenv("STORAGE_BACKEND", "memory"), len(cfg.systems))
    yield


app = FastAPI(title="Alfa PD Security Module", version="1.2.0", lifespan=lifespan)


def _system(request: Request, x_system: str | None) -> str:
    return x_system or request.headers.get("X-System", "") or ""


def _check_system(cfg: Config, system: str, *, required: bool = False) -> str:
    """Return effective system name. Unknown systems ignored on /process (org: no header)."""
    if not system:
        if required:
            raise HTTPException(403, "X-System required")
        return ""
    if system not in cfg.systems or not cfg.systems[system].enabled:
        if required:
            raise HTTPException(403, f"System '{system}' not allowed")
        return ""  # autotest: ignore junk X-System
    return system


def _api_key_ok(x_api_key: str | None) -> bool:
    expected = os.getenv("PROXY_API_KEYS", "")
    if not expected:
        return True
    allowed = {k.strip() for k in expected.split(",") if k.strip()}
    return bool(x_api_key and x_api_key in allowed)


def _read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        log.exception("failed to read %s", path)
        return None


def _open_pii_leaked(text: str, findings: list, masked: str) -> list[str]:
    """Open spans that were supposed to be masked but remain in the LLM prompt."""
    leaked = []
    for f in findings:
        if getattr(f, "decision", "mask") != "mask":
            continue
        value = text[f.start : f.end]
        if len(value) >= 3 and value in masked:
            leaked.append(value)
    return leaked


@app.post("/process", response_model=ProcessResponse)
async def process(
    request: Request,
    body: ProcessRequest,
    x_system: str | None = Header(default=None, alias="X-System"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    # Org Q&A: /process autotest does NOT require API key / consumer auth.
    # Keep x_api_key in signature for compatibility; ignore it here.
    _ = x_api_key
    cfg: Config = request.app.state.config
    svc: ProcessService = request.app.state.process
    system = _check_system(cfg, _system(request, x_system), required=False)

    sem = _process_semaphore()
    try:
        await asyncio.wait_for(sem.acquire(), timeout=0.002)
    except TimeoutError:
        RPS.labels(route="process", mode="reject", status="429").inc()
        return JSONResponse(
            status_code=429,
            content={"detail": "overloaded"},
            headers={"Retry-After": "1"},
        )

    start = time.perf_counter()
    mode = "unknown"
    status = "200"
    try:
        trace: dict[str, object] = {}
        result = await asyncio.to_thread(
            svc.process,
            body.payload,
            body.payload_id,
            system or None,
            trace=trace,
        )
        mode = str(trace.get("mode", mode))
        log.info(
            json.dumps(
                {
                    "event": "process",
                    "payload_id_hash": hashlib.sha256(body.payload_id.encode("utf-8")).hexdigest()[:12],
                    "system": system or "autotest",
                    "mode": trace.get("mode", mode),
                    "types": trace.get("types", []),
                    "findings": trace.get("findings", 0),
                    "detect_ms": trace.get("detect_ms", 0.0),
                    "mask_ms": trace.get("mask_ms", 0.0),
                    "state_ms": trace.get("state_ms", 0.0),
                    "total_ms": trace.get("total_ms", 0.0),
                    "mask_style": trace.get("mask_style", ""),
                    "payload_chars": len(body.payload),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return ProcessResponse(result=result)
    except ProcessError as exc:
        status = str(exc.status)
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    except Exception as exc:
        status = "503"
        log.exception("process failed")
        raise HTTPException(503, "storage or detection unavailable") from exc
    finally:
        sem.release()
        LATENCY.labels(route="process", mode=mode).observe(time.perf_counter() - start)
        RPS.labels(route="process", mode=mode, status=status).inc()
        TPS.labels(route="process").inc(max(len(body.payload) / 4, 1))


@app.post("/proxy/chat", response_model=ProxyResponse)
async def proxy_chat(
    request: Request,
    body: ProxyRequest,
    x_system: str | None = Header(default=None, alias="X-System"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_consumer_id: str | None = Header(default=None, alias="X-Consumer-Id"),
):
    if not _api_key_ok(x_api_key):
        raise HTTPException(401, "invalid API key")

    cfg: Config = request.app.state.config
    svc: ProcessService = request.app.state.process
    llm: AlfaGenClient = request.app.state.llm

    system = _system(request, x_system) or "demo"
    _check_system(cfg, system, required=True)
    consumer = x_consumer_id or system
    op_id = body.operation_id or str(uuid.uuid4())

    start = time.perf_counter()
    status = "200"
    try:
        masked, _state = svc.proxy_protect(
            body.text, consumer_id=consumer, operation_id=op_id, system=system
        )
        answer = llm.chat(masked)
        restored = None
        sys_cfg = cfg.systems[system]
        if sys_cfg.allow_demask:
            restored = svc.proxy_restore(
                answer, consumer_id=consumer, operation_id=op_id, system=system
            )
        return ProxyResponse(
            operation_id=op_id,
            masked_prompt=masked,
            answer=answer,
            restored=restored,
        )
    except ProcessError as exc:
        status = str(exc.status)
        raise HTTPException(exc.status, exc.detail) from exc
    except HTTPException:
        raise
    except Exception as exc:
        status = "502"
        log.exception("proxy failed")
        raise HTTPException(502, "LLM or protection path failed") from exc
    finally:
        LATENCY.labels(route="proxy", mode="chat").observe(time.perf_counter() - start)
        RPS.labels(route="proxy", mode="chat", status=status).inc()
        TPS.labels(route="proxy").inc(max(len(body.text) / 4, 1))


@app.post("/demo/run")
async def demo_run(
    request: Request,
    body: DemoRunRequest,
    x_system: str | None = Header(default=None, alias="X-System"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_consumer_id: str | None = Header(default=None, alias="X-Consumer-Id"),
):
    """Pipeline x-ray for Contour UI: DETECT → MASK → LLM → DEMASK."""
    if not _api_key_ok(x_api_key):
        raise HTTPException(401, "invalid API key")

    cfg: Config = request.app.state.config
    svc: ProcessService = request.app.state.process
    llm: AlfaGenClient = request.app.state.llm

    system = _system(request, x_system) or "demo"
    _check_system(cfg, system, required=True)
    consumer = x_consumer_id or "demo-ui"
    op_id = body.operation_id or str(uuid.uuid4())

    stages_ms: dict[str, float] = {}
    t_all = time.perf_counter()

    t0 = time.perf_counter()
    findings = svc.detect(body.text, system)
    stages_ms["detect"] = round((time.perf_counter() - t0) * 1000, 2)

    t0 = time.perf_counter()
    try:
        masked, state = svc.proxy_protect(
            body.text, consumer_id=consumer, operation_id=op_id, system=system
        )
    except ProcessError as exc:
        raise HTTPException(exc.status, exc.detail) from exc
    stages_ms["mask"] = round((time.perf_counter() - t0) * 1000, 2)
    stages_ms["state"] = stages_ms["mask"]

    leaked = _open_pii_leaked(body.text, findings, masked)

    answer = None
    llm_status = "skipped"
    t0 = time.perf_counter()
    use_llm = not body.skip_llm and bool(llm.api_key) and llm.api_key != "your-key-here"
    if use_llm:
        try:
            answer = llm.chat(masked)
            llm_status = "ok"
        except Exception as exc:
            log.warning("demo LLM failed: %s", exc)
            answer = None
            llm_status = f"error:{exc.__class__.__name__}"
    else:
        llm_status = "skipped_no_key" if not body.skip_llm else "skipped_by_flag"
        answer = (
            "[LLM пропущен — контур защиты показан без вызова модели. "
            "В masked_prompt не должно быть открытых ПД.]"
        )
    stages_ms["llm"] = round((time.perf_counter() - t0) * 1000, 2)

    restored = None
    t0 = time.perf_counter()
    sys_cfg = cfg.systems[system]
    if sys_cfg.allow_demask:
        try:
            aad = f"proxy:{consumer}:{op_id}"
            mapping = (
                json.loads(decrypt(state.tokens_enc, aad)) if state.tokens_enc else {}
            )
            if answer and "⟦PII_" in answer:
                restored = restore_scoped_tokens(answer, mapping)
            else:
                # Prove demask: masked wire → original
                restored = restore_scoped_tokens(masked, mapping)
        except Exception:
            log.exception("demo demask failed")
            restored = None
    stages_ms["demask"] = round((time.perf_counter() - t0) * 1000, 2)
    stages_ms["total"] = round((time.perf_counter() - t_all) * 1000, 2)

    LATENCY.labels(route="demo", mode="run").observe(stages_ms["total"] / 1000.0)
    RPS.labels(route="demo", mode="run", status="200").inc()
    TPS.labels(route="demo").inc(max(len(body.text) / 4, 1))

    return {
        "operation_id": op_id,
        "system": system,
        "original": body.text,
        "findings": [
            {
                "type": f.type,
                "start": f.start,
                "end": f.end,
                "value": body.text[f.start : f.end],
                "score": f.score,
                "detector": f.detector,
                "decision": getattr(f, "decision", "mask") or "mask",
                "reason": getattr(f, "reason", "") or "",
                **({"part": f.part} if getattr(f, "part", "") else {}),
            }
            for f in findings
        ],
        "masked_prompt": masked,
        "answer": answer,
        "restored": restored,
        "llm_status": llm_status,
        "open_pii_in_llm": leaked,
        "leak_free": len(leaked) == 0,
        "stages_ms": stages_ms,
        "mask_strategy": state.mask_strategy,
        "roundtrip_ok": restored == body.text,
    }


@app.get("/demo/config")
async def demo_config(request: Request):
    cfg: Config = request.app.state.config
    return {
        "systems": {
            name: {
                "enabled": s.enabled,
                "pd_types": s.pd_types or cfg.default_pd_types,
                "allow_demask": s.allow_demask,
                "mask_style": s.mask_style,
            }
            for name, s in cfg.systems.items()
            if s.enabled
        },
        "default_pd_types": cfg.default_pd_types,
        "storage": os.getenv("STORAGE_BACKEND", "memory"),
        "ner_enabled": os.getenv("NER_ENABLED", "0") == "1",
        "proxy_key_required": bool(os.getenv("PROXY_API_KEYS", "").strip()),
    }


@app.get("/demo/evidence")
async def demo_evidence():
    eval_raw = _read_json(DOCS_DIR / "acceptance_summary.json") or _read_json(
        DOCS_DIR / "acceptance_eval_report.json"
    )
    holdout_raw = _read_json(DOCS_DIR / "holdout_cases.json")
    eval_summary = None
    if isinstance(eval_raw, dict):
        # already slim or full report
        if "by_type" in eval_raw and "cases_total" in eval_raw:
            if eval_raw.get("span_metrics") is not None:
                eval_summary = {
                    "cases_total": eval_raw.get("cases_total"),
                    "cases_passed": eval_raw.get("cases_passed"),
                    "case_pass_rate": eval_raw.get("case_pass_rate"),
                    "span_metrics": eval_raw.get("span_metrics"),
                    "mask_accuracy": eval_raw.get("mask_accuracy"),
                    "roundtrip_rate": eval_raw.get("roundtrip_rate"),
                    "by_type": {
                        k: {
                            "passed": v.get("passed"),
                            "cases": v.get("cases"),
                            "f1": v.get("f1"),
                            "failed_ids": v.get("failed_ids"),
                        }
                        for k, v in (eval_raw.get("by_type") or {}).items()
                    },
                }
    holdout_n = 0
    if isinstance(holdout_raw, dict):
        holdout_n = len(holdout_raw.get("cases") or [])
    return {
        "acceptance": eval_summary,
        "holdout": {
            "cases": holdout_n,
            "note": "pytest tests/test_holdout.py",
        },
        "load": _read_json(DOCS_DIR / "load_results.json"),
        "criteria": _read_json(DOCS_DIR / "criteria_checklist.json"),
    }


@app.get("/health", response_model=HealthResponse)
async def health(request: Request):
    cfg = request.app.state.config
    return HealthResponse(
        status="ok",
        systems=len(cfg.systems),
        pd_types=len(cfg.pd_rules),
        storage=os.getenv("STORAGE_BACKEND", "memory"),
    )


@app.get("/ready")
async def ready(request: Request):
    store = request.app.state.store
    try:
        ok = store.ping()
    except Exception:
        ok = False
    if not ok:
        raise HTTPException(503, "state store not ready")
    return {"status": "ready"}


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/systems")
async def systems(request: Request):
    cfg = request.app.state.config
    return {
        name: {
            "enabled": s.enabled,
            "pd_types": s.pd_types or cfg.default_pd_types,
            "allow_demask": s.allow_demask,
            "mask_style": s.mask_style,
        }
        for name, s in cfg.systems.items()
    }


@app.get("/")
async def ui_home():
    index = UI_DIR / "index.html"
    if not index.exists():
        raise HTTPException(404, "UI not built")
    return FileResponse(index)


@app.get("/evidence")
async def ui_evidence():
    page = UI_DIR / "evidence.html"
    if not page.exists():
        raise HTTPException(404, "UI not built")
    return FileResponse(page)


if UI_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(UI_DIR)), name="ui")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc.detail)})
