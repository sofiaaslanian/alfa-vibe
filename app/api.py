"""HTTP API: /process, /proxy, /health, /ready, /metrics."""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.config import Config, load_config
from app.llm import AlfaGenClient
from app.process import ProcessError, ProcessService
from app.state import build_store

log = logging.getLogger("alfa.api")

LATENCY = Histogram("alfa_process_latency_seconds", "Latency", ["route", "mode"])
RPS = Counter("alfa_process_total", "Total requests", ["route", "mode", "status"])
TPS = Counter("alfa_tokens_total", "Estimated tokens", ["route"])


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


app = FastAPI(title="Alfa PD Security Module", version="1.1.0", lifespan=lifespan)


def _system(request: Request, x_system: str | None) -> str:
    return x_system or request.headers.get("X-System", "") or ""


def _check_system(cfg: Config, system: str, *, required: bool = False) -> None:
    if not system:
        if required:
            raise HTTPException(403, "X-System required")
        return
    if system not in cfg.systems or not cfg.systems[system].enabled:
        raise HTTPException(403, f"System '{system}' not allowed")


def _api_key_ok(x_api_key: str | None) -> bool:
    expected = os.getenv("PROXY_API_KEYS", "")
    if not expected:
        return True  # open in local demo if unset
    allowed = {k.strip() for k in expected.split(",") if k.strip()}
    return bool(x_api_key and x_api_key in allowed)


@app.post("/process", response_model=ProcessResponse)
async def process(
    request: Request,
    body: ProcessRequest,
    x_system: str | None = Header(default=None, alias="X-System"),
):
    cfg: Config = request.app.state.config
    svc: ProcessService = request.app.state.process
    system = _system(request, x_system)
    _check_system(cfg, system)

    start = time.perf_counter()
    mode = "unknown"
    status = "200"
    try:
        # peek to label metrics
        live = svc.store.get_live("autotest", body.payload_id)
        mode = "mask" if live is None else "retry_or_demask"
        result = svc.process(body.payload, body.payload_id, system or None)
        return ProcessResponse(result=result)
    except ProcessError as exc:
        status = str(exc.status)
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    except Exception as exc:
        status = "503"
        log.exception("process failed")
        raise HTTPException(503, "storage or detection unavailable") from exc
    finally:
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
    """Demo proxy: mask with scoped tokens → AlfaGen → restore if allowed."""
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
        # Fail closed: never send original to LLM
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


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc.detail)})
