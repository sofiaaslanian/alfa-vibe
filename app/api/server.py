"""HTTP-интейс: FastAPI-приложение с endpoint'ами."""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.api.schemas import HealthResponse, ProcessRequest, ProcessResponse
from app.core.config import Config, load_config
from app.core.llm import AlfaGenClient
from app.core.masker import Masker

log = logging.getLogger("alfa.api")

# --- Метрики ---
LATENCY = Histogram(
    "alfa_process_latency_seconds",
    "Latency of /process",
    ["system", "mode"],
)
RPS = Counter(
    "alfa_process_total",
    "Total /process requests",
    ["system", "mode"],
)
TPS = Counter(
    "alfa_tokens_total",
    "Estimated tokens processed",
    ["system"],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = load_config(os.getenv("CONFIG_PATH", "config.yaml"))
    app.state.config = cfg
    app.state.masker = Masker(cfg)
    app.state.llm = AlfaGenClient()
    log.info("Alfa proxy started: systems=%d pd_types=%d", len(cfg.systems), len(cfg.pd_rules))
    yield


app = FastAPI(
    title="Alfa PD Security Module",
    description="Прокси: ID → MASK → LLM → UNMASK",
    version="1.0.0",
    lifespan=lifespan,
)


def _get_system(request: Request) -> str:
    return request.headers.get("X-System", "")


def _check_system(cfg: Config, system: str) -> None:
    """Проверяет allowlist систем."""
    if not system:
        return
    if system not in cfg.systems:
        raise HTTPException(status_code=403, detail=f"System '{system}' not allowed")
    if not cfg.systems[system].enabled:
        raise HTTPException(status_code=403, detail=f"System '{system}' is disabled")


@app.post("/process", response_model=ProcessResponse)
async def process(request: Request, body: ProcessRequest):
    cfg: Config = request.app.state.config
    masker: Masker = request.app.state.masker
    system = _get_system(request)
    _check_system(cfg, system)

    existed = masker.store.get(body.payload_id) is not None
    start = time.perf_counter()
    try:
        result = masker.process(body.payload, body.payload_id, system or None)
    except Exception as exc:
        log.exception("process error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    elapsed = time.perf_counter() - start
    mode = "demask" if existed else "mask"
    LATENCY.labels(system=system or "unknown", mode=mode).observe(elapsed)
    RPS.labels(system=system or "unknown", mode=mode).inc()
    TPS.labels(system=system or "unknown").inc(len(body.payload) / 4)

    return ProcessResponse(result=result)


@app.get("/health", response_model=HealthResponse)
async def health(request: Request):
    cfg = request.app.state.config
    return HealthResponse(
        status="ok",
        systems=len(cfg.systems),
        pd_types=len(cfg.pd_rules),
    )


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/pd-types")
async def pd_types(request: Request):
    cfg = request.app.state.config
    return {
        pid: {
            "name": r.name,
            "mask": r.mask,
            "requires_context": r.requires_context,
        }
        for pid, r in cfg.pd_rules.items()
    }


@app.get("/systems")
async def systems(request: Request):
    cfg = request.app.state.config
    return {
        name: {
            "enabled": s.enabled,
            "pd_types": s.pd_types,
            "allow_demask": s.allow_demask,
            "mask_style": s.mask_style,
        }
        for name, s in cfg.systems.items()
    }


@app.post("/llm/chat")
async def llm_chat(request: Request, body: ProcessRequest):
    """Проксирует замаскированный промпт в AlfaGen."""
    cfg: Config = request.app.state.config
    masker: Masker = request.app.state.masker
    llm: AlfaGenClient = request.app.state.llm
    system = _get_system(request)
    _check_system(cfg, system)

    masked = masker.mask(body.payload, system or None)
    try:
        answer = llm.chat(masked)
    except Exception as exc:
        log.exception("llm chat error: %s", exc)
        raise HTTPException(status_code=502, detail=f"AlfaGen unavailable: {exc}")

    return {"masked_prompt": masked, "answer": answer}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )