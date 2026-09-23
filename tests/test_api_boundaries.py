"""Regression tests for proxy access and async request handling."""

import asyncio
import time
from types import SimpleNamespace

import httpx

from app import api
from app.config import load_config


def test_proxy_rejects_missing_or_empty_key_configuration(monkeypatch):
    monkeypatch.delenv("PROXY_API_KEYS", raising=False)
    assert not api._api_key_ok(None)
    assert not api._api_key_ok("demo-key")

    monkeypatch.setenv("PROXY_API_KEYS", " ,  ")
    assert not api._api_key_ok("demo-key")

    monkeypatch.setenv("PROXY_API_KEYS", "secret-one,secret-two")
    assert api._api_key_ok("secret-two")
    assert not api._api_key_ok("other")


def test_proxy_routes_reject_requests_without_configured_key(monkeypatch):
    monkeypatch.delenv("PROXY_API_KEYS", raising=False)

    async def check():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api.app),
            base_url="http://test",
        ) as client:
            proxy = await client.post("/proxy/chat", json={"text": "example"})
            demo = await client.post("/demo/run", json={"text": "example"})
            return proxy.status_code, demo.status_code

    assert asyncio.run(check()) == (401, 401)


def test_process_keeps_event_loop_responsive(monkeypatch):
    class SlowService:
        store = SimpleNamespace(get_live=lambda *_: None)

        def process(self, *_):
            time.sleep(0.08)
            return "masked"

    monkeypatch.setattr(api, "_process_sem", None)
    api.app.state.config = load_config("config.yaml")
    api.app.state.process = SlowService()

    async def request_with_tick():
        tick = asyncio.Event()

        async def tick_soon():
            await asyncio.sleep(0.01)
            tick.set()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api.app),
            base_url="http://test",
        ) as client:
            request_task = asyncio.create_task(
                client.post("/process", json={"payload": "sample", "payload_id": "1"})
            )
            tick_task = asyncio.create_task(tick_soon())
            await asyncio.wait_for(tick.wait(), timeout=0.05)
            assert not request_task.done()
            response = await request_task
            await tick_task
            return response

    response = asyncio.run(request_with_tick())
    assert response.status_code == 200
    assert response.json() == {"result": "masked"}
