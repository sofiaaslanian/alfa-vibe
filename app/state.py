"""Shared operation state: memory (tests) or Redis (prod)."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Optional, Protocol

log = logging.getLogger("alfa.state")

LIVE_TTL = int(os.getenv("STATE_TTL", "3600"))
SEEN_TTL = int(os.getenv("STATE_SEEN_TTL", "86400"))


@dataclass
class OperationState:
    payload_id: str
    namespace: str
    original_fp: str
    masked_fp: str
    masked_enc: str
    original_enc: str
    system: str = ""
    mask_strategy: str = "dev_redact_v1"
    tokens_enc: str = ""  # encrypted JSON token map for proxy
    created_at: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str) -> "OperationState":
        return cls(**json.loads(raw))


class StateStore(Protocol):
    def get_live(self, namespace: str, payload_id: str) -> Optional[OperationState]: ...
    def get_seen(self, namespace: str, payload_id: str) -> bool: ...
    def create_atomic(self, state: OperationState) -> bool: ...
    def ping(self) -> bool: ...


class MemoryStateStore:
    """Unit-test / fallback store (not for multi-worker)."""

    def __init__(self, live_ttl: int = LIVE_TTL, seen_ttl: int = SEEN_TTL):
        self.live_ttl = live_ttl
        self.seen_ttl = seen_ttl
        self._lock = threading.Lock()
        self._live: dict[str, tuple[OperationState, float]] = {}
        self._seen: dict[str, float] = {}

    def _key(self, namespace: str, payload_id: str) -> str:
        return f"{namespace}:{payload_id}"

    def get_live(self, namespace: str, payload_id: str) -> Optional[OperationState]:
        with self._lock:
            k = self._key(namespace, payload_id)
            item = self._live.get(k)
            if not item:
                return None
            state, exp = item
            if time.time() > exp:
                del self._live[k]
                return None
            return state

    def get_seen(self, namespace: str, payload_id: str) -> bool:
        with self._lock:
            k = self._key(namespace, payload_id)
            exp = self._seen.get(k)
            if exp is None:
                return False
            if time.time() > exp:
                del self._seen[k]
                return False
            return True

    def create_atomic(self, state: OperationState) -> bool:
        with self._lock:
            k = self._key(state.namespace, state.payload_id)
            if k in self._live and time.time() <= self._live[k][1]:
                return False
            if k in self._seen and time.time() <= self._seen[k]:
                return False
            now = time.time()
            self._live[k] = (state, now + self.live_ttl)
            self._seen[k] = now + self.seen_ttl
            return True

    def ping(self) -> bool:
        return True


_LUA_CREATE = """
-- KEYS[1]=live KEYS[2]=seen  ARGV[1]=payload ARGV[2]=live_ttl ARGV[3]=seen_ttl
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
redis.call('SET', KEYS[2], '1', 'EX', ARGV[3])
return 1
"""


class RedisStateStore:
    def __init__(
        self,
        url: str | None = None,
        live_ttl: int = LIVE_TTL,
        seen_ttl: int = SEEN_TTL,
    ):
        import redis

        self.live_ttl = live_ttl
        self.seen_ttl = seen_ttl
        self._r = redis.Redis.from_url(url or os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
        self._create = self._r.register_script(_LUA_CREATE)

    def _live_key(self, namespace: str, payload_id: str) -> str:
        return f"alfa:live:{namespace}:{payload_id}"

    def _seen_key(self, namespace: str, payload_id: str) -> str:
        return f"alfa:seen:{namespace}:{payload_id}"

    def get_live(self, namespace: str, payload_id: str) -> Optional[OperationState]:
        raw = self._r.get(self._live_key(namespace, payload_id))
        if not raw:
            return None
        return OperationState.from_json(raw)

    def get_seen(self, namespace: str, payload_id: str) -> bool:
        return bool(self._r.exists(self._seen_key(namespace, payload_id)))

    def create_atomic(self, state: OperationState) -> bool:
        ok = self._create(
            keys=[self._live_key(state.namespace, state.payload_id), self._seen_key(state.namespace, state.payload_id)],
            args=[state.to_json(), self.live_ttl, self.seen_ttl],
        )
        return bool(ok)

    def ping(self) -> bool:
        return self._r.ping()


def build_store() -> StateStore:
    backend = os.getenv("STORAGE_BACKEND", os.getenv("storage_backend", "memory")).lower()
    if backend == "redis":
        try:
            store = RedisStateStore()
            store.ping()
            log.info("Using Redis state store")
            return store
        except Exception:
            log.exception("Redis unavailable")
            raise
    log.info("Using in-memory state store")
    return MemoryStateStore()
