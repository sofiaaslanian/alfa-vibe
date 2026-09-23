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
    def get_cached_mask(self, namespace: str, text_fp: str) -> Optional[tuple[bool, str]]: ...
    def put_cached_mask(self, namespace: str, text_fp: str, masked: str | None) -> None: ...
    def lookup_for_mask(
        self, namespace: str, payload_id: str, text_fp: str
    ) -> tuple[Optional[OperationState], bool, Optional[tuple[bool, str]]]: ...
    def commit_new_mask(
        self,
        state: OperationState,
        text_fp: str,
        masked: str | None,
        write_cache: bool,
    ) -> bool: ...
    def ping(self) -> bool: ...


class MemoryStateStore:
    """Unit-test / fallback store (not for multi-worker)."""

    def __init__(self, live_ttl: int = LIVE_TTL, seen_ttl: int = SEEN_TTL):
        self.live_ttl = live_ttl
        self.seen_ttl = seen_ttl
        self._lock = threading.RLock()
        self._live: dict[str, tuple[OperationState, float]] = {}
        self._seen: dict[str, float] = {}
        self._cache: dict[str, tuple[tuple[bool, str], float]] = {}

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

    def _cache_key(self, namespace: str, text_fp: str) -> str:
        return f"cache:{namespace}:{text_fp}"

    def get_cached_mask(self, namespace: str, text_fp: str) -> Optional[tuple[bool, str]]:
        with self._lock:
            item = self._cache.get(self._cache_key(namespace, text_fp))
            if not item:
                return None
            value, exp = item
            if time.time() > exp:
                del self._cache[self._cache_key(namespace, text_fp)]
                return None
            return value

    def put_cached_mask(self, namespace: str, text_fp: str, masked: str | None) -> None:
        value = (True, "") if masked is None else (False, masked)
        with self._lock:
            self._cache[self._cache_key(namespace, text_fp)] = (value, time.time() + self.live_ttl)

    def lookup_for_mask(self, namespace, payload_id, text_fp):
        with self._lock:
            live = self.get_live(namespace, payload_id)
            seen = self.get_seen(namespace, payload_id)
            cached = self.get_cached_mask(namespace, text_fp)
        return live, seen, cached

    def commit_new_mask(self, state, text_fp, masked, write_cache) -> bool:
        if write_cache:
            self.put_cached_mask(state.namespace, text_fp, masked)
        return self.create_atomic(state)

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

    def _cache_key(self, namespace: str, text_fp: str) -> str:
        return f"alfa:mask:{namespace}:{text_fp}"

    def get_cached_mask(self, namespace: str, text_fp: str) -> Optional[tuple[bool, str]]:
        raw = self._r.get(self._cache_key(namespace, text_fp))
        if raw is None:
            return None
        if raw == "U":
            return (True, "")
        if raw.startswith("R"):
            return (False, raw[1:])
        return None

    def put_cached_mask(self, namespace: str, text_fp: str, masked: str | None) -> None:
        raw = "U" if masked is None else "R" + masked
        self._r.set(self._cache_key(namespace, text_fp), raw, ex=self.live_ttl)

    def _decode_cache(self, raw):
        if raw is None:
            return None
        if raw == "U":
            return (True, "")
        if raw.startswith("R"):
            return (False, raw[1:])
        return None

    def lookup_for_mask(self, namespace, payload_id, text_fp):
        pipe = self._r.pipeline(transaction=False)
        pipe.get(self._live_key(namespace, payload_id))
        pipe.exists(self._seen_key(namespace, payload_id))
        pipe.get(self._cache_key(namespace, text_fp))
        live_raw, seen_flag, cache_raw = pipe.execute()
        live = OperationState.from_json(live_raw) if live_raw else None
        return live, bool(seen_flag), self._decode_cache(cache_raw)

    def commit_new_mask(self, state, text_fp, masked, write_cache) -> bool:
        pipe = self._r.pipeline(transaction=False)
        if write_cache:
            raw = "U" if masked is None else "R" + masked
            pipe.set(self._cache_key(state.namespace, text_fp), raw, ex=self.live_ttl)
        pipe.eval(
            _LUA_CREATE,
            2,
            self._live_key(state.namespace, state.payload_id),
            self._seen_key(state.namespace, state.payload_id),
            state.to_json(),
            str(self.live_ttl),
            str(self.seen_ttl),
        )
        return bool(pipe.execute()[-1])

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
