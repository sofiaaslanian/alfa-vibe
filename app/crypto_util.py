"""Crypto helpers: HMAC fingerprints + AES-GCM for sensitive state."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_lock = threading.Lock()
_hmac_key: bytes | None = None
_aesgcm: AESGCM | None = None


def _key_from_env(name: str) -> bytes:
    raw = os.getenv(name, "")
    weak = (
        not raw
        or raw.startswith("change-me")
        or raw in {"changeme", "secret", "password"}
    )
    if weak:
        # Refuse predictable keys when Redis holds encrypted state.
        if os.getenv("STORAGE_BACKEND", "memory") == "redis" and os.getenv(
            "ALLOW_WEAK_STATE_KEYS", "0"
        ) != "1":
            raise RuntimeError(
                f"{name} must be a strong secret when STORAGE_BACKEND=redis "
                f"(got empty/placeholder). Set ALLOW_WEAK_STATE_KEYS=1 only for local demos."
            )
        # ephemeral for local/dev memory store
        return hashlib.sha256(f"dev-{name}".encode()).digest()
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return hashlib.sha256(raw.encode()).digest()


def _hmac_key_cached() -> bytes:
    global _hmac_key
    if _hmac_key is None:
        with _lock:
            if _hmac_key is None:
                _hmac_key = _key_from_env("STATE_HMAC_KEY")
    return _hmac_key


def _aesgcm_cached() -> AESGCM:
    global _aesgcm
    if _aesgcm is None:
        with _lock:
            if _aesgcm is None:
                _aesgcm = AESGCM(_key_from_env("STATE_ENC_KEY"))
    return _aesgcm


def hmac_hex(data: str, key: bytes | None = None) -> str:
    key = key or _hmac_key_cached()
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def encrypt(plaintext: str, aad: str = "") -> str:
    """Returns nonce_hex:ciphertext_hex."""
    aes = _aesgcm_cached()
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
    return nonce.hex() + ":" + ct.hex()


def decrypt(blob: str, aad: str = "") -> str:
    aes = _aesgcm_cached()
    nonce_hex, ct_hex = blob.split(":", 1)
    pt = aes.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), aad.encode("utf-8"))
    return pt.decode("utf-8")
