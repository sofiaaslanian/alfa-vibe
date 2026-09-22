"""Crypto helpers: HMAC fingerprints + AES-GCM for sensitive state."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _key_from_env(name: str, nbytes: int = 32) -> bytes:
    raw = os.getenv(name, "")
    if raw:
        # accept hex or raw utf-8 padded
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return hashlib.sha256(raw.encode()).digest()
    # ephemeral for local/dev — set STATE_HMAC_KEY / STATE_ENC_KEY in prod
    return hashlib.sha256(f"dev-{name}".encode()).digest()


def hmac_hex(data: str, key: bytes | None = None) -> str:
    key = key or _key_from_env("STATE_HMAC_KEY")
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def encrypt(plaintext: str, aad: str = "") -> str:
    """Returns nonce_hex:ciphertext_hex."""
    key = _key_from_env("STATE_ENC_KEY")
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
    return nonce.hex() + ":" + ct.hex()


def decrypt(blob: str, aad: str = "") -> str:
    key = _key_from_env("STATE_ENC_KEY")
    nonce_hex, ct_hex = blob.split(":", 1)
    aes = AESGCM(key)
    pt = aes.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), aad.encode("utf-8"))
    return pt.decode("utf-8")
