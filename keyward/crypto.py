"""Password-based encryption: Argon2id to derive a key, AES-256-GCM to seal data.

Nothing here prints, logs or formats secret material. Every failure to open sealed
data raises the same VaultError message, so an attacker cannot tell a wrong
password from a damaged or edited file.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GENERIC_ERROR = "Wrong password or damaged vault"
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 32


class VaultError(Exception):
    """Raised for any vault problem. Messages never contain secret values."""


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_cost: int = 64 * 1024  # KiB, i.e. 64 MB
    parallelism: int = 4

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "KdfParams":
        try:
            p = cls(int(d["time_cost"]), int(d["memory_cost"]), int(d["parallelism"]))
        except (KeyError, TypeError, ValueError):
            raise VaultError(GENERIC_ERROR) from None
        # Refuse absurdly weak parameters, e.g. from a tampered header.
        if p.time_cost < 1 or p.memory_cost < 8 * 1024 or p.parallelism < 1:
            raise VaultError(GENERIC_ERROR)
        return p


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    if not password:
        raise VaultError("Password must not be empty")
    if len(salt) != SALT_LEN:
        raise VaultError(GENERIC_ERROR)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt with a fresh random nonce. Returns nonce + ciphertext (with GCM tag)."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < NONCE_LEN + 16:
        raise VaultError(GENERIC_ERROR)
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except (InvalidTag, ValueError):
        raise VaultError(GENERIC_ERROR) from None
