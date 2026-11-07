"""The vault: one encrypted file holding secrets, each with a list of versions.

Design (deliberately simple):
  * The whole secret store is one JSON document, sealed with AES-256-GCM.
  * The file header (format, KDF params, salt) is bound to the ciphertext as
    associated data, so editing the header also breaks decryption.
  * Changing a secret never overwrites: it appends a version. `undo` moves the
    "current" pointer back. Values are never returned by listing functions.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .crypto import GENERIC_ERROR, KdfParams, VaultError, derive_key, new_salt, seal, unseal

FORMAT = "keyward-vault"
FORMAT_VERSION = 1
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
TTL_RE = re.compile(r"^(\d{1,5})([mhdw])$")
TTL_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}

AGENT_TOKEN = "KEYWARD_AGENT_TOKEN"
ADMIN_TOKEN = "KEYWARD_ADMIN_TOKEN"
INTERNAL_NAMES = {AGENT_TOKEN, ADMIN_TOKEN}

EXPIRING_SOON = timedelta(days=7)
OLD_AFTER = timedelta(days=180)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds") if dt else None


def _parse(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def parse_ttl(ttl: str) -> timedelta:
    """'30m', '6h', '7d', '2w' -> timedelta."""
    m = TTL_RE.match(ttl.strip().lower())
    if not m or int(m.group(1)) == 0:
        raise VaultError(f"Invalid TTL {ttl!r}: use a number plus m, h, d or w (e.g. 90d)")
    return timedelta(**{TTL_UNITS[m.group(2)]: int(m.group(1))})


def check_name(name: str) -> None:
    if not NAME_RE.match(name):
        raise VaultError(
            f"Invalid secret name {name!r}: start with a letter; letters, digits, _ . - only; max 64"
        )


def _write_private(path: Path, data: bytes) -> None:
    """Atomic write, readable only by the owner."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


class Vault:
    def __init__(self, path: Path, key: bytes, header: dict, data: dict):
        self.path = Path(path)
        self._key = key
        self._header = header
        self._data = data

    # ------------------------------------------------------------ file I/O --
    @staticmethod
    def _aad(header: dict) -> bytes:
        return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def create(cls, path: str | Path, password: str, params: KdfParams | None = None) -> "Vault":
        path = Path(path)
        if path.exists():
            raise VaultError(f"A vault already exists at {path}")
        if len(password) < 10:
            raise VaultError("Master password must be at least 10 characters")
        params = params or KdfParams()
        salt = new_salt()
        header = {
            "format": FORMAT,
            "version": FORMAT_VERSION,
            "kdf": {"alg": "argon2id", **params.to_dict()},
            "salt": base64.b64encode(salt).decode(),
        }
        v = cls(path, derive_key(password, salt, params), header, {"secrets": {}})
        for name in (AGENT_TOKEN, ADMIN_TOKEN):
            v.set(name, "kw_" + pysecrets.token_urlsafe(32), note="created by keyward init")
        v.save()
        return v

    @classmethod
    def open(cls, path: str | Path, password: str) -> "Vault":
        path = Path(path)
        if not path.exists():
            raise VaultError(f"No vault at {path} (run: keyward init)")
        header, blob = cls._read(path)
        try:
            salt = base64.b64decode(header["salt"], validate=True)
            params = KdfParams.from_dict(header["kdf"])
        except (KeyError, ValueError, TypeError):
            raise VaultError(GENERIC_ERROR) from None
        key = derive_key(password, salt, params)
        data = cls._decode(key, header, blob)
        return cls(path, key, header, data)

    @staticmethod
    def _read(path: Path) -> tuple[dict, bytes]:
        try:
            outer = json.loads(path.read_bytes())
            header = outer["header"]
            blob = base64.b64decode(outer["data"], validate=True)
            if header.get("format") != FORMAT or header.get("version") != FORMAT_VERSION:
                raise ValueError
        except (ValueError, KeyError, TypeError, AttributeError):
            raise VaultError(GENERIC_ERROR) from None
        return header, blob

    @classmethod
    def _decode(cls, key: bytes, header: dict, blob: bytes) -> dict:
        try:
            data = json.loads(unseal(key, blob, cls._aad(header)))
            if not isinstance(data.get("secrets"), dict):
                raise ValueError
        except (ValueError, AttributeError):
            raise VaultError(GENERIC_ERROR) from None
        return data

    def reload(self) -> None:
        """Re-read the file with the key already in memory (used by the running broker)."""
        header, blob = self._read(self.path)
        if header != self._header:
            raise VaultError("Vault header changed (password changed?). Restart the broker.")
        self._data = self._decode(self._key, header, blob)

    def save(self) -> None:
        plaintext = json.dumps(self._data, sort_keys=True).encode()
        blob = seal(self._key, plaintext, self._aad(self._header))
        outer = {"header": self._header, "data": base64.b64encode(blob).decode()}
        _write_private(self.path, json.dumps(outer, indent=2).encode())

    def change_password(self, new_password: str, params: KdfParams | None = None) -> None:
        if len(new_password) < 10:
            raise VaultError("Master password must be at least 10 characters")
        params = params or KdfParams.from_dict(self._header["kdf"])
        salt = new_salt()
        self._header = {**self._header, "kdf": {"alg": "argon2id", **params.to_dict()},
                        "salt": base64.b64encode(salt).decode()}
        self._key = derive_key(new_password, salt, params)
        self.save()

    # ------------------------------------------------------------- secrets --
    def _entry(self, name: str) -> dict:
        check_name(name)
        e = self._data["secrets"].get(name)
        if e is None:
            raise VaultError(f"No secret named {name!r}")
        return e

    @staticmethod
    def _current(e: dict) -> dict:
        return next(v for v in e["versions"] if v["v"] == e["current"])

    def set(self, name: str, value: str, ttl: str | None = None, note: str = "",
            now: datetime | None = None) -> int:
        """Add a new version and make it current. Returns the version number."""
        check_name(name)
        if not value:
            raise VaultError("Secret value must not be empty")
        if len(note) > 200:
            raise VaultError("Note must be at most 200 characters")
        now = now or utcnow()
        e = self._data["secrets"].setdefault(name, {"versions": [], "current": None, "removed": False})
        num = max((v["v"] for v in e["versions"]), default=0) + 1
        e["versions"].append({
            "v": num,
            "value": value,
            "created": _iso(now),
            "expires": _iso(now + parse_ttl(ttl)) if ttl else None,
            "note": note,
        })
        e["current"] = num
        e["removed"] = False
        return num

    def undo(self, name: str) -> int:
        """Make the version before the current one current again."""
        e = self._entry(name)
        older = sorted((v["v"] for v in e["versions"] if v["v"] < e["current"]), reverse=True)
        if not older:
            raise VaultError(f"{name} has no earlier version to go back to")
        e["current"] = older[0]
        e["removed"] = False
        return older[0]

    def use_version(self, name: str, version: int) -> None:
        e = self._entry(name)
        if not any(v["v"] == version for v in e["versions"]):
            raise VaultError(f"{name} has no version {version}")
        e["current"] = version
        e["removed"] = False

    def remove(self, name: str) -> None:
        """Hide a secret from use. Versions are kept until purge."""
        if name in INTERNAL_NAMES:
            raise VaultError(f"{name} is used by Keyward itself and cannot be removed")
        self._entry(name)["removed"] = True

    def purge(self, name: str) -> None:
        """Delete a secret and all its versions for good."""
        if name in INTERNAL_NAMES:
            raise VaultError(f"{name} is used by Keyward itself and cannot be purged")
        self._entry(name)
        del self._data["secrets"][name]

    def get(self, name: str, now: datetime | None = None) -> str:
        """Current value, only if not removed and not expired."""
        e = self._entry(name)
        if e["removed"]:
            raise VaultError(f"{name} is removed")
        cur = self._current(e)
        exp = _parse(cur["expires"])
        if exp and exp <= (now or utcnow()):
            raise VaultError(f"{name} expired")
        return cur["value"]

    def has(self, name: str) -> bool:
        return name in self._data["secrets"]

    def active_values(self, now: datetime | None = None) -> dict[str, str]:
        out = {}
        for name in self._data["secrets"]:
            try:
                out[name] = self.get(name, now)
            except VaultError:
                pass
        return out

    def all_values(self) -> list[str]:
        """Every stored value, any version. Used only to redact replies."""
        return [v["value"] for e in self._data["secrets"].values() for v in e["versions"]]

    # -------------------------------------------- listing (never values) --
    def status(self, name: str, now: datetime | None = None) -> str:
        e = self._entry(name)
        if e["removed"]:
            return "removed"
        exp = _parse(self._current(e)["expires"])
        return "expired" if exp and exp <= (now or utcnow()) else "active"

    def list(self, now: datetime | None = None) -> list[dict]:
        rows = []
        for name in sorted(self._data["secrets"]):
            e = self._data["secrets"][name]
            cur = self._current(e)
            rows.append({
                "name": name,
                "version": e["current"],
                "versions": len(e["versions"]),
                "created": cur["created"],
                "expires": cur["expires"],
                "status": self.status(name, now),
                "internal": name in INTERNAL_NAMES,
            })
        return rows

    def history(self, name: str) -> list[dict]:
        e = self._entry(name)
        return [
            {"version": v["v"], "created": v["created"], "expires": v["expires"],
             "note": v["note"], "current": v["v"] == e["current"]}
            for v in sorted(e["versions"], key=lambda v: v["v"])
        ]

    def check(self, now: datetime | None = None) -> list[dict]:
        """Problems worth fixing: expired, expiring soon, very old, removed-but-kept."""
        now = now or utcnow()
        issues = []
        for name in sorted(self._data["secrets"]):
            e = self._data["secrets"][name]
            cur = self._current(e)
            exp, created = _parse(cur["expires"]), _parse(cur["created"])
            if e["removed"]:
                issues.append({"name": name, "issue": "removed", "detail": "still stored; purge to delete"})
            elif exp and exp <= now:
                issues.append({"name": name, "issue": "expired", "detail": f"expired {cur['expires']}"})
            elif exp and exp - now <= EXPIRING_SOON:
                issues.append({"name": name, "issue": "expiring", "detail": f"expires {cur['expires']}"})
            elif not exp and name not in INTERNAL_NAMES and now - created >= OLD_AFTER:
                days = (now - created).days
                issues.append({"name": name, "issue": "old", "detail": f"{days} days old, no expiry"})
        return issues
