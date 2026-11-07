"""Task passes: short-lived permission for one job.

A pass says who it's for, which routes it may use, how much money it may move in
total, how many calls it may make, and when it dies. The broker stores only a
SHA-256 hash of each pass token, so a memory dump of the pass table can't be replayed.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field


class PassError(Exception):
    pass


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Pass:
    id: str  # short public id, safe to log
    subject: str  # who/what the task is for, e.g. a phone number or "booking-42"
    routes: frozenset[str]
    max_amount: int | None
    uses_left: int
    expires: float
    spent: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def summary(self) -> dict:
        return {"id": self.id, "subject": self.subject, "routes": sorted(self.routes),
                "max_amount": self.max_amount, "uses_left": self.uses_left,
                "spent": self.spent, "expires": self.expires}


class PassStore:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._by_hash: dict[str, Pass] = {}
        self._lock = threading.Lock()

    def issue(self, subject: str, routes: set[str], max_amount: int | None,
              uses: int, ttl: int) -> tuple[str, Pass]:
        token = "kwp_" + secrets.token_urlsafe(24)
        p = Pass(id="p_" + secrets.token_hex(4), subject=subject, routes=frozenset(routes),
                 max_amount=max_amount, uses_left=uses, expires=self._clock() + ttl)
        with self._lock:
            self._prune()
            self._by_hash[_h(token)] = p
        return token, p

    def get(self, token: str | None) -> Pass:
        if not token:
            raise PassError("missing pass")
        with self._lock:
            p = self._by_hash.get(_h(token))
        if p is None:
            raise PassError("invalid pass")
        if p.expires <= self._clock():
            raise PassError("pass expired")
        if p.uses_left <= 0:
            raise PassError("pass used up")
        return p

    def charge(self, p: Pass, amount: int | None) -> None:
        """Use one call (and money, if any). Raises if the pass can't cover it."""
        with p.lock:
            if p.uses_left <= 0:
                raise PassError("pass used up")
            if amount is not None and p.max_amount is not None and p.spent + amount > p.max_amount:
                raise PassError("pass money limit reached")
            p.uses_left -= 1
            if amount is not None:
                p.spent += amount

    def refund(self, p: Pass, amount: int | None) -> None:
        """Give money back to the pass when the upstream call didn't succeed."""
        if amount:
            with p.lock:
                p.spent = max(0, p.spent - amount)

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._by_hash.pop(_h(token), None) is not None

    def revoke_all(self) -> int:
        with self._lock:
            n = len(self._by_hash)
            self._by_hash.clear()
            return n

    def active(self) -> list[Pass]:
        with self._lock:
            self._prune()
            return list(self._by_hash.values())

    def _prune(self) -> None:
        now = self._clock()
        for k in [k for k, p in self._by_hash.items() if p.expires <= now or p.uses_left <= 0]:
            del self._by_hash[k]
