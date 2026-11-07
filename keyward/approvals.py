"""Ask a human before acting.

A request that needs approval waits (asynchronously) until the owner answers
with its one-time 6-digit code, or until it times out. Codes are single-use and
only valid while their request is waiting.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable


@dataclass
class Approval:
    code: str
    route: str
    summary: str
    subject: str
    created: float
    expires: float
    status: str = "pending"  # pending | approved | denied | expired
    reason: str = ""
    event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    def public(self) -> dict:
        return {"code": self.code, "route": self.route, "summary": self.summary,
                "subject": self.subject, "expires": self.expires}


Notifier = Callable[[Approval], Awaitable[None]]


class ApprovalCenter:
    def __init__(self, timeout: int, clock=time.time):
        self.timeout = timeout
        self._clock = clock
        self._pending: dict[str, Approval] = {}
        self.notifier: Notifier | None = None

    def _new_code(self) -> str:
        while True:
            code = f"{secrets.randbelow(10**6):06d}"
            if code not in self._pending:
                return code

    async def ask(self, route: str, summary: str, subject: str) -> Approval:
        now = self._clock()
        a = Approval(code=self._new_code(), route=route, summary=summary, subject=subject,
                     created=now, expires=now + self.timeout)
        self._pending[a.code] = a
        try:
            if self.notifier is None:
                raise RuntimeError("no approval channel")
            try:
                await self.notifier(a)
            except Exception:
                a.status, a.reason = "denied", "could not send the approval request"
                return a
            try:
                await asyncio.wait_for(a.event.wait(), timeout=self.timeout)
            except asyncio.TimeoutError:
                a.status, a.reason = "expired", "no answer in time"
            return a
        finally:
            self._pending.pop(a.code, None)

    def decide(self, code: str, approve: bool, via: str = "owner") -> Approval | None:
        """Answer a waiting request. Returns None for an unknown or used code."""
        a = self._pending.get(code.strip())
        if a is None or a.status != "pending":
            return None
        a.status = "approved" if approve else "denied"
        a.reason = f"{a.status} by {via}"
        a.event.set()
        return a

    def deny_all(self, reason: str) -> int:
        n = 0
        for a in list(self._pending.values()):
            if a.status == "pending":
                a.status, a.reason = "denied", reason
                a.event.set()
                n += 1
        return n

    def pending(self) -> list[Approval]:
        return [a for a in self._pending.values() if a.status == "pending"]
