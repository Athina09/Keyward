"""Rolling budgets per route: call counts and money, stored in SQLite."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from pathlib import Path

from .rules import Route

WINDOWS = {"per_minute": 60, "per_hour": 3600, "per_day": 86400, "per_week": 7 * 86400}
WORDS = {"per_minute": "minute", "per_hour": "hour", "per_day": "day", "per_week": "week"}


class Budget:
    def __init__(self, path: str | Path, clock=time.time):
        self._clock = clock
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS usage (route TEXT, ts REAL, amount INTEGER)")
        self._db.execute("CREATE INDEX IF NOT EXISTS usage_route_ts ON usage(route, ts)")
        self._db.commit()
        self._lock = threading.Lock()

    def _sum(self, route: str, window: int) -> tuple[int, int]:
        since = self._clock() - window
        n, total = self._db.execute(
            "SELECT COUNT(*), COALESCE(SUM(amount), 0) FROM usage WHERE route = ? AND ts > ?",
            (route, since),
        ).fetchone()
        return n, total

    def check(self, route: Route, amount: int | None) -> str | None:
        """Reason to refuse, or None if this call fits every limit (read-only)."""
        with self._lock:
            return self._check_locked(route, amount)

    def _check_locked(self, route: Route, amount: int | None) -> str | None:
        for key, limit in route.limits.items():
            n, _ = self._sum(route.name, WINDOWS[key])
            if n >= limit:
                return f"{route.name}: limit of {limit} calls per {WORDS[key]} reached"
        m = route.money
        if m and amount is not None:
            if m.per_request is not None and amount > m.per_request:
                return f"{m.fmt(amount)} is over the {m.fmt(m.per_request)} per-payment limit"
            for key in ("per_day", "per_week"):
                limit = getattr(m, key)
                if limit is not None:
                    _, spent = self._sum(route.name, WINDOWS[key])
                    if spent + amount > limit:
                        return (f"{m.fmt(amount)} would pass the {m.fmt(limit)} per-{WORDS[key]} "
                                f"limit ({m.fmt(spent)} used)")
        return None

    def reserve(self, route: Route, amount: int | None) -> tuple[int | None, str | None]:
        """Atomically check every limit and, if it fits, record the call.

        Returns (reservation_id, None) or (None, reason). Doing check + insert under
        one lock means two calls at the same moment can't both squeeze under a limit.
        """
        with self._lock:
            reason = self._check_locked(route, amount)
            if reason:
                return None, reason
            cur = self._db.execute("INSERT INTO usage VALUES (?, ?, ?)",
                                   (route.name, self._clock(), amount or 0))
            self._db.execute("DELETE FROM usage WHERE ts < ?", (self._clock() - WINDOWS["per_week"],))
            self._db.commit()
            return cur.lastrowid, None

    def release_money(self, reservation_id: int) -> None:
        """The call failed upstream: keep it in the call count, give the money back."""
        with self._lock:
            self._db.execute("UPDATE usage SET amount = 0 WHERE rowid = ?", (reservation_id,))
            self._db.commit()

    def record(self, route: str, amount: int | None = None) -> None:
        with self._lock:
            self._db.execute("INSERT INTO usage VALUES (?, ?, ?)", (route, self._clock(), amount or 0))
            self._db.commit()

    def usage(self, route: Route) -> dict:
        with self._lock:
            out = {}
            for key, limit in route.limits.items():
                out[key] = {"used": self._sum(route.name, WINDOWS[key])[0], "limit": limit}
            if route.money:
                for key in ("per_day", "per_week"):
                    limit = getattr(route.money, key)
                    if limit is not None:
                        out[f"money_{key}"] = {"used": self._sum(route.name, WINDOWS[key])[1],
                                               "limit": limit}
            return out

    def close(self) -> None:
        self._db.close()
