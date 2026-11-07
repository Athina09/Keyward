"""Receipts: one JSON line per decision. Never request/response bodies, never secrets."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path


class Receipts:
    def __init__(self, path: str | Path, clock=time.time):
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def write(self, **fields) -> dict:
        rec = {"ts": round(self._clock(), 3), **fields}
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line)
        return rec

    def read(self, since: float | None = None, limit: int = 200) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if since is None or rec.get("ts", 0) >= since:
                    out.append(rec)
        return out[-limit:]


def describe(rec: dict) -> str:
    """One receipt as a plain sentence."""
    t = time.strftime("%H:%M", time.localtime(rec["ts"]))
    kind = rec.get("kind", "use")
    if kind == "use":
        what = f"{rec.get('route')} {rec.get('method')} {rec.get('path')}"
        money = f" for {rec['amount_text']}" if rec.get("amount_text") else ""
        if rec.get("decision") == "allowed":
            return f"{t} used {rec.get('route')}{money}: {what} → {rec.get('status')}"
        return f"{t} refused {what}{money}: {rec.get('reason')}"
    return f"{t} {kind}: {rec.get('detail', '')}".rstrip(": ")
