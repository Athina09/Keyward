"""The broker: the only process that ever holds secrets in usable form.

Agents (like Halo) talk to it on 127.0.0.1 with a short-lived task pass. Every
`/use/{route}/{path}` call goes through the same checklist:

  1 pass     valid, unexpired, uses left, allowed this route
  2 freeze   owner hasn't frozen Keyward
  3 rules    method + path allowed by rules.toml (deny by default)
  4 budget   call and money limits (checked early, reserved atomically later)
  5 approval a human YES when the rule asks for one
  6 inject   strip caller credentials, add the real one
  7 send     HTTPS to the configured host only, no redirects, bounded size
  8 clean    secrets removed from the reply, only safe headers returned
  9 receipt  one log line, never bodies or secrets
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from .approvals import Approval, ApprovalCenter
from .budget import Budget
from .crypto import VaultError
from .passes import PassError, PassStore
from .receipts import Receipts, describe
from .rules import Route, Rules
from .vault import ADMIN_TOKEN, AGENT_TOKEN, Vault

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
# Headers never forwarded from the agent to the upstream.
STRIP_REQUEST = {
    "authorization", "proxy-authorization", "x-api-key", "api-key", "cookie", "host",
    "content-length", "connection", "keep-alive", "transfer-encoding", "te", "trailer",
    "upgrade", "accept-encoding", "forwarded", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-real-ip",
}
# Only these upstream headers go back to the agent.
KEEP_RESPONSE = {"content-type", "retry-after", "request-id", "x-request-id"}
KEEP_RESPONSE_PREFIXES = ("x-ratelimit-", "anthropic-ratelimit-")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~:@!$&'()*+,;=/-]*$")
REDACTED = b"[REDACTED]"
MIN_REDACT_LEN = 8
MESSAGE_MAX_AGE = 300  # seconds: older WhatsApp commands are ignored (replay protection)


def _eq(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def _safe_path(path: str) -> bool:
    if not SAFE_PATH.match(path) or "//" in path:
        return False
    return not any(seg in (".", "..") for seg in path.split("/"))


def _amount(body: bytes, dotted: str) -> int | None:
    try:
        val = json.loads(body)
        for part in dotted.split("."):
            val = val[part]
    except (ValueError, KeyError, TypeError, IndexError):
        return None
    if isinstance(val, bool) or not isinstance(val, int):
        return None
    return val


def _redact(content: bytes, secrets: list[str]) -> bytes:
    for s in sorted(set(secrets), key=len, reverse=True):
        if len(s) < MIN_REDACT_LEN:
            continue
        for form in (s.encode(), base64.b64encode(s.encode())):
            content = content.replace(form, REDACTED)
    return content


def _sign(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


class Broker:
    def __init__(self, vault: Vault, rules: Rules, home: str | Path,
                 transport: httpx.AsyncBaseTransport | None = None, clock=time.time):
        self.vault = vault
        self.rules = rules
        self.home = Path(home)
        self.clock = clock
        self.passes = PassStore(clock)
        self.budget = Budget(self.home / "budget.db", clock)
        self.receipts = Receipts(self.home / "receipts.jsonl", clock)
        self.approvals = ApprovalCenter(rules.approval_timeout, clock)
        self.approvals.notifier = (self._notify_whatsapp if rules.channel == "whatsapp"
                                   else self._notify_terminal)
        self._freeze_file = self.home / "FROZEN"
        self.frozen = self._freeze_file.exists()
        self._seen_messages: dict[str, float] = {}
        self.client = httpx.AsyncClient(transport=transport, follow_redirects=False)

    # ------------------------------------------------------------ helpers --
    def missing_secrets(self) -> list[str]:
        names = {r.secret for r in self.rules.routes.values()}
        names |= {v.secret for v in self.rules.verifiers.values()}
        if self.rules.whatsapp:
            names.add(self.rules.whatsapp.app_secret)
        active = self.vault.active_values()
        return sorted(n for n in names if n not in active)

    def _is_agent(self, request: Request) -> bool:
        return _eq(request.headers.get("x-keyward-agent"), self.vault.active_values().get(AGENT_TOKEN))

    def _is_admin(self, request: Request) -> bool:
        return _eq(request.headers.get("x-keyward-admin"), self.vault.active_values().get(ADMIN_TOKEN))

    def freeze(self, by: str) -> None:
        self.frozen = True
        self._freeze_file.touch(mode=0o600)
        revoked = self.passes.revoke_all()
        denied = self.approvals.deny_all("Keyward was frozen")
        self.receipts.write(kind="freeze", detail=f"by {by}; {revoked} passes revoked, {denied} approvals denied")

    def unfreeze(self, by: str) -> None:
        self.frozen = False
        self._freeze_file.unlink(missing_ok=True)
        self.receipts.write(kind="unfreeze", detail=f"by {by}")

    async def _send(self, route: Route, method: str, path: str, query: str, headers: dict,
                    body: bytes) -> tuple[int, bytes, dict]:
        """Send to the route's upstream with the real credential. Returns cleaned results."""
        secret = self.vault.get(route.secret)
        injected = (route.inject_format
                    .replace("{secret_base64}", base64.b64encode(secret.encode()).decode())
                    .replace("{secret}", secret))
        out_headers = {k: v for k, v in headers.items()
                       if k.lower() not in STRIP_REQUEST and not k.lower().startswith(("x-keyward-", "proxy-"))
                       and k.lower() != route.inject_header.lower()}
        out_headers[route.inject_header] = injected
        url = httpx.URL(route.upstream + path + (f"?{query}" if query else ""))
        if url.scheme != "https" or url.host != route.host:
            raise httpx.InvalidURL("refusing to send to a different host")
        limit = self.rules.max_response_bytes
        chunks, size = [], 0
        async with self.client.stream(method, url, headers=out_headers, content=body,
                                      timeout=route.timeout) as resp:
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > limit:
                    raise httpx.HTTPError("upstream reply too large")
                chunks.append(chunk)
            status, resp_headers = resp.status_code, resp.headers
        content = _redact(b"".join(chunks), self.vault.all_values() + [injected])
        kept = {k: v for k, v in resp_headers.items()
                if k.lower() in KEEP_RESPONSE or k.lower().startswith(KEEP_RESPONSE_PREFIXES)}
        return status, content, kept

    # ---------------------------------------------------------- approvals --
    async def _notify_terminal(self, a: Approval) -> None:
        self.receipts.write(kind="approval-request", detail=a.summary)
        print(f"\n[keyward] APPROVAL NEEDED: {a.summary}\n"
              f"          run:  keyward approve {a.code}   or   keyward deny {a.code}\n",
              file=sys.stderr, flush=True)

    async def _notify_whatsapp(self, a: Approval) -> None:
        mins = max(1, round(self.approvals.timeout / 60))
        text = (f"Keyward: {a.summary}\n\nReply YES {a.code} to allow or NO {a.code} to refuse "
                f"(expires in {mins} min).")
        self.receipts.write(kind="approval-request", detail=a.summary)
        await self._whatsapp_text(text)

    async def _whatsapp_text(self, text: str) -> None:
        w = self.rules.whatsapp
        route = self.rules.routes[w.route]
        body = json.dumps({"messaging_product": "whatsapp", "to": w.owner, "type": "text",
                           "text": {"body": text[:4000]}}).encode()
        status, _, _ = await self._send(route, "POST", w.path, "", {"content-type": "application/json"}, body)
        self.budget.record(route.name)
        self.receipts.write(kind="notify", detail=f"WhatsApp message to owner → {status}")
        if status >= 300:
            raise RuntimeError(f"WhatsApp send failed with {status}")

    def _owner_command(self, text: str) -> str | None:
        """Handle a command from the owner. Returns a reply, or None if not a command."""
        words = text.strip().upper().split()
        if not words:
            return None
        cmd = words[0]
        if cmd in ("YES", "Y", "NO", "N") and len(words) == 2 and words[1].isdigit():
            a = self.approvals.decide(words[1], approve=cmd in ("YES", "Y"), via="owner on WhatsApp")
            if a is None:
                return "That code isn't waiting for an answer (wrong, used or expired)."
            self.receipts.write(kind="approval", detail=f"{a.status}: {a.summary}")
            return f"{'Allowed' if a.status == 'approved' else 'Refused'}: {a.summary}"
        if cmd == "FREEZE":
            self.freeze("owner on WhatsApp")
            return "Frozen. Every key is blocked and all passes are cancelled. Send UNFREEZE to resume."
        if cmd == "UNFREEZE":
            self.unfreeze("owner on WhatsApp")
            return "Unfrozen. Agents need new passes to continue."
        if cmd == "TODAY":
            start = time.mktime(time.localtime(self.clock())[:3] + (0, 0, 0, 0, 0, -1))
            recs = [r for r in self.receipts.read(since=start) if r.get("kind") in ("use", "freeze", "unfreeze")]
            if not recs:
                return "Nothing used today."
            lines = [describe(r) for r in recs[-15:]]
            more = f"\n(+{len(recs) - 15} earlier)" if len(recs) > 15 else ""
            return "Today:\n" + "\n".join(lines) + more
        if cmd == "LIMITS":
            parts = []
            for r in self.rules.routes.values():
                u = self.budget.usage(r)
                if u:
                    items = []
                    for k, v in u.items():
                        if k.startswith("money_") and r.money:
                            items.append(f"{r.money.fmt(v['used'])}/{r.money.fmt(v['limit'])} {k[6:].replace('_', ' ')}")
                        else:
                            items.append(f"{v['used']}/{v['limit']} {k.replace('_', ' ')}")
                    parts.append(f"{r.name}: " + ", ".join(items))
            return "Limits:\n" + ("\n".join(parts) or "no limits set")
        if cmd == "PENDING":
            p = self.approvals.pending()
            return "\n".join(f"{a.code}: {a.summary}" for a in p) or "Nothing waiting."
        return None

    # ---------------------------------------------------------------- app --
    def app(self) -> FastAPI:
        @asynccontextmanager
        async def lifespan(_app):
            yield
            await self.client.aclose()
            self.budget.close()

        app = FastAPI(title="Keyward", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
        rules = self.rules

        @app.get("/health")
        async def health():
            return {"ok": True, "frozen": self.frozen}

        # ---------------------------------------------------------- passes --
        @app.post("/passes")
        async def create_pass(request: Request):
            if not self._is_agent(request):
                return JSONResponse({"error": "agent token required"}, 401)
            if self.frozen:
                return JSONResponse({"error": "keyward is frozen"}, 423)
            try:
                d = await request.json()
                subject = str(d.get("subject", "")).strip()
                routes = set(d.get("routes") or [])
                max_amount = d.get("max_amount")
                uses = int(d.get("uses", 10))
                ttl = int(d.get("ttl", 600))
            except (ValueError, TypeError, AttributeError):
                return JSONResponse({"error": "invalid JSON"}, 400)
            if not subject or len(subject) > 64:
                return JSONResponse({"error": "subject must be 1-64 characters"}, 400)
            if not routes or not routes <= set(rules.routes):
                return JSONResponse({"error": f"routes must be some of {sorted(rules.routes)}"}, 400)
            if max_amount is not None and (isinstance(max_amount, bool) or not isinstance(max_amount, int)
                                           or max_amount < 0):
                return JSONResponse({"error": "max_amount must be a whole number (minor units) or null"}, 400)
            if not 1 <= uses <= rules.pass_uses_max:
                return JSONResponse({"error": f"uses must be 1-{rules.pass_uses_max}"}, 400)
            if not 30 <= ttl <= rules.pass_ttl_max:
                return JSONResponse({"error": f"ttl must be 30-{rules.pass_ttl_max} seconds"}, 400)
            token, p = self.passes.issue(subject, routes, max_amount, uses, ttl)
            self.receipts.write(kind="pass", detail=f"{p.id} for {subject}: {sorted(routes)}, "
                                                   f"{uses} uses, {ttl}s, max {max_amount}")
            return {"pass": token, **p.summary()}

        @app.delete("/passes")
        async def revoke_pass(request: Request):
            ok = self.passes.revoke(request.headers.get("x-keyward-pass", ""))
            return {"revoked": ok}

        # ------------------------------------------------------------- use --
        @app.api_route("/use/{route_name}/{path:path}", methods=METHODS)
        async def use(route_name: str, path: str, request: Request):
            t0 = self.clock()
            method, upath, query = request.method, "/" + path, request.url.query
            rec = {"kind": "use", "route": route_name, "method": method, "path": upath}

            def refuse(status: int, reason: str):
                self.receipts.write(**rec, decision="refused", reason=reason)
                return JSONResponse({"error": reason}, status)

            # 1 pass
            try:
                p = self.passes.get(request.headers.get("x-keyward-pass"))
            except PassError as e:
                return refuse(401, str(e))
            rec.update(pass_id=p.id, subject=p.subject)
            # 2 freeze
            if self.frozen:
                return refuse(423, "keyward is frozen")
            # 3 rules
            route = rules.routes.get(route_name)
            if route is None or route_name not in p.routes:
                return refuse(403, "route not allowed for this pass")
            if not _safe_path(upath) or not route.allows(method, upath):
                return refuse(403, "not allowed by rules")
            declared = request.headers.get("content-length", "0")
            if not declared.isdigit() or int(declared) > rules.max_request_bytes:
                return refuse(413, "request too large")
            chunks, size = [], 0
            async for chunk in request.stream():  # bounded even without Content-Length
                size += len(chunk)
                if size > rules.max_request_bytes:
                    return refuse(413, "request too large")
                chunks.append(chunk)
            body = b"".join(chunks)
            amount = None
            if route.money:
                amount = _amount(body, route.money.field)
                if amount is None or amount <= 0:
                    return refuse(400, f"money route: '{route.money.field}' must be a positive whole number")
                rec.update(amount=amount, amount_text=route.money.fmt(amount))
                if p.max_amount is not None and p.spent + amount > p.max_amount:
                    return refuse(403, "pass money limit reached")
            # 4 budget (early check, so we don't bother a human for something we'd refuse)
            reason = self.budget.check(route, amount)
            if reason:
                return refuse(429, reason)
            # 5 approval
            if route.needs_approval(amount):
                summary = f"{route.name} {method} {upath}"
                if amount is not None:
                    summary += f" for {route.money.fmt(amount)}"
                summary += f" (task: {p.subject})"
                a = await self.approvals.ask(route.name, summary, p.subject)
                rec["approval"] = a.status
                if a.status != "approved":
                    return refuse(403, f"not approved: {a.reason}")
                if self.frozen:
                    return refuse(423, "keyward is frozen")
            # reserve budget + charge pass atomically
            res_id, reason = self.budget.reserve(route, amount)
            if reason:
                return refuse(429, reason)
            try:
                self.passes.charge(p, amount)
            except PassError as e:
                self.budget.release_money(res_id)
                return refuse(403, str(e))
            # 6-8 inject, send, clean
            try:
                status, content, headers = await self._send(route, method, upath, query,
                                                            dict(request.headers), body)
            except VaultError:
                self.budget.release_money(res_id)
                self.passes.refund(p, amount)
                return refuse(503, f"secret for route {route.name} is missing or expired")
            except (httpx.HTTPError, httpx.InvalidURL):
                self.budget.release_money(res_id)
                self.passes.refund(p, amount)
                return refuse(502, "upstream request failed")
            if not 200 <= status < 300:
                self.budget.release_money(res_id)
                self.passes.refund(p, amount)
            # 9 receipt
            self.receipts.write(**rec, decision="allowed", status=status,
                                ms=round((self.clock() - t0) * 1000))
            return Response(content, status_code=status, headers=headers)

        # ---------------------------------------------------------- verify --
        @app.post("/verify/{name}")
        async def verify(name: str, request: Request):
            try:
                self.passes.get(request.headers.get("x-keyward-pass"))
                authed = True
            except PassError:
                authed = self._is_agent(request)
            if not authed:
                return JSONResponse({"error": "pass or agent token required"}, 401)
            v = rules.verifiers.get(name)
            if v is None:
                return JSONResponse({"error": "unknown verifier"}, 404)
            try:
                d = await request.json()
                payload = base64.b64decode(d["payload_b64"], validate=True)
                signature = str(d["signature"])
                secret = self.vault.get(v.secret)
            except VaultError:
                return JSONResponse({"error": f"secret for verifier {name} is missing or expired"}, 503)
            except (ValueError, KeyError, TypeError):
                return JSONResponse({"error": "send {payload_b64, signature}"}, 400)
            valid = _eq(signature, v.prefix + _sign(secret, payload))
            self.receipts.write(kind="verify", detail=f"{name}: {'valid' if valid else 'INVALID'}")
            return {"valid": valid}

        # ------------------------------------------------ WhatsApp commands --
        @app.post("/channels/whatsapp/inbound")
        async def whatsapp_inbound(request: Request):
            """The agent forwards the RAW webhook body + signature. Keyward checks the
            signature itself, so an agent can't invent a YES or a command."""
            if rules.whatsapp is None:
                return JSONResponse({"error": "WhatsApp channel not configured"}, 404)
            if not self._is_agent(request):
                return JSONResponse({"error": "agent token required"}, 401)
            try:
                d = await request.json()
                payload = base64.b64decode(d["payload_b64"], validate=True)
                signature = str(d["signature"])
                secret = self.vault.get(rules.whatsapp.app_secret)
            except VaultError:
                return JSONResponse({"error": "WhatsApp app secret is missing or expired"}, 503)
            except (ValueError, KeyError, TypeError):
                return JSONResponse({"error": "send {payload_b64, signature}"}, 400)
            if not _eq(signature, "sha256=" + _sign(secret, payload)):
                self.receipts.write(kind="inbound", detail="rejected: bad signature")
                return JSONResponse({"handled": False, "error": "bad signature"}, 403)
            try:
                data = json.loads(payload)
            except ValueError:
                return {"handled": False}
            now = self.clock()
            for k in [k for k, t in self._seen_messages.items() if now - t > MESSAGE_MAX_AGE * 2]:
                del self._seen_messages[k]
            handled = False
            for entry in data.get("entry", []):
                for change in entry.get("changes", []):
                    for msg in change.get("value", {}).get("messages", []):
                        if msg.get("from") != rules.whatsapp.owner or msg.get("type") != "text":
                            continue
                        mid, ts = str(msg.get("id", "")), msg.get("timestamp", "0")
                        if not mid or mid in self._seen_messages:
                            continue  # replayed message
                        if not str(ts).isdigit() or now - int(ts) > MESSAGE_MAX_AGE:
                            continue  # too old: could be a replay
                        self._seen_messages[mid] = now
                        reply = self._owner_command(msg.get("text", {}).get("body", ""))
                        if reply is not None:
                            handled = True
                            try:
                                await self._whatsapp_text(reply)
                            except Exception:
                                pass
            return {"handled": handled}

        # ------------------------------------------------------------ admin --
        def require_admin(request: Request) -> None:
            if not self._is_admin(request):
                raise HTTPException(401, "admin token required")

        admin = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])

        @app.exception_handler(HTTPException)
        async def http_error(_request, exc: HTTPException):
            return JSONResponse({"error": exc.detail}, exc.status_code)

        @admin.post("/freeze")
        async def admin_freeze():
            self.freeze("owner (CLI)")
            return {"frozen": True}

        @admin.post("/unfreeze")
        async def admin_unfreeze():
            self.unfreeze("owner (CLI)")
            return {"frozen": False}

        @admin.get("/status")
        async def admin_status():
            return {
                "frozen": self.frozen,
                "channel": rules.channel,
                "missing_secrets": self.missing_secrets(),
                "passes": [p.summary() for p in self.passes.active()],
                "pending": [a.public() for a in self.approvals.pending()],
                "usage": {r.name: self.budget.usage(r) for r in rules.routes.values()},
            }

        @admin.post("/approvals/{code}")
        async def admin_decide(code: str, request: Request):
            try:
                approve = bool((await request.json())["approve"])
            except (ValueError, KeyError, TypeError):
                return JSONResponse({"error": "send {approve: true|false}"}, 400)
            a = self.approvals.decide(code, approve, via="owner (CLI)")
            if a is None:
                return JSONResponse({"error": "no waiting request with that code"}, 404)
            self.receipts.write(kind="approval", detail=f"{a.status}: {a.summary}")
            return {"status": a.status, "summary": a.summary}

        @admin.post("/reload")
        async def admin_reload():
            try:
                self.vault.reload()
            except VaultError as e:
                return JSONResponse({"error": str(e)}, 409)
            self.receipts.write(kind="reload", detail="vault reloaded")
            return {"reloaded": True, "missing_secrets": self.missing_secrets()}

        app.include_router(admin)
        return app


def serve(vault: Vault, rules: Rules, home: str | Path) -> None:
    import uvicorn

    broker = Broker(vault, rules, home)
    missing = broker.missing_secrets()
    print(f"[keyward] listening on http://{rules.host}:{rules.port}  "
          f"(approvals: {rules.channel}{', FROZEN' if broker.frozen else ''})", file=sys.stderr)
    if missing:
        print(f"[keyward] warning: these secrets are missing or expired: {', '.join(missing)}",
              file=sys.stderr)
    uvicorn.run(broker.app(), host=rules.host, port=rules.port, log_level="warning", access_log=False)
