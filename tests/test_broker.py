import asyncio
import base64
import hashlib
import hmac
import json
import time

import httpx
import pytest

from keyward.broker import Broker
from keyward.rules import RulesError, parse_rules
from keyward.vault import ADMIN_TOKEN, AGENT_TOKEN, Vault

from .conftest import FAST, PASSWORD

AI_KEY = "sk-ai-very-secret-123456"
WA_TOKEN = "EAAG-whatsapp-token-987654"
RZP_KEY = "rzp_test_abc:rzp_secret_xyz789"
WA_APP_SECRET = "wa-app-secret-555555"
OWNER = "919876543210"

RULES = {
    "approvals": {
        "channel": "whatsapp",
        "timeout": 10,
        "whatsapp": {"route": "whatsapp", "path": "/v21.0/111/messages", "owner": OWNER,
                     "app_secret": "WA_APP_SECRET"},
    },
    "routes": {
        "ai": {
            "upstream": "https://api.ai.example",
            "secret": "AI_KEY",
            "inject": {"header": "x-api-key", "format": "{secret}"},
            "allow": [{"method": "POST", "path": "^/v1/messages$"}],
            "limits": {"per_minute": 3},
        },
        "whatsapp": {
            "upstream": "https://graph.facebook.com",
            "secret": "WA_TOKEN",
            "inject": {"header": "Authorization", "format": "Bearer {secret}"},
            "allow": [{"method": "POST", "path": "^/v[0-9.]+/111/messages$"}],
        },
        "pay": {
            "upstream": "https://api.razorpay.com",
            "secret": "RZP_KEY",
            "inject": {"header": "Authorization", "format": "Basic {secret_base64}"},
            "allow": [{"method": "POST", "path": "^/v1/payment_links$"}],
            "money": {"field": "amount", "per_request": 200000, "per_week": 300000, "approve_over": 50000},
        },
    },
    "verifiers": {"razorpay": {"secret": "RZP_WEBHOOK"}, "whatsapp": {"secret": "WA_APP_SECRET",
                                                                      "prefix": "sha256="}},
}


class Upstream:
    """Fake internet: records every request and answers like the real APIs."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.status = 200

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        if host == "api.ai.example":
            # A careless API that echoes the key back, plus a cookie.
            return httpx.Response(self.status, json={"reply": "hi", "debug": request.headers.get("x-api-key")},
                                  headers={"set-cookie": "session=abc", "x-request-id": "r1"})
        if host == "api.razorpay.com":
            if self.status != 200:
                return httpx.Response(self.status, json={"error": "bad"})
            return httpx.Response(200, json={"short_url": "https://rzp.io/i/x"})
        if host == "graph.facebook.com":
            return httpx.Response(200, json={"messages": [{"id": "wamid.1"}]})
        return httpx.Response(404)


class Env:
    def __init__(self, tmp_path, rules=None):
        self.vault = Vault.create(tmp_path / "vault.kw", PASSWORD, FAST)
        for name, val in [("AI_KEY", AI_KEY), ("WA_TOKEN", WA_TOKEN), ("RZP_KEY", RZP_KEY),
                          ("WA_APP_SECRET", WA_APP_SECRET), ("RZP_WEBHOOK", "rzp-webhook-secret-1")]:
            self.vault.set(name, val)
        self.vault.save()
        self.up = Upstream()
        self.rules = parse_rules(rules or RULES)
        self.broker = Broker(self.vault, self.rules, tmp_path, transport=httpx.MockTransport(self.up))
        self.app = self.broker.app()
        self.agent = {"x-keyward-agent": self.vault.get(AGENT_TOKEN)}
        self.admin = {"x-keyward-admin": self.vault.get(ADMIN_TOKEN)}
        self.home = tmp_path

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://kw")

    async def new_pass(self, c, routes=("ai", "whatsapp", "pay"), **kw):
        r = await c.post("/passes", headers=self.agent,
                         json={"subject": "booking-42", "routes": list(routes), **kw})
        assert r.status_code == 200, r.text
        return {"x-keyward-pass": r.json()["pass"]}

    def receipts_text(self):
        p = self.home / "receipts.jsonl"
        return p.read_text() if p.exists() else ""

    def signed(self, body: dict, secret=WA_APP_SECRET):
        raw = json.dumps(body).encode()
        sig = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        return {"payload_b64": base64.b64encode(raw).decode(), "signature": sig}


def wa_message(text, sender=OWNER, mid="wamid.A", ts=None):
    return {"entry": [{"changes": [{"value": {"messages": [{
        "from": sender, "id": mid, "timestamp": str(int(ts if ts is not None else time.time())),
        "type": "text", "text": {"body": text}}]}}]}]}


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------------------ passes --
def test_pass_required_and_agent_token_required(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            assert (await c.post("/use/ai/v1/messages", json={})).status_code == 401
            assert (await c.post("/use/ai/v1/messages", headers={"x-keyward-pass": "kwp_fake"},
                                 json={})).status_code == 401
            assert (await c.post("/passes", json={"subject": "x", "routes": ["ai"]})).status_code == 401
            bad = await c.post("/passes", headers=env.agent, json={"subject": "x", "routes": ["evil"]})
            assert bad.status_code == 400
            too_long = await c.post("/passes", headers=env.agent,
                                    json={"subject": "x", "routes": ["ai"], "ttl": 99999})
            assert too_long.status_code == 400
    run(go())
    assert env.up.requests == []


def test_pass_expires_and_runs_out(tmp_path):
    env = Env(tmp_path)
    clock = [1000.0]
    env.broker.passes._clock = lambda: clock[0]

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai"], uses=1, ttl=60)
            assert (await c.post("/use/ai/v1/messages", headers=p, json={})).status_code == 200
            r = await c.post("/use/ai/v1/messages", headers=p, json={})
            assert r.status_code == 401 and "used up" in r.text
            p2 = await env.new_pass(c, routes=["ai"], ttl=60)
            clock[0] += 61
            r = await c.post("/use/ai/v1/messages", headers=p2, json={})
            assert r.status_code == 401 and "expired" in r.text
    run(go())


# --------------------------------------------------- inject, strip, clean --
def test_injects_strips_and_redacts(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c)
            r = await c.post("/use/ai/v1/messages?beta=1",
                             headers={**p, "authorization": "Bearer attacker", "x-api-key": "attacker",
                                      "cookie": "a=b", "anthropic-version": "2023-06-01"},
                             json={"q": "hello"})
            return r
    r = run(go())
    assert r.status_code == 200
    sent = env.up.requests[0]
    assert sent.url == "https://api.ai.example/v1/messages?beta=1"
    assert sent.headers["x-api-key"] == AI_KEY
    assert "authorization" not in sent.headers and "cookie" not in sent.headers
    assert "x-keyward-pass" not in sent.headers
    assert sent.headers["anthropic-version"] == "2023-06-01"
    # the echoed key never reaches the agent; cookie dropped; safe header kept
    assert AI_KEY not in r.text and "[REDACTED]" in r.text
    assert "set-cookie" not in r.headers and r.headers["x-request-id"] == "r1"
    assert AI_KEY not in env.receipts_text()


def test_basic_auth_injection_and_base64_redaction(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["pay"])
            return await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 20000})
    r = run(go())
    assert r.status_code == 200
    assert env.up.requests[0].headers["authorization"] == "Basic " + base64.b64encode(RZP_KEY.encode()).decode()


# ------------------------------------------------------------------- rules --
@pytest.mark.parametrize("method,path", [
    ("POST", "/use/ai/v1/other"),
    ("GET", "/use/ai/v1/messages"),
    ("POST", "/use/ai/v1/messages/../../admin"),
    ("POST", "/use/ai/v1/%2e%2e/messages"),
    ("POST", "/use/ai//v1/messages"),
    ("POST", "/use/nope/v1/messages"),
])
def test_denied_by_rules(tmp_path, method, path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c)
            return await c.request(method, path, headers=p, json={})
    r = run(go())
    assert r.status_code in (403, 404, 405)
    assert env.up.requests == []


def test_route_not_in_pass(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai"])
            return await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 100})
    assert run(go()).status_code == 403


def test_redirects_not_followed(tmp_path):
    env = Env(tmp_path)

    def handler(request):
        env.up.requests.append(request)
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})
    env.broker.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai"])
            return await c.post("/use/ai/v1/messages", headers=p, json={})
    r = run(go())
    assert r.status_code == 302 and "location" not in r.headers
    assert len(env.up.requests) == 1


# ------------------------------------------------------------------ freeze --
def test_freeze_blocks_and_cancels_passes(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai"])
            assert (await c.post("/admin/freeze")).status_code == 401  # no admin token
            assert (await c.post("/admin/freeze", headers=env.agent)).status_code == 401
            assert (await c.post("/admin/freeze", headers=env.admin)).status_code == 200
            assert (await c.post("/passes", headers=env.agent,
                                 json={"subject": "x", "routes": ["ai"]})).status_code == 423
            assert (await c.post("/use/ai/v1/messages", headers=p, json={})).status_code == 401
            await c.post("/admin/unfreeze", headers=env.admin)
            p2 = await env.new_pass(c, routes=["ai"])
            assert (await c.post("/use/ai/v1/messages", headers=p2, json={})).status_code == 200
    run(go())
    assert not (tmp_path / "FROZEN").exists()


def test_freeze_survives_restart(tmp_path):
    env = Env(tmp_path)
    env.broker.freeze("test")
    again = Broker(env.vault, env.rules, tmp_path, transport=httpx.MockTransport(env.up))
    assert again.frozen


# ------------------------------------------------------------------ budget --
def test_call_limit(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai"])
            codes = [(await c.post("/use/ai/v1/messages", headers=p, json={})).status_code for _ in range(4)]
            return codes
    assert run(go()) == [200, 200, 200, 429]


def test_money_limits(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["pay"])
            no_amount = await c.post("/use/pay/v1/payment_links", headers=p, json={"amt": 1})
            text_amount = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": "500"})
            over_request = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 250000})
            ok1 = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 50000})
            env.up.status = 500  # failed payments don't use up the budget
            failed = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 50000})
            env.up.status = 200
            for _ in range(5):  # ₹500 + 5 x ₹500 = ₹3,000: exactly the weekly limit
                last = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 50000})
            over_week = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 50000})
            return no_amount, text_amount, over_request, ok1, failed, last, over_week
    no_amount, text_amount, over_request, ok1, failed, last, over_week = run(go())
    assert no_amount.status_code == 400 and text_amount.status_code == 400
    assert over_request.status_code == 429 and "per-payment" in over_request.text
    assert ok1.status_code == 200 and failed.status_code == 500 and last.status_code == 200
    assert over_week.status_code == 429 and "per-week" in over_week.text  # one more would be ₹3,500


def test_pass_money_cap(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["pay"], max_amount=40000)
            a = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 30000})
            b = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 20000})
            return a, b
    a, b = run(go())
    assert a.status_code == 200 and b.status_code == 403 and "pass money limit" in b.text


# --------------------------------------------------------------- approvals --
async def _wait_pending(env, n=1):
    for _ in range(200):
        if len(env.broker.approvals.pending()) >= n:
            return env.broker.approvals.pending()
        await asyncio.sleep(0.01)
    raise AssertionError("no pending approval")


def test_approval_via_cli_admin(tmp_path):
    env = Env(tmp_path, rules={**RULES, "approvals": {"channel": "terminal"}})

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["pay"])
            small = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 10000})
            task = asyncio.create_task(c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 120000}))
            (a,) = await _wait_pending(env)
            assert "₹1,200.00" in a.summary and "booking-42" in a.summary
            assert len(env.up.requests) == 1  # nothing sent while waiting
            assert (await c.post(f"/admin/approvals/{a.code}", json={"approve": True})).status_code == 401
            ok = await c.post(f"/admin/approvals/{a.code}", headers=env.admin, json={"approve": True})
            assert ok.json()["status"] == "approved"
            big = await task
            # code is single use
            again = await c.post(f"/admin/approvals/{a.code}", headers=env.admin, json={"approve": True})
            return small, big, again
    small, big, again = run(go())
    assert small.status_code == 200 and big.status_code == 200 and again.status_code == 404
    assert len(env.up.requests) == 2


def test_approval_denied_and_timeout(tmp_path):
    env = Env(tmp_path, rules={**RULES, "approvals": {"channel": "terminal"}})
    env.broker.approvals.timeout = 0.2

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["pay"])
            timed_out = await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 120000})
            env.broker.approvals.timeout = 5
            task = asyncio.create_task(c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 120000}))
            (a,) = await _wait_pending(env)
            await c.post(f"/admin/approvals/{a.code}", headers=env.admin, json={"approve": False})
            return timed_out, await task
    timed_out, denied = run(go())
    assert timed_out.status_code == 403 and "no answer" in timed_out.text
    assert denied.status_code == 403 and "denied" in denied.text
    assert not any(r.url.host == "api.razorpay.com" for r in env.up.requests)


def test_whatsapp_yes_must_be_signed_from_owner_and_fresh(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["pay"])
            task = asyncio.create_task(c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 120000}))
            (a,) = await _wait_pending(env)
            ask = env.up.requests[-1]
            assert ask.url.host == "graph.facebook.com" and a.code in ask.content.decode()
            inbound = "/channels/whatsapp/inbound"
            # 1. the agent forges a YES without WhatsApp's signature
            forged = env.signed(wa_message(f"YES {a.code}"), secret="guess")
            r1 = await c.post(inbound, headers=env.agent, json=forged)
            # 2. a correctly signed YES from someone else
            r2 = await c.post(inbound, headers=env.agent, json=env.signed(wa_message(f"YES {a.code}", sender="911111111111")))
            # 3. an old (replayed) message from the owner
            r3 = await c.post(inbound, headers=env.agent,
                              json=env.signed(wa_message(f"YES {a.code}", ts=time.time() - 3600, mid="old")))
            assert a.status == "pending"
            # 4. the real thing
            r4 = await c.post(inbound, headers=env.agent, json=env.signed(wa_message(f"YES {a.code}", mid="real")))
            result = await task
            # 5. the same signed message replayed
            r5 = await c.post(inbound, headers=env.agent, json=env.signed(wa_message("FREEZE", mid="real")))
            return r1, r2, r3, r4, result, r5
    r1, r2, r3, r4, result, r5 = run(go())
    assert r1.status_code == 403
    assert r2.json() == {"handled": False} and r3.json() == {"handled": False}
    assert r4.json() == {"handled": True} and result.status_code == 200
    assert r5.json() == {"handled": False} and not env.broker.frozen


def test_whatsapp_freeze_and_today(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai"])
            await c.post("/use/ai/v1/messages", headers=p, json={})
            r = await c.post("/channels/whatsapp/inbound", headers=env.agent,
                             json=env.signed(wa_message("today", mid="t1")))
            assert r.json()["handled"]
            today_msg = json.loads(env.up.requests[-1].content)["text"]["body"]
            r = await c.post("/channels/whatsapp/inbound", headers=env.agent,
                             json=env.signed(wa_message("FREEZE", mid="f1")))
            blocked = await c.post("/use/ai/v1/messages", headers=p, json={})
            return today_msg, blocked
    today_msg, blocked = run(go())
    assert "used ai" in today_msg
    assert env.broker.frozen and blocked.status_code == 401  # pass was cancelled by the freeze


# -------------------------------------------------------------------- misc --
def test_verify_endpoint(tmp_path):
    env = Env(tmp_path)
    body = b'{"event":"payment_link.paid"}'
    good = hmac.new(b"rzp-webhook-secret-1", body, hashlib.sha256).hexdigest()

    async def go():
        async with env.client() as c:
            payload = base64.b64encode(body).decode()
            ok = await c.post("/verify/razorpay", headers=env.agent, json={"payload_b64": payload, "signature": good})
            bad = await c.post("/verify/razorpay", headers=env.agent, json={"payload_b64": payload, "signature": "00"})
            anon = await c.post("/verify/razorpay", json={"payload_b64": payload, "signature": good})
            return ok, bad, anon
    ok, bad, anon = run(go())
    assert ok.json() == {"valid": True} and bad.json() == {"valid": False} and anon.status_code == 401


def test_expired_secret_gives_503(tmp_path):
    env = Env(tmp_path)
    from datetime import datetime, timedelta, timezone
    env.vault.set("AI_KEY", "sk-ai-short-lived-0001", ttl="1m",
                  now=datetime.now(timezone.utc) - timedelta(minutes=5))

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai"])
            return await c.post("/use/ai/v1/messages", headers=p, json={})
    r = run(go())
    assert r.status_code == 503 and env.up.requests == []


def test_admin_status_and_no_secrets_anywhere(tmp_path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai", "pay"])
            await c.post("/use/ai/v1/messages", headers=p, json={})
            await c.post("/use/pay/v1/payment_links", headers=p, json={"amount": 1000})
            return await c.get("/admin/status", headers=env.admin)
    status = run(go())
    assert status.status_code == 200 and status.json()["missing_secrets"] == []
    everything = status.text + env.receipts_text()
    for secret in (AI_KEY, WA_TOKEN, RZP_KEY, WA_APP_SECRET, env.vault.get(AGENT_TOKEN)):
        assert secret not in everything


@pytest.mark.parametrize("path", ["/admin/status", "/%61dmin/status", "/admin/../admin/status"])
def test_admin_paths_need_admin_token(tmp_path, path):
    env = Env(tmp_path)

    async def go():
        async with env.client() as c:
            return await c.get(path, headers=env.agent)
    assert run(go()).status_code in (401, 404)


def test_oversized_body_without_content_length(tmp_path):
    env = Env(tmp_path)

    async def chunks():
        for _ in range(3):
            yield b"x" * 600_000

    async def go():
        async with env.client() as c:
            p = await env.new_pass(c, routes=["ai"])
            return await c.post("/use/ai/v1/messages", headers=p, content=chunks())
    r = run(go())
    assert r.status_code == 413 and env.up.requests == []


# ------------------------------------------------------------------- rules --
@pytest.mark.parametrize("patch,msg", [
    ({"broker": {"host": "0.0.0.0"}}, "local-only"),
    ({"routes": {"x": {**RULES["routes"]["ai"], "upstream": "http://api.ai.example"}}}, "https"),
    ({"routes": {"x": {**RULES["routes"]["ai"], "upstream": "https://api.ai.example/v1"}}}, "no path"),
    ({"routes": {"x": {**RULES["routes"]["ai"], "inject": {"header": "x-api-key", "format": "nokey"}}}}, "secret"),
    ({"routes": {"x": {**RULES["routes"]["ai"], "allow": []}}}, "at least one"),
    ({"routes": {"x": {**RULES["routes"]["ai"], "allow": [{"method": "POST", "path": "v1"}]}}}, "start with"),
    ({"routes": {"x": {**RULES["routes"]["ai"], "surprise": 1}}}, "Unknown"),
    ({"approvals": {"channel": "carrier-pigeon"}}, "terminal"),
])
def test_rules_validation(patch, msg):
    doc = {"routes": {"ai": RULES["routes"]["ai"]}}
    doc.update(patch)
    with pytest.raises(RulesError, match=msg):
        parse_rules(doc)


def test_whatsapp_channel_path_must_be_allowed():
    doc = json.loads(json.dumps(RULES))
    doc["approvals"]["whatsapp"]["path"] = "/v21.0/999/messages"
    with pytest.raises(RulesError, match="allowed"):
        parse_rules(doc)
