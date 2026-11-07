# Integrating Keyward into your system

This guide shows how to put Keyward between your AI agent (or any app) and the APIs it calls,
so the agent never holds a real key.

> **Alpha.** Use test keys and small limits first. Read [SECURITY.md](../SECURITY.md).
> Passes are created by the agent itself, so they limit a leaked pass, not a hijacked agent.
> Your real protection is `rules.toml`, budgets and human approval. Write those carefully.

## What changes in your app

| Before | After |
|---|---|
| `.env` holds `OPENAI_API_KEY`, `RAZORPAY_KEY`, ... | `.env` holds only `KEYWARD_URL` and `KEYWARD_AGENT_TOKEN` |
| App calls `https://api.example.com/...` | App calls `http://127.0.0.1:8787/use/<route>/...` |
| App sends its own `Authorization` header | App sends `x-keyward-pass`. Keyward adds the real key |
| App checks webhook signatures itself | App asks `POST /verify/<name>` |

Keyward must run on the **same machine** as your app (it listens on loopback only).

## Step 1: Install and create the vault

```bash
pip install -e .                 # Python 3.11+
keyward init                     # asks for a master password (10+ characters)
keyward set GEMINI_API_KEY --ttl 90d     # value is typed hidden; never pass it as an argument
```

Do not set `KEYWARD_PASSWORD` in the environment your agent runs in. Anything that can read that
variable can open the vault.

## Step 2: Describe what the agent may do (`rules.toml`)

```bash
cp examples/rules.toml rules.toml
keyward rules                    # validates the file and checks the secrets exist
```

One block per API. **Anything not listed is refused.**

```toml
[routes.ai]
upstream = "https://generativelanguage.googleapis.com"   # https, host only
secret   = "GEMINI_API_KEY"                              # name in the vault
inject   = { header = "x-goog-api-key", format = "{secret}" }
allow    = [{ method = "POST", path = "^/v1beta/models/[a-z0-9.-]+:generateContent$" }]
limits   = { per_minute = 15, per_day = 500 }
```

Tips:

- Make `allow` as narrow as you can. `^/.*$` allows everything on that host.
- For anything that moves money, set a `money` block (`per_request`, `per_day`, `per_week`,
  `approve_over`) and consider `approval = true`.
- Amounts are whole numbers in minor units (paise, cents). `200000` is ₹2,000.

## Step 3: Start the broker

```bash
keyward serve                    # http://127.0.0.1:8787, asks for the master password once
keyward token agent              # prints the agent token (interactive terminal only)
```

Put the token in your app's environment:

```env
KEYWARD_URL=http://127.0.0.1:8787
KEYWARD_AGENT_TOKEN=kw_...
```

## Step 4: Call APIs through Keyward

Every job follows the same pattern: get a pass, use it, drop it.

```python
import os, httpx

KW = os.environ["KEYWARD_URL"]
AGENT = {"x-keyward-agent": os.environ["KEYWARD_AGENT_TOKEN"]}


def new_pass(subject: str, routes: list[str], uses=10, max_amount=None, ttl=600) -> dict:
    r = httpx.post(f"{KW}/passes", headers=AGENT, json={
        "subject": subject, "routes": routes,
        "uses": uses, "max_amount": max_amount, "ttl": ttl})
    r.raise_for_status()
    return {"x-keyward-pass": r.json()["pass"]}


p = new_pass("booking-42", ["ai", "razorpay"], max_amount=120000)

# The path after /use/<route> is the real API path.
r = httpx.post(f"{KW}/use/ai/v1beta/models/gemini-2.5-flash:generateContent",
               headers=p, json={"contents": [{"parts": [{"text": "Hello"}]}]}, timeout=60)

httpx.request("DELETE", f"{KW}/passes", headers=p)    # done: throw the pass away
```

Pass limits: `ttl` 30 to `pass_ttl_max` seconds (default 900), `uses` 1 to `pass_uses_max`
(default 50), `subject` 1 to 64 characters. Keep the subject plain text: it is shown to you in
approval requests.

### With an SDK

Point the SDK's base URL at `http://127.0.0.1:8787/use/<route>`, give it any placeholder key
(Keyward strips it), and add the pass header.

```python
from anthropic import Anthropic

client = Anthropic(
    base_url="http://127.0.0.1:8787/use/ai",
    api_key="placeholder",
    default_headers={"x-keyward-pass": p["x-keyward-pass"]},
)
```

The SDK's own paths (for example `/v1/messages`) must match an `allow` rule.

### With curl

```bash
curl -s -X POST http://127.0.0.1:8787/use/ai/v1beta/models/gemini-2.5-flash:generateContent \
  -H "x-keyward-pass: $PASS" -H "content-type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

## Step 5: Approvals (risky actions wait for a human)

If a rule asks for approval (`approval = true`, or an amount above `approve_over`), the request
**waits** (up to `approvals.timeout`, default 300 s) until you answer. Set your HTTP client timeout
above that (for example `timeout=320`).

- **Terminal channel (default):** run `keyward approvals`, then `keyward approve CODE` or
  `keyward deny CODE`.
- **WhatsApp channel:** set `[approvals] channel = "whatsapp"` in `rules.toml`. Keyward messages you
  and you reply `YES 482913` or `NO 482913`. See the next section.

A refused or unanswered request returns `403` with `not approved: ...`. Handle that as a normal
outcome in your app.

## Step 6: Webhooks (optional)

### Verify a webhook is real (WhatsApp, Razorpay, ...)

Add a verifier in `rules.toml`:

```toml
[verifiers.razorpay]
secret = "RAZORPAY_WEBHOOK_SECRET"
```

Your webhook handler forwards the raw body and signature. It never holds the webhook secret.

```python
import base64

raw = await request.body()
proof = {"payload_b64": base64.b64encode(raw).decode(),
         "signature": request.headers["x-razorpay-signature"]}
valid = httpx.post(f"{KW}/verify/razorpay", headers=AGENT, json=proof).json()["valid"]
if not valid:
    raise HTTPException(403)
```

### WhatsApp approvals and owner commands

Your WhatsApp webhook must forward the **unmodified** raw body and the `x-hub-signature-256` header
to Keyward. Keyward checks the signature, the sender's number, the message age and the one-time code
itself.

```python
httpx.post(f"{KW}/channels/whatsapp/inbound", headers=AGENT, json={
    "payload_b64": base64.b64encode(raw).decode(),
    "signature": request.headers.get("x-hub-signature-256", "")})
```

The owner can also text `FREEZE`, `UNFREEZE`, `TODAY`, `LIMITS` and `PENDING`. Your app sits in the
middle of that path, so a compromised app could drop a `FREEZE` message. `keyward freeze` in the
terminal always works.

## Step 7: Check it is working

```bash
keyward status                   # frozen?, active passes, waiting approvals, usage
keyward receipts --today         # what was used, in plain words
```

Common responses from `/use`:

| Code | Meaning | What to do |
|---|---|---|
| 401 | Missing, invalid, expired or used-up pass | Get a new pass |
| 403 | Route not on the pass, not in `rules.toml`, pass money limit, or approval refused | Fix the rule or the request |
| 400 | Money route without a positive whole-number amount field | Send the amount in minor units |
| 413 | Request too large | Send less data |
| 423 | Keyward is frozen | Wait for `keyward unfreeze` |
| 429 | A call or money budget is used up | Wait for the window to pass |
| 502 / 503 | Upstream failed / secret is missing or expired | Check `keyward check` and `keyward status` |

After `keyward set` or `keyward undo`, run `keyward reload` so the running broker picks it up.

## Integration checklist

- [ ] The app's `.env` and code contain **no** real API keys (search for them).
- [ ] Every outbound API call goes to `KEYWARD_URL/use/<route>/...`.
- [ ] `rules.toml` allows only the exact methods and paths the app needs.
- [ ] Money routes have `per_request` and `per_week` limits and an `approve_over` threshold.
- [ ] You tested with **test** keys (Razorpay test mode, WhatsApp test number).
- [ ] `KEYWARD_PASSWORD` is not set where the agent can read it.
- [ ] You know how to stop everything: `keyward freeze`.
- [ ] Ideally, Keyward runs as a different OS user than the agent. An agent running as the same user
      can edit `budget.db`, `receipts.jsonl` and `FROZEN`.

## Limits to keep in mind

- Keyward protects keys from the agent, not from root on the same machine.
- No streaming responses yet. Replies larger than `max_response_bytes` (default 5 MB) fail.
- Redaction catches exact and base64 copies of secrets in replies, not other transformations.
- Keyward is local-only. To use it from another machine, run the agent on the Keyward machine.
