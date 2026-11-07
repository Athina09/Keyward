# Keyward

**Let an AI agent use your keys and your money, but only with your yes, and only within your limits.**

AI agents are starting to book, buy and pay for people. Giving an agent your API keys or payment
credentials means trusting every prompt it will ever read. Keyward sits between the agent and the
outside world:

- The agent **never holds a real key.** Keyward adds it to approved requests at the last moment.
- Risky actions **wait for a human YES**, in your terminal or on WhatsApp.
- **Budgets** cap calls and money: ₹2,000 per payment, ₹5,000 per week, 20 messages a minute.
- Each job gets a **task pass** that expires, so a hijacked agent can only finish the job in hand.
- Every use leaves a **plain-language receipt**, and one **FREEZE** stops everything.

```
            ┌───────────┐   pass + request    ┌───────────────────────────┐    real key    ┌──────────┐
            │  Agent    │ ──────────────────► │         Keyward           │ ─────────────► │   APIs   │
            │ (no keys) │ ◄────────────────── │ rules · budgets · approval│ ◄───────────── │          │
            └───────────┘   cleaned reply     └─────────────┬─────────────┘                └──────────┘
                                                            │  YES 482913 / FREEZE
                                                      ┌─────┴─────┐
                                                      │    You    │
                                                      └───────────┘
```

> **Status: alpha (0.1).** It works and is tested, but it has not had a professional security audit.
> Use test keys first. See [SECURITY.md](SECURITY.md).

## How it's different

Credential brokers for agents already exist, such as vaultx and Infisical Agent Vault, and Keyward builds
on the same core idea of injecting a secret into an approved request. Keyward focuses on what those
tools leave out: **a human in the loop and money limits**, for agents that act on people's behalf
rather than for coding agents in a terminal.

| | Keyward |
|---|---|
| Human approval | Built in: terminal or WhatsApp, one-time 6-digit codes |
| Money | Per-payment, per-day and per-week limits; "ask me above ₹500" |
| Access | Task passes: routes, uses, money cap and expiry per job |
| Kill switch | `keyward freeze`, or text FREEZE |
| Secret history | Simple versions with undo (no branches) |
| Size | ~1,900 lines of plain Python, 51 tests |

## Quickstart (5 minutes)

```bash
git clone https://github.com/Athina09/Keyward && cd Keyward
pip install -e .               # Python 3.11+

keyward init                   # create the encrypted vault (~/.keyward/vault.kw)
keyward set GEMINI_API_KEY --ttl 90d     # value is typed hidden
cp examples/rules.toml rules.toml        # edit to taste
keyward rules                  # validate rules and check the secrets exist
keyward serve                  # broker on http://127.0.0.1:8787
```

In another terminal, give your agent its token (shown only in a real terminal):

```bash
keyward token agent
```

## Using it from an agent

Full walkthrough with a checklist: [docs/integration.md](docs/integration.md).

```python
import httpx, os

KW = "http://127.0.0.1:8787"
agent = {"x-keyward-agent": os.environ["KEYWARD_AGENT_TOKEN"]}

# 1. Get a pass for this job: which routes, how many calls, how much money, how long.
p = httpx.post(f"{KW}/passes", headers=agent, json={
    "subject": "booking-42", "routes": ["ai", "razorpay"],
    "uses": 10, "max_amount": 120000, "ttl": 600,
}).json()["pass"]
use = {"x-keyward-pass": p}

# 2. Call APIs through Keyward. The path after /use/<route> is the real API path.
reply = httpx.post(f"{KW}/use/ai/v1beta/models/gemini-2.5-flash:generateContent",
                   headers=use, json={"contents": [{"parts": [{"text": "Hello"}]}]})

# Above the approve_over amount this waits until you answer "keyward approve <code>".
link = httpx.post(f"{KW}/use/razorpay/v1/payment_links", headers=use, timeout=320,
                  json={"amount": 120000, "currency": "INR", "description": "Table for 4"})

# 3. Done: throw the pass away.
httpx.request("DELETE", f"{KW}/passes", headers=use)
```

SDKs work too: point their base URL at `http://127.0.0.1:8787/use/<route>`, set any placeholder API
key (Keyward strips it), and add the `x-keyward-pass` header.

**Webhook signatures** (WhatsApp, Razorpay): the agent asks Keyward whether a webhook is real, without
ever holding the webhook secret:

```python
import base64
httpx.post(f"{KW}/verify/razorpay", headers=agent, json={
    "payload_b64": base64.b64encode(raw_body).decode(),
    "signature": request.headers["x-razorpay-signature"],
}).json()   # {"valid": true}
```

## Rules

`rules.toml` describes everything an agent may do. **Anything not listed is refused.**

```toml
[routes.razorpay]
upstream = "https://api.razorpay.com"            # https only, host only
secret   = "RAZORPAY_KEY"                        # name in the vault
inject   = { header = "Authorization", format = "Basic {secret_base64}" }
allow    = [{ method = "POST", path = "^/v1/payment_links$" }]
limits   = { per_day = 10 }
money    = { field = "amount", currency = "INR", per_request = 200000, per_week = 500000, approve_over = 50000 }
```

See [examples/rules.toml](examples/rules.toml) for Gemini, Anthropic, WhatsApp and Razorpay.

## Approvals on WhatsApp

Set `[approvals] channel = "whatsapp"` and Keyward messages you:

> Keyward: razorpay POST /v1/payment_links for ₹1,200.00 (task: booking-42)
> Reply YES 482913 to allow or NO 482913 to refuse (expires in 5 min).

Your app's WhatsApp webhook receives your reply and forwards the **raw body and signature** to
`POST /channels/whatsapp/inbound`. Keyward checks WhatsApp's signature itself, the sender's number,
the message age and the one-time code, so **the agent cannot fake your YES**. You can also text
`FREEZE`, `UNFREEZE`, `TODAY`, `LIMITS` and `PENDING`.

## Commands

| Command | What it does |
|---|---|
| `keyward init` | Create the vault |
| `keyward set NAME [--ttl 90d] [--note ...]` | Add a new version of a secret |
| `keyward list` · `history NAME` | Names, versions, expiry (never values) |
| `keyward undo NAME` · `use NAME N` | Go back a version / pick a version |
| `keyward remove NAME` · `purge NAME` | Stop using / delete forever |
| `keyward check` | Expired, expiring and old secrets |
| `keyward reveal NAME` | Print a value (interactive terminal only) |
| `keyward token agent [--rotate]` | The agent's token |
| `keyward passwd` | Change the master password |
| `keyward serve` | Run the broker |
| `keyward status` | Freeze state, passes, waiting approvals, usage |
| `keyward approvals` · `approve CODE` · `deny CODE` | Answer requests |
| `keyward freeze` · `unfreeze` | Kill switch |
| `keyward reload` | Apply vault changes to the running broker |
| `keyward receipts [--today]` | What was used, in plain words |
| `keyward rules` | Validate rules.toml |

## How it works

[docs/how-it-works.md](docs/how-it-works.md) explains it in simple words. In short:

- **Vault:** Argon2id (64 MB, 3 passes) turns your password into a key; AES-256-GCM seals one JSON
  document of secrets. The header is authenticated, every failure gives one generic error, and the
  file is written atomically with mode 600.
- **Broker:** runs on 127.0.0.1 only. Every call goes through pass → freeze → rules → budget →
  approval → strip & inject → send (HTTPS, no redirects, size limits) → redact → receipt.

## Limitations (read these)

- If the machine running Keyward is compromised while it runs, the attacker can read its memory.
  Keyward protects keys *from the agent*, not from root.
- An agent running as the same OS user can read Keyward's files. That's fine for the vault (it's
  encrypted) but means receipts and budgets are not secret.
- Redaction catches exact and base64 copies of secrets in replies, not every possible transformation.
- WhatsApp replay protection remembers message IDs in memory; after a restart, only the 5-minute age
  limit applies.
- No streaming responses yet.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT. See [LICENSE](LICENSE).
