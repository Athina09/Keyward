# Example: Halo (a WhatsApp booking assistant) behind Keyward

Halo is a FastAPI app that receives WhatsApp messages, asks an AI what to reply, and sends replies.
With Keyward, Halo's `.env` holds **no API keys at all**:

```env
KEYWARD_URL=http://127.0.0.1:8787
KEYWARD_AGENT_TOKEN=kw_...        # from `keyward token agent`
WHATSAPP_PHONE_NUMBER_ID=123456789012345
WHATSAPP_VERIFY_TOKEN=any-string-you-chose
OWNER_NUMBER=919876543210
```

The keys live in the vault:

```bash
keyward set GEMINI_API_KEY --ttl 90d
keyward set WHATSAPP_TOKEN
keyward set WHATSAPP_APP_SECRET
keyward set RAZORPAY_KEY             # "rzp_test_xxx:yyy"
keyward set RAZORPAY_WEBHOOK_SECRET
```

Rules: use [rules.toml](rules.toml) with `channel = "whatsapp"` and your phone number ID.

## The three changes in Halo

### 1. A pass per conversation turn

```python
import base64, httpx, os

KW = os.environ["KEYWARD_URL"]
AGENT = {"x-keyward-agent": os.environ["KEYWARD_AGENT_TOKEN"]}
PHONE_ID = os.environ["WHATSAPP_PHONE_NUMBER_ID"]


def new_pass(subject: str) -> dict:
    r = httpx.post(f"{KW}/passes", headers=AGENT, json={
        "subject": subject, "routes": ["ai", "whatsapp", "razorpay"],
        "uses": 10, "max_amount": 200000, "ttl": 600})
    r.raise_for_status()
    return {"x-keyward-pass": r.json()["pass"]}
```

### 2. AI and WhatsApp calls go through Keyward

```python
def ask_ai(p: dict, contents: list) -> dict:
    r = httpx.post(f"{KW}/use/ai/v1beta/models/gemini-2.5-flash:generateContent",
                   headers=p, json={"contents": contents}, timeout=60)
    r.raise_for_status()
    return r.json()


def send_whatsapp(p: dict, to: str, text: str) -> None:
    httpx.post(f"{KW}/use/whatsapp/v21.0/{PHONE_ID}/messages", headers=p, json={
        "messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": text}})


def payment_link(p: dict, paise: int, description: str) -> str:
    # Above `approve_over`, this waits for the owner's YES (up to the approval timeout).
    r = httpx.post(f"{KW}/use/razorpay/v1/payment_links", headers=p, timeout=320,
                   json={"amount": paise, "currency": "INR", "description": description})
    r.raise_for_status()
    return r.json()["short_url"]
```

### 3. The webhook: verify via Keyward, forward the owner's messages

```python
@app.post("/webhook")
async def webhook(request: Request):
    raw = await request.body()
    sig = request.headers.get("x-hub-signature-256", "")
    proof = {"payload_b64": base64.b64encode(raw).decode(), "signature": sig}

    # Is this really from WhatsApp? (Halo doesn't have the app secret.)
    if not httpx.post(f"{KW}/verify/whatsapp", headers=AGENT, json=proof).json().get("valid"):
        raise HTTPException(403)

    # Owner commands (YES 123456, FREEZE, TODAY…) go to Keyward untouched.
    if httpx.post(f"{KW}/channels/whatsapp/inbound", headers=AGENT, json=proof).json().get("handled"):
        return {"ok": True}

    # …otherwise handle the customer's message as usual, with a fresh pass.
```

Halo can forward your messages, but it **can't change them or invent new ones**: Keyward
re-checks WhatsApp's signature, your number, the message age and the one-time code.
