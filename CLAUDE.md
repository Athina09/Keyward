# Keyward

Keyward lets an AI agent use keys and money only with a human YES and within budgets.
Read README.md, docs/how-it-works.md and SECURITY.md before changing anything.

## Layout

```
keyward/crypto.py     Argon2id + AES-256-GCM (no I/O, no printing)
keyward/vault.py      encrypted vault: versions, undo, expiry, check
keyward/rules.py      rules.toml loading and validation (deny by default)
keyward/passes.py     task passes (hashed tokens, uses, money cap, expiry)
keyward/budget.py     SQLite call/money limits with atomic reservation
keyward/approvals.py  waiting requests and one-time codes
keyward/receipts.py   JSONL receipts (never bodies or secrets)
keyward/broker.py     FastAPI broker: /passes, /use, /verify, /channels/whatsapp/inbound, /admin
keyward/cli.py        the `keyward` command
tests/                pytest; fake upstreams via httpx.MockTransport
```

## How we work

- Tests first. Run `pytest -q` after every change; all tests must pass.
- Keep it small and readable. Ask before adding a dependency.
- Update README.md / ROADMAP.md when behaviour changes.

## Security rules (never break these)

1. No secret value is ever printed, logged, put in an error message, a receipt, a test snapshot or a commit.
2. Secrets are never accepted as command-line arguments. Use getpass or stdin.
3. Crypto: Argon2id + AES-256-GCM, fresh 12-byte random nonce per encryption. No home-made crypto.
4. Every unlock failure says exactly: `Wrong password or damaged vault`.
5. Compare tokens, passes and signatures with `hmac.compare_digest`, never `==`.
6. The broker listens on loopback only. Anything not in rules.toml is refused.
7. Outbound: HTTPS only, the route's host only, no redirects, timeouts and size limits.
8. Strip caller credentials before injecting the real one.
9. Approvals count only from the admin token or a signed, owner-sent, fresh WhatsApp message with a valid one-time code.
10. Files are written with permission 600; the vault atomically.

## Never commit

`vault.kw`, `*.tmp`, `.env`, `receipts.jsonl`, `budget.db`, `FROZEN`, any real key. Use test keys only.
