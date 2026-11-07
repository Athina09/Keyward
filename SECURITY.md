# Security

Keyward is **alpha software that has not been professionally audited.** Start with test keys
(Razorpay test mode, the WhatsApp test number) and small limits.

## Reporting a vulnerability

Please **don't open a public issue.** Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") with steps to reproduce. We aim to reply within 7 days.

## What Keyward protects against

| Threat | Protection |
|---|---|
| Prompt injection asking the agent to reveal a key | The agent never has the key |
| A hijacked agent calling other APIs or hosts | Deny-by-default rules; one fixed HTTPS host per route; no redirects |
| A hijacked agent spending money | Task-pass money caps, budgets, human approval |
| An agent faking the owner's "YES" | Approvals need the admin token or a WhatsApp message whose signature, sender, age and one-time code all check out |
| Replayed WhatsApp commands | Message IDs are remembered; messages older than 5 minutes are ignored |
| Keys leaking back in API replies | Exact and base64 copies are replaced with `[REDACTED]`; only safe headers are returned |
| Stolen vault file | Argon2id + AES-256-GCM; authenticated header; one generic error for every failure |
| Keys in logs | Receipts never contain bodies or secret values |

## What it does not protect against

- Someone with root, or with your user account, on the machine **while the broker runs**: they can read its memory.
- A weak master password.
- An upstream API that returns a secret in a transformed form (e.g. partially masked or re-encoded).
- Misconfigured rules: an `allow` pattern like `^/.*$` allows everything on that host.

## Design rules for contributors

1. No secret value is ever printed, logged, put in an error, a receipt or a test snapshot.
2. Secrets are never accepted as command-line arguments.
3. Argon2id + AES-256-GCM with a fresh random nonce per encryption. No home-made crypto.
4. Tokens, passes and signatures are compared with `hmac.compare_digest`.
5. The broker binds to loopback only and refuses anything not in the rules.
6. Outbound: HTTPS only, no redirects, timeouts, size limits.
