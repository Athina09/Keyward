# Roadmap

## 0.1 (done)

- [x] Encrypted vault: Argon2id + AES-256-GCM, authenticated header, generic errors, atomic writes
- [x] Versions, undo, pick a version, expiry, `check`
- [x] Broker on 127.0.0.1 with deny-by-default rules
- [x] Credential injection (header, Bearer, Basic) and stripping of caller credentials
- [x] HTTPS-only, single host per route, no redirects, size limits
- [x] Reply redaction (exact + base64) and safe response headers
- [x] Task passes: routes, uses, money cap, expiry; hashed in memory
- [x] Budgets: calls per minute/hour/day; money per request/day/week; atomic reservation
- [x] Approvals: terminal and WhatsApp (signed, owner-only, fresh, one-time codes)
- [x] FREEZE / UNFREEZE (CLI and WhatsApp), survives restarts, cancels passes
- [x] Receipts in plain words; TODAY, LIMITS, PENDING on WhatsApp
- [x] Webhook signature verification (`/verify/<name>`) without exposing secrets
- [x] CLI, docs, 51 tests

## Next

- [ ] Telegram approval channel
- [ ] Time-of-day rules (e.g. no payments after 23:00)
- [ ] Per-person budgets (limits per pass subject)
- [ ] Streaming responses (for AI APIs)
- [ ] Wipe secrets from memory where Python allows; optional OS keychain unlock
- [ ] Signed, hash-chained receipts (tamper-evident log)
- [ ] Publish to PyPI
- [ ] A simple terminal dashboard
