# How Keyward Works (in simple words)

## The picture

Think of a shop:

- The **agent** (for example Halo, a WhatsApp booking assistant) is the **receptionist**. It talks to customers.
- **Keyward** is the **manager with the safe**. It holds the keys and the money rules.
- **You** are the **owner**. Big decisions come to you.

The receptionist never touches the safe. It asks the manager, the manager checks the rules, asks
you if needed, does the job, and hands back only the result.

---

## 1. The vault: the safe

One file, `~/.keyward/vault.kw`. Everything inside is scrambled.

- **Locking:** your master password goes through **Argon2id**, a deliberately slow recipe that
  needs 64 MB of memory per guess. That makes password-guessing very expensive. The result is a
  key that locks the data with **AES-256-GCM**, which also detects tampering: change one byte
  and it refuses to open.
- **One error for everything:** a wrong password and a damaged file both say
  *"Wrong password or damaged vault"*, so attackers learn nothing.
- **Versions and undo:** `keyward set` never overwrites; it adds a version. If a new key breaks
  something, `keyward undo NAME` brings back the old one. `history` shows dates and notes, never values.
- **Expiry:** `--ttl 90d` makes a key stop working after 90 days. `keyward check` reminds you.

---

## 2. The broker: the manager

`keyward serve` asks for your password once, opens the vault, and keeps keys **in memory only**.
It listens on `127.0.0.1`, which means "this computer only".

Every request from the agent goes through this checklist. Any "no" stops it:

| # | Check | Question | If no |
|---|---|---|---|
| 1 | Pass | Does the agent have a valid task pass for this route? | 401 |
| 2 | Freeze | Has the owner frozen everything? | 423 |
| 3 | Rules | Is this exact method and path listed in `rules.toml`? | 403 |
| 4 | Budget | Under the call and money limits? | 429 |
| 5 | Approval | Does it need a YES? Did the owner say YES? | 403 |
| 6 | Inject | Remove any key the agent sent; add the real one | |
| 7 | Send | HTTPS to the route's host only; never follow redirects | |
| 8 | Clean | Replace any key found in the reply with `[REDACTED]` | |
| 9 | Receipt | One line: what, when, allowed or not. No bodies, no keys | |

---

## 3. What makes Keyward different

**Task passes.** The agent has a long-term *agent token*, but it can only ask for passes with it,
not use keys. Each job gets a pass, like a cinema ticket: *"booking-42: AI and Razorpay, 10 uses,
max ₹1,200, valid 10 minutes."* After that it's dead. FREEZE cancels all passes at once.

**Budgets.** Like a prepaid card with limits. Even with your YES, a ₹2,500 payment is refused if
the per-payment limit is ₹2,000.

**Ask before acting.** Routes can require approval always, or only above an amount
(`approve_over`). The request waits up to 5 minutes for your answer:

- in the terminal: `keyward approve 482913`
- on WhatsApp: reply `YES 482913`

**Receipts.** `keyward receipts --today`, or text `TODAY`:

```
08:14 used razorpay for ₹1,200.00: razorpay POST /v1/payment_links → 200
08:15 refused razorpay POST /v1/payment_links for ₹2,500.00: ₹2,500.00 is over the ₹2,000.00 per-payment limit
```

---

## 4. Why the agent can't fake your YES

Your WhatsApp reply arrives at the **agent's** webhook first. So couldn't a hacked agent
pretend you said YES?

1. WhatsApp **signs** every webhook with the app secret.
2. The app secret is in Keyward's vault, and the agent doesn't have it.
3. The agent must forward the message **exactly as received**, with WhatsApp's signature.
4. Keyward checks the signature itself, then the sender's number (must be the owner),
   the message age (under 5 minutes) and the message ID (never seen before), and finally the
   one-time code (must belong to a waiting request).

A made-up or replayed YES fails one of these checks and is ignored.

In terminal mode, approving needs the **admin token**, which only the CLI reads from the vault after
you type the master password.

---

## 5. One paid booking, start to finish

1. A friend texts Halo: "Book Barbeque Nation for 4, Saturday 8pm."
2. Halo asks Keyward for a **pass**: routes ai, whatsapp, razorpay; max ₹1,200; 10 minutes.
3. Halo → Keyward: "ask the AI" → pass ✔ rules ✔ budget ✔ → key added → reply cleaned.
4. Halo → Keyward: "create a ₹1,200 payment link".
5. Keyward: rules ✔ budget ✔ → over ₹500 so approval needed → WhatsApp to you:
   *"razorpay … for ₹1,200.00. Reply YES 482913"*.
6. You reply "YES 482913". Halo forwards it with WhatsApp's signature, and Keyward verifies it ✔.
7. Keyward adds the Razorpay key → link created → only the link goes back to Halo.
8. Your friend pays on Razorpay's own page with UPI or card. Nobody else sees the card.
9. Razorpay tells Halo "paid". Halo asks Keyward `/verify/razorpay` whether it's real ✔.
10. Receipt: *"used razorpay for ₹1,200.00 → 200"*.

---

## 6. If something goes wrong

| If this happens… | The attacker gets |
|---|---|
| Someone tricks the AI ("print your API key") | Nothing: the AI never saw a key |
| The agent is hacked | Only what its current pass allows, under budget, needing a real YES |
| Fake or replayed "YES" messages | Ignored |
| `vault.kw` is stolen | Scrambled data, useless without the password |
| Keyward's machine is hacked while it runs | Everything, so keep that machine safe |
