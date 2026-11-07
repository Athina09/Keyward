"""The `keyward` command.

Vault:      init, set, list, history, undo, use, remove, purge, check, reveal, token, passwd
Broker:     serve, status, freeze, unfreeze, approvals, approve, deny, reload
Records:    receipts, rules
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .crypto import VaultError
from .receipts import Receipts, describe
from .rules import Rules, RulesError, load_rules
from .vault import ADMIN_TOKEN, AGENT_TOKEN, INTERNAL_NAMES, Vault

DEFAULT_HOME = Path(os.environ.get("KEYWARD_HOME", Path.home() / ".keyward"))


class CliError(Exception):
    pass


# ------------------------------------------------------------------ helpers --
def _password(confirm: bool = False) -> str:
    pw = os.environ.get("KEYWARD_PASSWORD")
    if pw:
        return pw
    pw = getpass.getpass("Master password: ")
    if confirm and getpass.getpass("Repeat password: ") != pw:
        raise CliError("Passwords don't match")
    return pw


def _open(args) -> Vault:
    return Vault.open(args.home / "vault.kw", _password())


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _rules_path(args) -> Path:
    if args.rules:
        return Path(args.rules)
    local = Path("rules.toml")
    return local if local.exists() else args.home / "rules.toml"


def _rules(args, required: bool = True) -> Rules:
    path = _rules_path(args)
    if not path.exists() and not required:
        return Rules()
    return load_rules(path)


def _when(iso: str | None) -> str:
    if not iso:
        return "-"
    return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")


def _admin(args, method: str, path: str, json=None):
    """Call the running broker as the owner (needs the master password)."""
    import httpx

    token = _open(args).get(ADMIN_TOKEN)
    rules = _rules(args, required=False)
    url = f"http://{rules.host if rules.host != '::1' else '[::1]'}:{rules.port}{path}"
    try:
        with httpx.Client(trust_env=False, timeout=10) as c:
            r = c.request(method, url, headers={"x-keyward-admin": token}, json=json)
    except httpx.HTTPError:
        raise CliError(f"Can't reach the broker at {url}. Is `keyward serve` running?") from None
    if r.status_code >= 400:
        try:
            msg = r.json().get("error", r.text)
        except ValueError:
            msg = r.text
        raise CliError(f"Broker said: {msg}")
    return r.json()


def _read_value(args, name: str) -> str:
    if args.stdin:
        value = sys.stdin.readline().rstrip("\n")
    else:
        value = getpass.getpass(f"Value for {name} (hidden): ")
    if not value:
        raise CliError("Empty value, nothing saved")
    return value


# ----------------------------------------------------------------- commands --
def cmd_init(args):
    path = args.home / "vault.kw"
    Vault.create(path, _password(confirm=True))
    print(f"Created vault at {path}")
    print("Next: add secrets with `keyward set NAME`, write rules.toml, then `keyward serve`.")
    print("Give your agent its token with `keyward token agent` (shown once, in this terminal only).")


def cmd_set(args):
    v = _open(args)
    if args.name in INTERNAL_NAMES:
        raise CliError(f"{args.name} is managed by Keyward. Use `keyward token rotate`.")
    num = v.set(args.name, _read_value(args, args.name), ttl=args.ttl, note=args.note or "")
    v.save()
    print(f"Saved {args.name} version {num}" + (f", expires in {args.ttl}" if args.ttl else ""))
    print("If the broker is running, apply it with `keyward reload`.")


def cmd_list(args):
    rows = _open(args).list()
    if not rows:
        print("No secrets yet.")
        return
    print(f"{'NAME':<28} {'VER':>4} {'STATUS':<8} {'EXPIRES':<17}")
    for r in rows:
        label = r["name"] + (" *" if r["internal"] else "")
        print(f"{label:<28} {r['version']:>4} {r['status']:<8} {_when(r['expires']):<17}")
    print("\n* used by Keyward itself")


def cmd_history(args):
    for h in _open(args).history(args.name):
        mark = "→" if h["current"] else " "
        print(f"{mark} v{h['version']:<3} {_when(h['created'])}  expires {_when(h['expires'])}  {h['note']}")


def cmd_undo(args):
    v = _open(args)
    num = v.undo(args.name)
    v.save()
    print(f"{args.name} is back to version {num}. Run `keyward reload` if the broker is running.")


def cmd_use(args):
    v = _open(args)
    v.use_version(args.name, args.version)
    v.save()
    print(f"{args.name} now uses version {args.version}.")


def cmd_remove(args):
    v = _open(args)
    v.remove(args.name)
    v.save()
    print(f"Removed {args.name} (versions kept; `keyward undo {args.name}` or `set` brings it back).")


def cmd_purge(args):
    if not args.yes:
        if not _interactive() or input(f"Delete {args.name} and ALL its versions forever? [y/N] ").lower() != "y":
            raise CliError("Cancelled")
    v = _open(args)
    v.purge(args.name)
    v.save()
    print(f"Purged {args.name}.")


def cmd_check(args):
    issues = _open(args).check()
    if not issues:
        print("All good: nothing expired, expiring soon or very old.")
        return
    for i in issues:
        print(f"{i['issue'].upper():<9} {i['name']:<28} {i['detail']}")


def cmd_reveal(args):
    # A speed bump against scripts and agents, not a hard barrier.
    if not _interactive():
        raise CliError("reveal only works in an interactive terminal")
    print(_open(args).get(args.name))


def cmd_token(args):
    import secrets as pysecrets

    v = _open(args)
    name = {"agent": AGENT_TOKEN, "admin": ADMIN_TOKEN}[args.which]
    if args.rotate:
        v.set(name, "kw_" + pysecrets.token_urlsafe(32), note="rotated")
        v.save()
        print(f"Rotated the {args.which} token. Run `keyward reload` and update your agent's config.")
        if args.which == "admin":
            return
    if args.which == "admin":
        raise CliError("The admin token is used by this CLI only and is never shown.")
    if not _interactive():
        raise CliError("token only shows in an interactive terminal")
    print(v.get(name))
    print("\nPut this in your agent's config as KEYWARD_AGENT_TOKEN. It lets the agent ask for passes,"
          "\nnot read secrets.", file=sys.stderr)


def cmd_passwd(args):
    v = _open(args)
    new = getpass.getpass("New master password: ")
    if getpass.getpass("Repeat new password: ") != new:
        raise CliError("Passwords don't match")
    v.change_password(new)
    print("Master password changed. Restart the broker.")


def cmd_serve(args):
    from .broker import serve

    rules = _rules(args)
    vault = _open(args)
    serve(vault, rules, args.home)


def cmd_status(args):
    s = _admin(args, "GET", "/admin/status")
    print(f"Frozen: {'YES' if s['frozen'] else 'no'}    Approvals via: {s['channel']}")
    if s["missing_secrets"]:
        print(f"Missing or expired secrets: {', '.join(s['missing_secrets'])}")
    print(f"Active passes: {len(s['passes'])}")
    for p in s["passes"]:
        print(f"  {p['id']}  {p['subject']}  routes={','.join(p['routes'])}  uses left={p['uses_left']}")
    for a in s["pending"]:
        print(f"WAITING {a['code']}: {a['summary']}")
    for route, u in s["usage"].items():
        if u:
            print(f"  {route}: " + ", ".join(f"{k} {v['used']}/{v['limit']}" for k, v in u.items()))


def cmd_freeze(args):
    _admin(args, "POST", "/admin/freeze")
    print("Frozen. Every key is blocked and all passes are cancelled.")


def cmd_unfreeze(args):
    _admin(args, "POST", "/admin/unfreeze")
    print("Unfrozen.")


def cmd_approvals(args):
    pending = _admin(args, "GET", "/admin/status")["pending"]
    if not pending:
        print("Nothing waiting.")
    for a in pending:
        left = max(0, int(a["expires"] - time.time()))
        print(f"{a['code']}  {a['summary']}  ({left}s left)")


def _decide(args, approve: bool):
    r = _admin(args, "POST", f"/admin/approvals/{args.code}", json={"approve": approve})
    print(f"{r['status'].capitalize()}: {r['summary']}")


def cmd_reload(args):
    r = _admin(args, "POST", "/admin/reload")
    print("Vault reloaded." + (f" Missing: {', '.join(r['missing_secrets'])}" if r["missing_secrets"] else ""))


def cmd_receipts(args):
    since = None
    if args.today:
        since = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
    recs = Receipts(args.home / "receipts.jsonl").read(since=since, limit=args.n)
    if not recs:
        print("No receipts yet.")
    for r in recs:
        print(describe(r))


def cmd_rules(args):
    rules = _rules(args)
    print(f"{_rules_path(args)} is valid: {len(rules.routes)} route(s), approvals via {rules.channel}.")
    for r in rules.routes.values():
        extra = []
        if r.money:
            extra.append("money")
        if r.approval or (r.money and r.money.approve_over is not None):
            extra.append("approval")
        print(f"  {r.name:<12} {r.upstream:<40} {', '.join(extra)}")
    vault = _open(args)
    needed = {r.secret for r in rules.routes.values()} | {v.secret for v in rules.verifiers.values()}
    if rules.whatsapp:
        needed.add(rules.whatsapp.app_secret)
    missing = sorted(n for n in needed if n not in vault.active_values())
    print("All secrets present." if not missing else f"Missing or expired in the vault: {', '.join(missing)}")


# -------------------------------------------------------------------- main --
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="keyward",
        description="Let an AI agent use your keys and money only with your yes, and within your limits.")
    ap.add_argument("--version", action="version", version=f"keyward {__version__}")
    ap.add_argument("--home", type=Path, default=DEFAULT_HOME, help="data folder (default ~/.keyward)")
    ap.add_argument("--rules", help="rules file (default ./rules.toml, then <home>/rules.toml)")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="command")

    def add(name, fn, help_):
        p = sub.add_parser(name, help=help_)
        p.set_defaults(fn=fn)
        return p

    add("init", cmd_init, "create a new vault")
    p = add("set", cmd_set, "add a new version of a secret (value typed hidden)")
    p.add_argument("name")
    p.add_argument("--ttl", help="expire after e.g. 90d, 12h, 2w")
    p.add_argument("--note", help="short note shown in history (never put secrets here)")
    p.add_argument("--stdin", action="store_true", help="read the value from stdin")
    add("list", cmd_list, "list secrets (names only)")
    add("history", cmd_history, "versions of a secret").add_argument("name")
    add("undo", cmd_undo, "go back to the previous version").add_argument("name")
    p = add("use", cmd_use, "switch to a specific version")
    p.add_argument("name")
    p.add_argument("version", type=int)
    add("remove", cmd_remove, "stop using a secret (versions kept)").add_argument("name")
    p = add("purge", cmd_purge, "delete a secret and all versions forever")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true")
    add("check", cmd_check, "find expired, expiring and old secrets")
    add("reveal", cmd_reveal, "print a secret (interactive terminal only)").add_argument("name")
    p = add("token", cmd_token, "show or rotate Keyward's own tokens")
    p.add_argument("which", choices=["agent", "admin"])
    p.add_argument("--rotate", action="store_true")
    add("passwd", cmd_passwd, "change the master password")
    add("serve", cmd_serve, "run the broker on 127.0.0.1")
    add("status", cmd_status, "broker status: freeze, passes, approvals, usage")
    add("freeze", cmd_freeze, "block every key immediately")
    add("unfreeze", cmd_unfreeze, "allow keys again")
    add("approvals", cmd_approvals, "list requests waiting for your yes")
    add("approve", lambda a: _decide(a, True), "say yes to a waiting request").add_argument("code")
    add("deny", lambda a: _decide(a, False), "say no to a waiting request").add_argument("code")
    add("reload", cmd_reload, "make the running broker re-read the vault")
    p = add("receipts", cmd_receipts, "what was used, in plain words")
    p.add_argument("--today", action="store_true")
    p.add_argument("-n", type=int, default=50)
    add("rules", cmd_rules, "check rules.toml and that its secrets exist")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    args.home = args.home.expanduser()
    try:
        args.fn(args)
        return 0
    except (VaultError, RulesError, CliError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
