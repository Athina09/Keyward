"""Load and validate rules.toml. Anything not described here is denied."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
LIMIT_KEYS = {"per_minute", "per_hour", "per_day"}
MONEY_KEYS = {"field", "currency", "per_request", "per_day", "per_week", "approve_over"}
ROUTE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
CURRENCY_SYMBOLS = {"INR": "₹", "USD": "$", "EUR": "€", "GBP": "£"}


class RulesError(Exception):
    pass


@dataclass(frozen=True)
class Allow:
    method: str
    path: re.Pattern


@dataclass(frozen=True)
class Money:
    field: str
    currency: str = "INR"
    per_request: int | None = None  # in minor units (paise, cents)
    per_day: int | None = None
    per_week: int | None = None
    approve_over: int | None = None

    def fmt(self, amount: int) -> str:
        sym = CURRENCY_SYMBOLS.get(self.currency, self.currency + " ")
        return f"{sym}{amount / 100:,.2f}"


@dataclass(frozen=True)
class Route:
    name: str
    upstream: str
    host: str
    secret: str
    inject_header: str
    inject_format: str
    allow: tuple[Allow, ...]
    limits: dict = field(default_factory=dict)
    money: Money | None = None
    approval: bool = False
    timeout: float = 30.0

    def allows(self, method: str, path: str) -> bool:
        return any(a.method == method and a.path.fullmatch(path) for a in self.allow)

    def needs_approval(self, amount: int | None) -> bool:
        if self.approval:
            return True
        return bool(self.money and self.money.approve_over is not None
                    and amount is not None and amount > self.money.approve_over)


@dataclass(frozen=True)
class Verifier:
    name: str
    secret: str
    prefix: str = ""


@dataclass(frozen=True)
class WhatsAppChannel:
    route: str
    path: str
    owner: str
    app_secret: str


@dataclass(frozen=True)
class Rules:
    host: str = "127.0.0.1"
    port: int = 8787
    pass_ttl_max: int = 900
    pass_uses_max: int = 50
    max_request_bytes: int = 1_000_000
    max_response_bytes: int = 5_000_000
    approval_timeout: int = 300
    channel: str = "terminal"
    whatsapp: WhatsAppChannel | None = None
    routes: dict[str, Route] = field(default_factory=dict)
    verifiers: dict[str, Verifier] = field(default_factory=dict)


def _int(d: dict, key: str, default: int | None, where: str, minimum: int = 0) -> int | None:
    val = d.get(key, default)
    if val is None:
        return None
    if not isinstance(val, int) or isinstance(val, bool) or val < minimum:
        raise RulesError(f"{where}.{key} must be a whole number >= {minimum}")
    return val


def _unknown(d: dict, allowed: set, where: str) -> None:
    extra = set(d) - allowed
    if extra:
        raise RulesError(f"Unknown setting(s) in {where}: {', '.join(sorted(extra))}")


def _route(name: str, d: dict) -> Route:
    where = f"routes.{name}"
    if not ROUTE_NAME_RE.match(name):
        raise RulesError(f"Route name {name!r}: lowercase letters, digits, _ or -")
    _unknown(d, {"upstream", "secret", "inject", "allow", "limits", "money", "approval", "timeout"}, where)

    upstream = d.get("upstream", "")
    u = urlsplit(upstream)
    if u.scheme != "https" or not u.hostname or u.username or u.password \
            or u.path not in ("", "/") or u.query or u.fragment:
        raise RulesError(f"{where}.upstream must be like https://api.example.com (https, no path)")

    secret = d.get("secret")
    if not isinstance(secret, str) or not secret:
        raise RulesError(f"{where}.secret must name a secret in the vault")

    inject = d.get("inject") or {}
    _unknown(inject, {"header", "format"}, f"{where}.inject")
    header, fmt = inject.get("header", ""), inject.get("format", "")
    if not HEADER_RE.match(header):
        raise RulesError(f"{where}.inject.header must be a header name, e.g. Authorization")
    if "{secret}" not in fmt and "{secret_base64}" not in fmt:
        raise RulesError(f"{where}.inject.format must contain {{secret}} or {{secret_base64}}")

    allow = []
    for i, a in enumerate(d.get("allow") or []):
        _unknown(a, {"method", "path"}, f"{where}.allow[{i}]")
        method = str(a.get("method", "")).upper()
        if method not in METHODS:
            raise RulesError(f"{where}.allow[{i}].method must be one of {sorted(METHODS)}")
        try:
            pattern = re.compile(a.get("path", ""))
        except re.error as e:
            raise RulesError(f"{where}.allow[{i}].path is not a valid regex: {e}") from None
        if not a.get("path", "").startswith("^/"):
            raise RulesError(f"{where}.allow[{i}].path must start with ^/")
        allow.append(Allow(method, pattern))
    if not allow:
        raise RulesError(f"{where}.allow needs at least one rule")

    limits = d.get("limits") or {}
    _unknown(limits, LIMIT_KEYS, f"{where}.limits")
    limits = {k: _int(limits, k, None, f"{where}.limits", 1) for k in limits}

    money = None
    if "money" in d:
        m = d["money"]
        _unknown(m, MONEY_KEYS, f"{where}.money")
        if not isinstance(m.get("field"), str) or not m["field"]:
            raise RulesError(f"{where}.money.field must name the amount field in the request body")
        money = Money(
            field=m["field"],
            currency=str(m.get("currency", "INR")).upper(),
            per_request=_int(m, "per_request", None, f"{where}.money"),
            per_day=_int(m, "per_day", None, f"{where}.money"),
            per_week=_int(m, "per_week", None, f"{where}.money"),
            approve_over=_int(m, "approve_over", None, f"{where}.money"),
        )

    approval = d.get("approval", False)
    if not isinstance(approval, bool):
        raise RulesError(f"{where}.approval must be true or false")
    timeout = d.get("timeout", 30)
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 120:
        raise RulesError(f"{where}.timeout must be between 1 and 120 seconds")

    return Route(name=name, upstream=f"https://{u.netloc}", host=u.hostname, secret=secret,
                 inject_header=header, inject_format=fmt, allow=tuple(allow), limits=limits,
                 money=money, approval=approval, timeout=float(timeout))


def parse_rules(doc: dict) -> Rules:
    _unknown(doc, {"broker", "approvals", "routes", "verifiers"}, "rules.toml")
    b = doc.get("broker") or {}
    _unknown(b, {"host", "port", "pass_ttl_max", "pass_uses_max", "max_request_bytes",
                 "max_response_bytes"}, "broker")
    host = b.get("host", "127.0.0.1")
    if host not in LOOPBACK:
        raise RulesError("broker.host must be 127.0.0.1, ::1 or localhost (Keyward is local-only)")

    routes = {name: _route(name, r) for name, r in (doc.get("routes") or {}).items()}

    verifiers = {}
    for name, v in (doc.get("verifiers") or {}).items():
        _unknown(v, {"secret", "prefix"}, f"verifiers.{name}")
        if not ROUTE_NAME_RE.match(name) or not isinstance(v.get("secret"), str):
            raise RulesError(f"verifiers.{name} needs a valid name and a 'secret'")
        verifiers[name] = Verifier(name, v["secret"], str(v.get("prefix", "")))

    a = doc.get("approvals") or {}
    _unknown(a, {"channel", "timeout", "whatsapp"}, "approvals")
    channel = a.get("channel", "terminal")
    whatsapp = None
    if channel == "whatsapp":
        w = a.get("whatsapp") or {}
        _unknown(w, {"route", "path", "owner", "app_secret"}, "approvals.whatsapp")
        if w.get("route") not in routes:
            raise RulesError("approvals.whatsapp.route must name a route used to send messages")
        if not re.fullmatch(r"\d{8,15}", str(w.get("owner", ""))):
            raise RulesError("approvals.whatsapp.owner must be a number with country code, digits only")
        if not routes[w["route"]].allows("POST", str(w.get("path", ""))):
            raise RulesError("approvals.whatsapp.path must be allowed by that route's rules")
        if not isinstance(w.get("app_secret"), str):
            raise RulesError("approvals.whatsapp.app_secret must name the WhatsApp app secret in the vault")
        whatsapp = WhatsAppChannel(w["route"], w["path"], str(w["owner"]), w["app_secret"])
    elif channel != "terminal":
        raise RulesError("approvals.channel must be 'terminal' or 'whatsapp'")

    return Rules(
        host=host,
        port=_int(b, "port", 8787, "broker", 1),
        pass_ttl_max=_int(b, "pass_ttl_max", 900, "broker", 30),
        pass_uses_max=_int(b, "pass_uses_max", 50, "broker", 1),
        max_request_bytes=_int(b, "max_request_bytes", 1_000_000, "broker", 1024),
        max_response_bytes=_int(b, "max_response_bytes", 5_000_000, "broker", 1024),
        approval_timeout=_int(a, "timeout", 300, "approvals", 10),
        channel=channel,
        whatsapp=whatsapp,
        routes=routes,
        verifiers=verifiers,
    )


def load_rules(path: str | Path) -> Rules:
    try:
        with open(path, "rb") as f:
            return parse_rules(tomllib.load(f))
    except FileNotFoundError:
        raise RulesError(f"Rules file not found: {path}") from None
    except tomllib.TOMLDecodeError as e:
        raise RulesError(f"rules.toml is not valid TOML: {e}") from None
