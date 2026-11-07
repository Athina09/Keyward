import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from keyward.crypto import GENERIC_ERROR, KdfParams, VaultError, derive_key, new_salt, seal, unseal
from keyward.vault import ADMIN_TOKEN, AGENT_TOKEN, Vault, parse_ttl

from .conftest import FAST, PASSWORD

T0 = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- crypto --
def test_seal_roundtrip_and_fresh_nonce():
    key = derive_key("pw-123456789", new_salt(), FAST)
    a, b = seal(key, b"hello"), seal(key, b"hello")
    assert a != b
    assert unseal(key, a) == b"hello"


def test_unseal_wrong_key_and_tamper_give_same_error():
    salt = new_salt()
    key = derive_key("pw-123456789", salt, FAST)
    blob = seal(key, b"hello", b"aad")
    with pytest.raises(VaultError, match=GENERIC_ERROR):
        unseal(derive_key("other-password", salt, FAST), blob, b"aad")
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(VaultError, match=GENERIC_ERROR):
        unseal(key, tampered, b"aad")
    with pytest.raises(VaultError, match=GENERIC_ERROR):
        unseal(key, blob, b"other-aad")


def test_weak_kdf_params_refused():
    with pytest.raises(VaultError):
        KdfParams.from_dict({"time_cost": 1, "memory_cost": 16, "parallelism": 1})


# ----------------------------------------------------------------- vault --
def make(tmp_path):
    return Vault.create(tmp_path / "vault.kw", PASSWORD, FAST)


def test_create_open_and_file_is_private(tmp_path):
    v = make(tmp_path)
    v.set("API_KEY", "sk-live-abcdef123456")
    v.save()
    mode = stat.S_IMODE(os.stat(tmp_path / "vault.kw").st_mode)
    assert mode == 0o600
    assert b"sk-live-abcdef123456" not in (tmp_path / "vault.kw").read_bytes()
    assert Vault.open(tmp_path / "vault.kw", PASSWORD).get("API_KEY") == "sk-live-abcdef123456"


def test_init_creates_internal_tokens(tmp_path):
    v = make(tmp_path)
    assert v.get(AGENT_TOKEN).startswith("kw_") and v.get(ADMIN_TOKEN).startswith("kw_")
    assert v.get(AGENT_TOKEN) != v.get(ADMIN_TOKEN)
    with pytest.raises(VaultError):
        v.remove(AGENT_TOKEN)


def test_wrong_password_and_tampering_same_message(tmp_path):
    make(tmp_path)
    path = tmp_path / "vault.kw"
    with pytest.raises(VaultError, match=f"^{GENERIC_ERROR}$"):
        Vault.open(path, "wrong password!!")
    outer = json.loads(path.read_bytes())
    # tamper with the header: must also fail, since the header is authenticated
    outer["header"]["kdf"]["time_cost"] = 2
    path.write_text(json.dumps(outer))
    with pytest.raises(VaultError, match=f"^{GENERIC_ERROR}$"):
        Vault.open(path, PASSWORD)
    path.write_text("not json")
    with pytest.raises(VaultError, match=f"^{GENERIC_ERROR}$"):
        Vault.open(path, PASSWORD)


def test_short_password_refused(tmp_path):
    with pytest.raises(VaultError, match="at least 10"):
        Vault.create(tmp_path / "v.kw", "short", FAST)


def test_versions_history_and_undo(tmp_path):
    v = make(tmp_path)
    assert v.set("TOKEN", "first-value-111", note="first") == 1
    assert v.set("TOKEN", "second-value-222", note="rotated") == 2
    hist = v.history("TOKEN")
    assert [h["version"] for h in hist] == [1, 2]
    assert hist[1]["current"] and not hist[0]["current"]
    assert "value" not in hist[0] and all("value" not in str(h) for h in hist)
    assert v.undo("TOKEN") == 1
    assert v.get("TOKEN") == "first-value-111"
    with pytest.raises(VaultError, match="no earlier version"):
        v.undo("TOKEN")
    v.use_version("TOKEN", 2)
    assert v.get("TOKEN") == "second-value-222"
    v.save()
    assert Vault.open(tmp_path / "vault.kw", PASSWORD).get("TOKEN") == "second-value-222"


def test_expiry_and_check(tmp_path):
    v = make(tmp_path)
    v.set("SHORT", "value-short-1", ttl="1h", now=T0)
    v.set("SOON", "value-soon-12", ttl="3d", now=T0)
    v.set("OLD", "value-old-123", now=T0 - timedelta(days=200))
    v.set("GONE", "value-gone-12", now=T0)
    v.remove("GONE")
    later = T0 + timedelta(hours=2)
    with pytest.raises(VaultError, match="expired"):
        v.get("SHORT", now=later)
    with pytest.raises(VaultError, match="removed"):
        v.get("GONE", now=later)
    issues = {i["name"]: i["issue"] for i in v.check(now=later)}
    assert issues == {"SHORT": "expired", "SOON": "expiring", "OLD": "old", "GONE": "removed"}
    assert "SHORT" not in v.active_values(now=later)
    # setting a new version un-removes and un-expires
    v.set("SHORT", "value-short-2", now=later)
    assert v.get("SHORT", now=later) == "value-short-2"


def test_listing_never_contains_values(tmp_path):
    v = make(tmp_path)
    v.set("API_KEY", "sk-secret-value-xyz")
    blob = json.dumps([v.list(), v.history("API_KEY"), v.check()])
    assert "sk-secret-value-xyz" not in blob
    assert not any(v.get(n) in blob for n in (AGENT_TOKEN, ADMIN_TOKEN))


def test_purge_and_names(tmp_path):
    v = make(tmp_path)
    v.set("X", "value-x-123456")
    v.purge("X")
    assert not v.has("X")
    for bad in ("1abc", "has space", "a" * 65, ""):
        with pytest.raises(VaultError):
            v.set(bad, "value")


def test_ttl_parsing():
    assert parse_ttl("90d") == timedelta(days=90)
    assert parse_ttl("2w") == timedelta(weeks=2)
    for bad in ("0d", "5y", "abc", "-1d"):
        with pytest.raises(VaultError):
            parse_ttl(bad)


def test_change_password(tmp_path):
    v = make(tmp_path)
    v.set("K", "value-k-123456")
    v.change_password("a brand new password", FAST)
    with pytest.raises(VaultError):
        Vault.open(tmp_path / "vault.kw", PASSWORD)
    assert Vault.open(tmp_path / "vault.kw", "a brand new password").get("K") == "value-k-123456"


def test_reload_sees_new_versions(tmp_path):
    broker_view = make(tmp_path)
    cli_view = Vault.open(tmp_path / "vault.kw", PASSWORD)
    cli_view.set("NEW", "value-new-1234")
    cli_view.save()
    broker_view.reload()
    assert broker_view.get("NEW") == "value-new-1234"
