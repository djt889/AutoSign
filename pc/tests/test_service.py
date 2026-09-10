"""test_service.py — crypto / db / config 服务层测试。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


# ---------- crypto ----------

def test_crypto_roundtrip(tmp_path, monkeypatch):
    from pc.service import crypto
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    enc = crypto.encrypt("hunter2密码")
    assert enc.startswith("enc:")
    assert crypto.decrypt(enc) == "hunter2密码"
    assert crypto.is_encrypted(enc)
    assert not crypto.is_encrypted("plain")


def test_crypto_idempotent_and_empty(tmp_path, monkeypatch):
    from pc.service import crypto
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    once = crypto.encrypt("abc")
    assert crypto.encrypt(once) == once        # 已加密幂等
    assert crypto.encrypt("") == ""            # 空串不加密


def test_crypto_rejects_plaintext_decrypt(tmp_path, monkeypatch):
    from pc.service import crypto
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt("plaintext")


def test_crypto_key_mismatch(tmp_path, monkeypatch):
    from pc.service import crypto
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "k1.key")
    enc = crypto.encrypt("secret")
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "k2.key")
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt(enc)


# ---------- config ----------

def test_config_site_key_of():
    from pc.service import config
    assert config.site_key_of("https://api.justwoker.icu/") == "api-justwoker-icu"
    assert config.site_key_of("AgentRouter.ORG") == "agentrouter-org"
    assert config.site_key_of("") == "site"


def test_config_roundtrip_and_find(tmp_path, monkeypatch):
    from pc.service import config
    monkeypatch.setattr(config, "CFG_PATH", tmp_path / "config.json")
    cfg = config.load()
    cfg["sites"].append({
        "key": "s1", "name": "站1", "baseUrl": "https://s1.example.com",
        "checkinType": "manual",
        "accounts": [{"key": "a1", "alias": "主号", "token": "t1"}],
    })
    config.save(cfg)
    cfg2 = config.load()
    site, acc = config.find_account(cfg2, "a1")
    assert site["key"] == "s1" and acc["token"] == "t1"
    assert config.find_account(cfg2, "nope") is None


def test_config_site_meta(tmp_path, monkeypatch):
    from pc.service import config
    monkeypatch.setattr(config, "CFG_PATH", tmp_path / "config.json")
    cfg = config.load()
    cfg["sites"].append({"key": "s1", "baseUrl": "https://x.com", "accounts": []})
    config.put_site_meta(cfg, "s1", "stateMethod", "get")
    assert config.site_meta(cfg, "s1", "stateMethod") == "get"
    assert config.site_meta(cfg, "s1", "missing", "dft") == "dft"


def test_config_update_atomic_no_lost_write(tmp_path, monkeypatch):
    """回归:并发 load→改→save 会丢账号(实测 90 条只落盘 34 条)。

    config.update 保证整段 load→mutator→save 在锁内原子完成,并发不再覆盖。
    """
    import threading
    from pc.service import config
    monkeypatch.setattr(config, "CFG_PATH", tmp_path / "config.json")
    cfg = config.load()
    cfg["sites"].append({"key": "s1", "name": "站1", "baseUrl": "https://s1.com",
                         "checkinType": "newapi", "accounts": []})
    config.save(cfg)

    N_THREADS, N_EACH = 6, 15

    def add_many(tag):
        for i in range(N_EACH):
            key = "acc_%s_%d" % (tag, i)

            def _mut(c):
                s = next((x for x in c["sites"] if x["key"] == "s1"), None)
                if s is not None:
                    s.setdefault("accounts", []).append({"key": key})

            config.update(_mut)

    threads = [threading.Thread(target=add_many, args=("t%d" % i,)) for i in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cfg2 = config.load()
    site = next(x for x in cfg2["sites"] if x["key"] == "s1")
    assert len(site["accounts"]) == N_THREADS * N_EACH  # 一条都不能丢


# ---------- db ----------

def test_db_append_and_recent(tmp_path, monkeypatch):
    from pc.service import db
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "_p", lambda name: tmp_path / name)
    db.append_log("s1", "a1", "checkin", {"http": 200}, level="info")
    db.append_log("s1", "a2", "error", {"msg": "x"}, level="err")
    logs = db.recent_logs(10)
    assert len(logs) == 2
    assert logs[0]["event"] == "error"      # 最新在前
    assert logs[0]["level"] == "err"
    assert {"time", "site", "account", "event", "detail"} <= set(logs[0])
