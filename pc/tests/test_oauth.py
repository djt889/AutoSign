"""test_oauth.py — OAuth/静默换凭据/凭据库测试(P2 契约)。

不发真实网络:mock authorize/SiteClient,验证状态机与防风暴语义。
"""
from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from pc.engine import silent_auth as sa  # noqa: E402
from pc.engine import oauth_flow as of  # noqa: E402
from pc.engine.oauth_flow import AuthResult  # noqa: E402


def _patch(monkeypatch, tmp_path):
    from pc.service import config, db, crypto
    monkeypatch.setattr(config, "CFG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "_p", lambda name: tmp_path / name)
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    # 清空防风暴全局状态(测试隔离)
    monkeypatch.setattr(sa, "_last_ok", {})
    monkeypatch.setattr(sa, "_fail_until", {})
    return config, db, crypto


def make_account_cfg(tmp_path):
    cfg = {
        "UA": "T", "proxy": {"enabled": False}, "impersonate": ["chrome"],
        "sites": [{
            "key": "s1", "name": "站1", "baseUrl": "https://s1.example.com",
            "checkinType": "newapi",
            "accounts": [{"key": "a1", "alias": "主号", "githubAccount": "u1",
                          "githubId": "111", "token": "", "siteCookie": ""}],
        }],
    }
    return cfg


# ---------- JWT 解析 ----------

def _jwt(exp: float) -> str:
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'HS256'})}.{b64({'exp': exp})}.sig"


def test_jwt_exp_parsing():
    now = time.time()
    assert sa.jwt_exp_epoch(_jwt(now + 3600)) == pytest.approx(now + 3600, abs=1)
    assert sa.jwt_exp_epoch("not.a-jwt_x") is None
    assert sa.jwt_exp_epoch("") is None


def test_token_expiring_thresholds():
    now = time.time()
    assert sa.token_expiring("") is True                       # 无 token
    assert sa.token_expiring("null") is True
    assert sa.token_expiring(_jwt(now + 10)) is True           # <60s
    assert sa.token_expiring(_jwt(now + 3600)) is False        # 充足
    assert sa.token_expiring("opaque-system-token") is False   # 非 JWT 等 401 兜底


# ---------- 防风暴三重保护 ----------

def test_reuse_window_8s(monkeypatch, tmp_path):
    """成功后 8s 内复用:不再发起 authorize。"""
    config, db, crypto = _patch(monkeypatch, tmp_path)
    cfg = make_account_cfg(tmp_path)
    config.save(cfg)
    site, acc = cfg["sites"][0], cfg["sites"][0]["accounts"][0]

    calls = {"n": 0}
    def fake_authorize(site, account, cfg, credential=None, headful=False):
        calls["n"] += 1
        return AuthResult("ok", "ok", token="t-new", site_cookie="sess=1", github_login="u1")
    monkeypatch.setattr(sa, "authorize", fake_authorize)

    r1 = sa.exchange(site, acc, cfg)
    assert r1.state == "ok" and calls["n"] == 1
    r2 = sa.exchange(site, acc, cfg)       # 8s 内
    assert r2.state == "ok" and calls["n"] == 1   # 复用,未重放


def test_fail_cooldown_90s(monkeypatch, tmp_path):
    """失败后 90s 冷却:冷却期内直接返回 failed,不发 authorize。"""
    config, db, crypto = _patch(monkeypatch, tmp_path)
    cfg = make_account_cfg(tmp_path)
    config.save(cfg)
    site, acc = cfg["sites"][0], cfg["sites"][0]["accounts"][0]

    calls = {"n": 0}
    monkeypatch.setattr(sa, "authorize",
                        lambda *a, **k: (calls.__setitem__("n", calls["n"] + 1),
                                         AuthResult("failed", "x"))[1])
    r1 = sa.exchange(site, acc, cfg)
    assert r1.state == "failed" and calls["n"] == 1
    assert sa.in_cooldown("a1") is True
    r2 = sa.exchange(site, acc, cfg)       # 冷却中
    assert r2.state == "failed" and calls["n"] == 1   # 未重放
    sa.clear_cooldown("a1")                # 手动授权清冷却
    r3 = sa.exchange(site, acc, cfg)
    assert calls["n"] == 2                 # 清了冷却就能再试


def test_force_skips_protections(monkeypatch, tmp_path):
    config, db, crypto = _patch(monkeypatch, tmp_path)
    cfg = make_account_cfg(tmp_path)
    config.save(cfg)
    site, acc = cfg["sites"][0], cfg["sites"][0]["accounts"][0]
    calls = {"n": 0}
    monkeypatch.setattr(sa, "authorize",
                        lambda *a, **k: (calls.__setitem__("n", calls["n"] + 1),
                                         AuthResult("ok", "", token=f"t{calls['n']}"))[1])
    sa.exchange(site, acc, cfg)
    sa.exchange(site, acc, cfg, force=True)     # force 跳过 8s 复用
    assert calls["n"] == 2


# ---------- 落盘:任一变化即成功 ----------

def test_persist_token_and_cookie(monkeypatch, tmp_path):
    config, db, crypto = _patch(monkeypatch, tmp_path)
    cfg = make_account_cfg(tmp_path)
    config.save(cfg)
    site, acc = cfg["sites"][0], cfg["sites"][0]["accounts"][0]

    monkeypatch.setattr(sa, "authorize",
                        lambda *a, **k: AuthResult("ok", "", token="tok1",
                                                   site_cookie="session=zzz",
                                                   site_user_id="42",
                                                   github_login="u1", github_id="111"))
    sa.exchange(site, acc, cfg)
    cfg2 = config.load()
    a2 = cfg2["sites"][0]["accounts"][0]
    # 落库是密文(§7 凭据安全),读回可解密
    from pc.service.secret_store import open_
    assert a2["token"].startswith("enc:")
    assert a2["siteCookie"].startswith("enc:")
    assert open_(a2["token"]) == "tok1"
    assert open_(a2["siteCookie"]) == "session=zzz"
    assert a2["siteUserId"] == "42"


def test_401_auto_reauth_and_retry(monkeypatch, tmp_path):
    """401 ⇒ 静默换新 ⇒ 重试一次,reauthed 标记(平移 callWithAuth)。"""
    config, db, crypto = _patch(monkeypatch, tmp_path)
    cfg = make_account_cfg(tmp_path)
    config.save(cfg)
    site, acc = cfg["sites"][0], cfg["sites"][0]["accounts"][0]
    acc["token"] = "expired-tok"

    seq = {"n": 0}
    class R:
        def __init__(self, status):
            self.status = status
            self.data = {"success": True} if status == 200 else {}
            self.raw = "{}"
            self.error = ""
            self.reauthed = False
            self.blocked_by_waf = False
            self.set_cookies = []
    def fake_call(self, method, path, body=None):
        seq["n"] += 1
        return R(401) if seq["n"] == 1 else R(200)
    monkeypatch.setattr(sa.SiteClient, "call", fake_call)
    monkeypatch.setattr(sa, "ensure_token", lambda *a, **k: "")
    monkeypatch.setattr(sa, "exchange",
                        lambda *a, **k: AuthResult("ok", "", token="fresh-tok"))

    r = sa.call_with_auto_reauth(site, acc, cfg, "get", "/api/user/self")
    assert r.status == 200
    assert r.reauthed is True
    assert seq["n"] == 2                       # 首次 401 + 换新后重试


# ---------- 回调判定(OAuthCallback 契约) ----------

def test_callback_check():
    host = "s1.example.com"
    ok = of.check_callback(
        f"https://{host}/oauth/github?code=abc&state=st1", host, "st1")
    assert ok.should_exchange and ok.code == "abc"

    bad = of.check_callback(
        f"https://{host}/oauth/github?code=abc&state=other", host, "st1")
    assert bad.bad_state and not bad.should_exchange       # state 不符拒绝

    miss = of.check_callback(f"https://{host}/oauth/github", host, "st1")
    assert miss.missing_code                                # 无 code 明确失败

    other_host = of.check_callback(
        "https://evil.com/oauth/github?code=abc&state=st1", host, "st1")
    assert not other_host.should_exchange                   # 非同域直接无视


def test_callback_path_tolerant():
    """v0.5.1 契约:回调路径不限 /oauth/*,根路径/任意路径都认。"""
    host = "s1.example.com"
    r = of.check_callback(f"https://{host}/?code=c&state=s", host, "s")
    assert r.should_exchange


# ---------- Set-Cookie 解析(契约 §3.0) ----------

def test_parse_set_cookies():
    vals = [
        "session=abc123; Path=/; HttpOnly",
        "deleted=; Path=/",                       # 空值跳过
        "tmp=x; Max-Age=0",                       # 删除态跳过
        "uid=7; Path=/",
        "gone=deleted",                           # deleted 值跳过
    ]
    assert of.parse_set_cookies(vals) == "session=abc123; uid=7"
    assert of.parse_set_cookies([]) == ""


# ---------- 凭据提取 + B1 身份校验 ----------

def test_extract_credentials_compat():
    # 旧版:user 嵌套 + accessToken 字段
    old = {"data": {"accessToken": "t1", "user": {"username": "octocat"}, "id": 5}}
    c = of.extract_credentials(old)
    assert c["token"] == "t1" and c["github_login"] == "octocat" and c["site_user_id"] == "5"
    # AgentRouter 型:data 直接是用户对象 + github_id
    new = {"data": {"access_token": None, "username": "u2", "id": 9, "github_id": 555}}
    c2 = of.extract_credentials(new)
    assert c2["token"] == "" and c2["github_login"] == "u2" and c2["github_id"] == "555"


def test_b1_identity_check():
    # 强判据:github_id 不等 ⇒ 拒
    ok, why = of.b1_identity_check({"github_id": "999", "github_login": "x"},
                                   {"githubId": "111"})
    assert not ok and "github_id" in why
    # 强判据:相等 ⇒ 过
    assert of.b1_identity_check({"github_id": "111"}, {"githubId": "111"})[0]
    # 弱判据:无 github_id,username 不等 ⇒ 拒
    ok2, why2 = of.b1_identity_check({"github_login": "bob"}, {"githubAccount": "alice"})
    assert not ok2
    # 都拿不到 ⇒ 跳过(不误拒)
    assert of.b1_identity_check({}, {"githubAccount": "alice"})[0]


# ---------- 凭据库 ----------

def test_credentials_roundtrip(monkeypatch, tmp_path):
    from pc.engine import credentials as cr
    config, db, crypto = _patch(monkeypatch, tmp_path)
    config.save(make_account_cfg(tmp_path))

    assert cr.save_credential("a1", username="user@x.com", password="pw1",
                              totp_secret="JBSWY3DPEHPK3PXP")
    cred = cr.get_credential("a1")
    assert cred == {"username": "user@x.com", "password": "pw1",
                    "totpSecret": "JBSWY3DPEHPK3PXP"}
    # 落盘的是密文
    cfg_raw = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    enc = cfg_raw["sites"][0]["accounts"][0]["encCredential"]
    assert enc.startswith("enc:")
    assert "pw1" not in enc

    # TOTP 现场生成
    code = cr.totp_now(cred)
    assert len(code) == 6 and code.isdigit()

    # 字段空串 = 保留原值
    assert cr.save_credential("a1", username="new@x.com")
    assert cr.get_credential("a1")["username"] == "new@x.com"
    assert cr.get_credential("a1")["password"] == "pw1"
    assert cr.get_credential("nope") == {}


# ---------- state 双形态 ----------

def test_fetch_state_post_404_fallback_get(monkeypatch, tmp_path):
    """契约:POST 404 ⇒ GET ?mode=login,形态记站点 meta。"""
    config, db, crypto = _patch(monkeypatch, tmp_path)
    cfg = make_account_cfg(tmp_path)
    config.save(cfg)
    site = cfg["sites"][0]

    seq = {"n": 0}
    class R:
        def __init__(self, status, data=None):
            self.status, self.data, self.raw = status, data or {}, "{}"
            self.error, self.blocked_by_waf, self.set_cookies = "", False, []
    def fake_call(self, method, path, body=None):
        seq["n"] += 1
        if seq["n"] == 1:
            return R(404)
        assert "mode=login" in path                # 回退必须带 query
        return R(200, {"success": True, "data": "flow_tok"})
    client = of.SiteClient(site, {}, cfg)
    monkeypatch.setattr(of.SiteClient, "call", fake_call)

    token, err = of.fetch_state(client)
    assert token == "flow_tok" and err == ""
    assert config.site_meta(config.load(), "s1", "stateMethod") == "get"
