"""test_api_auth.py — 授权/验证 API 层测试(冻结契约 v1:BRAVO 侧 ④⑥⑧⑨⑪⑫)。

覆盖:
- ④ 状态映射:AuthResult need_code→waiting_code / need_manual→waiting_manual;
     worker 经 on_state 就地写入 waiting_code/waiting_manual(任务保持运行语义)
- ⑥ authMode 保存(显式)+ 默认推导(有密码→auto,无密码→manual)
- ⑨ /api/accounts/save 同站点同凭据去重(复用 key,不重复建账号)
- ⑩ /api/credentials/verify 的 headful 选择(有密码 headless,无密码 headful)
- ⑪ 验证探测站选择(绑定站 > cfg.sites[0] > JustDoWork 常量)
- ⑫ _oauth_tasks/_verify_tasks TTL/容量清理

不发真实网络与浏览器:monkeypatch main.authorize。
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pc.main as main  # noqa: E402
from pc.engine.oauth_flow import AuthResult  # noqa: E402


def _res(state, message="", hint="", code_task="", manual_url="", github_login=""):
    """轻量 AuthResult 替身:hint/code_task 契约字段由 ALPHA 侧新增,合成与
    合并顺序无关,只验 BRAVO 侧映射逻辑。"""
    class _R:
        pass
    r = _R()
    r.state, r.message, r.hint, r.code_task = state, message, hint, code_task
    r.manual_url, r.github_login = manual_url, github_login
    r.token = r.site_cookie = r.site_user_id = r.github_id = ""
    return r


# ---------- 夹具 ----------

def _patch_env(monkeypatch, tmp_path):
    from pc.service import config, crypto, db
    monkeypatch.setattr(config, "CFG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "_p", lambda name: tmp_path / name)
    # 任务表/时间戳隔离
    monkeypatch.setattr(main, "_oauth_tasks", {})
    monkeypatch.setattr(main, "_verify_tasks", {})
    monkeypatch.setattr(main, "_task_ts", {})
    monkeypatch.setattr(main, "_task_account", {})
    return config, db, crypto


def _seed_config(config, with_credential: bool = True, cred_password: str = "pw1"):
    cfg = config.load()
    cfg["sites"] = [{
        "key": "s1", "name": "站1", "baseUrl": "https://s1.example.com",
        "checkinType": "newapi", "accounts": [],
    }]
    config.save(cfg)
    cid = ""
    if with_credential:
        from pc.engine import credentials as cr
        r = cr.upsert_credential(github_user="u1@x.com", alias="u1",
                                 password=cred_password or None)
        cid = r["id"]
    return cfg, cid


def _wait_task(store: dict, task_id: str, timeout: float = 5.0) -> dict:
    """等任务离开 running 态(worker 是后台线程)。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        t = store.get(task_id)
        if t and t.get("state") != "running":
            return t
        time.sleep(0.01)
    return store.get(task_id) or {}


@pytest.fixture
def client():
    with TestClient(main.app) as c:
        yield c


# ---------- ④ 状态映射 ----------

def test_result_state_mapping():
    """契约 4:need_code→waiting_code;need_manual→waiting_manual;ok/failed 原样。"""
    r = main._result_task(_res("need_code", "要码", hint="h", code_task="t"))
    assert r["state"] == "waiting_code" and r["hint"] == "h" and r["codeTask"] == "t"
    r = main._result_task(_res("need_manual", "转人工", manual_url="https://github.com/login"))
    assert r["state"] == "waiting_manual" and r["manualUrl"] == "https://github.com/login"
    assert main._result_task(_res("ok", "好"))["state"] == "ok"
    assert main._result_task(_res("failed", "坏"))["state"] == "failed"
    # 未知 state 兜底为 failed(不会把异常态漏给前端)
    assert main._result_task(_res("weird", "?"))["state"] == "failed"


def test_state_task_mapping():
    """契约 2:on_state 通知 {waiting_code|waiting_manual} 就地映射(含 hint/manualUrl)。"""
    wc = main._state_task({"state": "waiting_code", "hint": "请输入验证码"})
    assert wc["state"] == "waiting_code" and wc["hint"] == "请输入验证码"
    wm = main._state_task({"state": "waiting_manual", "manualUrl": "https://github.com/login"})
    assert wm["state"] == "waiting_manual" and wm["manualUrl"] == "https://github.com/login"


def _wait_for(pred, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return False


def test_oauth_start_writes_waiting_states_in_place(monkeypatch, tmp_path, client):
    """④:worker 传 on_state,waiting_code/waiting_manual 就地写入且任务不结束;
    只有 authorize 返回后才写结束态。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _seed_config(config, with_credential=False)
    cfg = config.load()
    cfg["sites"][0]["accounts"] = [{"key": "a1", "alias": "主号", "githubAccount": "u1"}]
    config.save(cfg)

    seen: dict = {}

    def fake_authorize(site, account, cfg, credential=None, headful=False,
                       task_id="", on_state=None):
        assert callable(on_state) and task_id
        on_state({"state": "waiting_code", "hint": "请输入 6 位验证码"})
        seen["mid"] = dict(main._oauth_tasks.get(task_id) or {})
        on_state({"state": "waiting_manual", "manualUrl": "https://github.com/login"})
        seen["mid2"] = dict(main._oauth_tasks.get(task_id) or {})
        return _res("need_code", "需要验证码", hint="请输入 6 位验证码", code_task="b1")

    monkeypatch.setattr(main, "authorize", fake_authorize)

    resp = client.post("/api/oauth/start", json={"accountKey": "a1"})
    assert resp.status_code == 200
    task_id = resp.json()["task"]

    # 等 worker 线程跑完(后台线程,resp 返回时可能尚未执行)
    assert _wait_for(lambda: bool(seen.get("mid2")))
    # on_state 就地写入(此刻流程仍在后台等)
    assert seen["mid"]["state"] == "waiting_code"
    assert seen["mid"]["hint"] == "请输入 6 位验证码"
    assert seen["mid2"]["state"] == "waiting_manual"
    assert seen["mid2"]["manualUrl"] == "https://github.com/login"

    final = _wait_task(main._oauth_tasks, task_id)
    assert _wait_for(lambda: (main._oauth_tasks.get(task_id) or {}).get("codeTask") == "b1")
    final = main._oauth_tasks[task_id]
    assert final["state"] == "waiting_code"          # need_code 映射
    assert final["hint"] == "请输入 6 位验证码"
    assert final["codeTask"] == "b1"

    st = client.get(f"/api/oauth/status?task={task_id}").json()
    assert st["ok"] is True and st["state"] == "waiting_code"
    assert st["hint"] == "请输入 6 位验证码"


# ---------- ⑥ authMode ----------

def test_derive_auth_mode(monkeypatch, tmp_path):
    """契约 6:有密码→auto;无密码→manual;凭据不存在→manual。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    config.save(config.load())
    from pc.engine import credentials as cr
    with_pw = cr.upsert_credential(github_user="a@x.com", password="pw")["id"]
    without_pw = cr.upsert_credential(github_user="b@x.com", twofa="SECRET")["id"]
    assert cr.derive_auth_mode(with_pw) == "auto"
    assert cr.derive_auth_mode(without_pw) == "manual"
    assert cr.derive_auth_mode("nope") == "manual"
    assert cr.derive_auth_mode("") == "manual"


def test_accounts_save_authmode_explicit_and_derived(monkeypatch, tmp_path, client):
    """⑥:/api/accounts/save 保存 authMode;缺省时由凭据能力推导。
    (同凭据在同站点会去重,故各断言用不同站点/凭据避免互相影响)"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid_pw = _seed_config(config, with_credential=True, cred_password="pw1")
    # 加第二个站点(s2):同凭据可在此独立建账号
    cfg = config.load()
    cfg["sites"].append({"key": "s2", "name": "站2", "baseUrl": "https://s2.example.com",
                         "checkinType": "newapi", "accounts": []})
    config.save(cfg)
    # 无密码凭据(独立凭据,避免与 cid_pw 混淆)
    from pc.engine import credentials as cr
    cid_nopw = cr.upsert_credential(github_user="nopw@x.com", twofa="SECRET")["id"]

    # 显式 authMode=manual 被保存(即便凭据有密码)
    r = client.post("/api/accounts/save",
                    json={"siteKey": "s1", "key": "a_manual", "credentialId": cid_pw,
                          "authMode": "manual"}).json()
    assert r["key"] == "a_manual"
    cfg = config.load()
    assert config.find_account(cfg, "a_manual")[1]["authMode"] == "manual"

    # 未传 authMode + 有密码凭据(另建站点)⇒ 推导 auto
    client.post("/api/accounts/save", json={"siteKey": "s2", "key": "a_auto",
                                            "credentialId": cid_pw})
    cfg = config.load()
    assert config.find_account(cfg, "a_auto")[1]["authMode"] == "auto"

    # 未传 authMode + 无密码凭据 ⇒ 推导 manual
    client.post("/api/accounts/save", json={"siteKey": "s1", "key": "a_nopw",
                                            "credentialId": cid_nopw})
    cfg = config.load()
    assert config.find_account(cfg, "a_nopw")[1]["authMode"] == "manual"

    # 无 credentialId ⇒ manual(无凭据能力)
    client.post("/api/accounts/save", json={"siteKey": "s2", "key": "a_none"})
    cfg = config.load()
    assert config.find_account(cfg, "a_none")[1]["authMode"] == "manual"


# ---------- ⑨ 去重 ----------

def test_accounts_save_dedupe_same_site_credential(monkeypatch, tmp_path, client):
    """⑨:同 (siteKey, credentialId) 第二次保存复用 key,不重复建账号。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid = _seed_config(config, with_credential=True)

    r1 = client.post("/api/accounts/save",
                     json={"siteKey": "s1", "credentialId": cid}).json()
    assert r1["deduplicated"] is False
    key1 = r1["key"]

    # 不带 key 再存一次同凭据 ⇒ 复用已有 key
    r2 = client.post("/api/accounts/save",
                     json={"siteKey": "s1", "credentialId": cid}).json()
    assert r2["deduplicated"] is True and r2["key"] == key1

    cfg = config.load()
    site = next(s for s in cfg["sites"] if s["key"] == "s1")
    assert len(site["accounts"]) == 1                  # 未重复建账号
    # 不同站点同凭据不互相去重
    cfg["sites"].append({"key": "s2", "name": "站2", "baseUrl": "https://s2.example.com",
                         "checkinType": "newapi", "accounts": []})
    config.save(cfg)
    r3 = client.post("/api/accounts/save",
                     json={"siteKey": "s2", "credentialId": cid}).json()
    assert r3["key"] != key1 and r3["deduplicated"] is False


def test_accounts_save_no_dedupe_without_credential(monkeypatch, tmp_path, client):
    """无 credentialId 时每次生成独立账号(不去重)。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _seed_config(config, with_credential=False)
    r1 = client.post("/api/accounts/save", json={"siteKey": "s1"}).json()
    r2 = client.post("/api/accounts/save", json={"siteKey": "s1"}).json()
    assert r1["key"] != r2["key"] and not r2["deduplicated"]


# ---------- ⑩ verify headful 选择 ----------

def _patch_authorize_capture(monkeypatch, store_key: str = "seen"):
    seen: dict = {}

    def fake_authorize(site, account, cfg, credential=None, headful=False,
                       task_id="", on_state=None):
        seen["headful"] = headful
        seen["credential"] = credential
        seen["site"] = site
        return AuthResult("ok", "授权成功", github_login="u1")

    monkeypatch.setattr(main, "authorize", fake_authorize)
    return seen


def test_verify_headless_when_password_present(monkeypatch, tmp_path, client):
    """⑩:凭据有密码 ⇒ headless 自验(headful=False),不弹浏览器。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid = _seed_config(config, with_credential=True, cred_password="pw1")
    seen = _patch_authorize_capture(monkeypatch)

    resp = client.post("/api/credentials/verify", json={"id": cid}).json()
    assert resp["headful"] is False
    _wait_task(main._verify_tasks, resp["task"])
    assert seen["headful"] is False


def test_verify_headful_when_no_password(monkeypatch, tmp_path, client):
    """⑩:凭据无密码 ⇒ headful=True(需人工)。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid = _seed_config(config, with_credential=True, cred_password="")
    seen = _patch_authorize_capture(monkeypatch)

    resp = client.post("/api/credentials/verify", json={"id": cid}).json()
    assert resp["headful"] is True
    _wait_task(main._verify_tasks, resp["task"])
    assert seen["headful"] is True


def test_verify_marks_verified(monkeypatch, tmp_path, client):
    """验证通过 ⇒ 凭据 verified=ok(走 config.update 原子事务)。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid = _seed_config(config, with_credential=True)
    _patch_authorize_capture(monkeypatch)
    resp = client.post("/api/credentials/verify", json={"id": cid}).json()
    _wait_task(main._verify_tasks, resp["task"])
    from pc.engine.credentials import list_credentials
    c = next(x for x in list_credentials() if x["id"] == cid)
    assert c["verified"] == "ok" and c["verifiedAt"]


# ---------- ⑪ 探测站选择 ----------

def test_probe_site_prefers_bound_site():
    """⑪:凭据已绑定站点 ⇒ 用该站点(自身 baseUrl/checkinType)。"""
    cfg = {"sites": [
        {"key": "s0", "baseUrl": "https://s0.example.com", "checkinType": "login",
         "accounts": [{"key": "x", "credentialId": "other"}]},
        {"key": "s1", "baseUrl": "https://s1.example.com", "checkinType": "newapi",
         "accounts": [{"key": "y", "credentialId": "cred_1"}]},
    ]}
    s = main._probe_site_for_credential(cfg, "cred_1")
    assert s["key"] == "s1" and s["baseUrl"] == "https://s1.example.com"
    assert s["checkinType"] == "newapi"


def test_probe_site_fallbacks():
    """⑪:无绑定 ⇒ cfg.sites[0];无站点 ⇒ JustDoWork 常量。"""
    cfg = {"sites": [{"key": "s0", "baseUrl": "https://s0.example.com"}]}
    assert main._probe_site_for_credential(cfg, "missing")["key"] == "s0"
    fb = main._probe_site_for_credential({"sites": []}, "cred_x")
    assert fb["key"] == "__verify__"
    assert fb["baseUrl"] == "https://api.justwoker.icu"
    assert fb["checkinType"] == "newapi"


def test_verify_unsaved_no_password_is_headful(monkeypatch, tmp_path, client):
    """⑩:未保存凭据只给 username(无密码)⇒ headful=True;缺 username 才 400。"""
    _patch_env(monkeypatch, tmp_path)
    seen = _patch_authorize_capture(monkeypatch)
    resp = client.post("/api/credentials/verify",
                       json={"username": "u1@x.com"}).json()
    assert resp["headful"] is True
    _wait_task(main._verify_tasks, resp["task"])
    assert seen["headful"] is True and seen["credential"]["password"] == ""
    assert client.post("/api/credentials/verify", json={}).status_code == 400


def test_verify_need_code_maps_waiting_not_failed(monkeypatch, tmp_path, client):
    """契约 4 应用于 verify 任务:need_code → waiting_code,且不标记为验失败。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid = _seed_config(config, with_credential=True)

    def fake_authorize(site, account, cfg, credential=None, headful=False,
                       task_id="", on_state=None):
        return _res("need_code", "需要验证码", hint="请输入 6 位验证码")

    monkeypatch.setattr(main, "authorize", fake_authorize)
    resp = client.post("/api/credentials/verify", json={"id": cid}).json()
    final = _wait_for(lambda: (main._verify_tasks.get(resp["task"]) or {})
                      .get("state") == "waiting_code")
    assert final, main._verify_tasks.get(resp["task"])
    assert main._verify_tasks[resp["task"]]["hint"] == "请输入 6 位验证码"
    # 等人工介入不算验失败:credential.verified 不应被写成 failed
    from pc.engine.credentials import list_credentials
    c = next(x for x in list_credentials() if x["id"] == cid)
    assert c["verified"] != "failed"


def test_verify_uses_bound_probe_site(monkeypatch, tmp_path, client):
    """⑪端到端:verify 的探测站是该凭据绑定站点,不再绑死 JustDoWork。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid = _seed_config(config, with_credential=True)
    # 把凭据绑定到 s1(改 baseUrl 便于区分)
    cfg = config.load()
    cfg["sites"][0]["baseUrl"] = "https://bound.example.com"
    cfg["sites"][0]["accounts"].append({"key": "a1", "credentialId": cid})
    config.save(cfg)
    seen = _patch_authorize_capture(monkeypatch)

    resp = client.post("/api/credentials/verify", json={"id": cid}).json()
    assert resp["probeSite"] == "s1"
    _wait_task(main._verify_tasks, resp["task"])
    assert seen["site"]["baseUrl"] == "https://bound.example.com"


# ---------- ⑫ 任务清理 ----------

def test_task_ttl_cleanup(monkeypatch, tmp_path):
    """⑫:超 1h 的任务在写入时被清理。"""
    _patch_env(monkeypatch, tmp_path)
    main._put_task(main._verify_tasks, "old", {"state": "ok"})
    main._task_ts["old"] = time.time() - (main._TASK_TTL_S + 10)
    main._put_task(main._oauth_tasks, "new", {"state": "running"})
    assert "old" not in main._verify_tasks and "old" not in main._task_ts
    assert "new" in main._oauth_tasks


def test_task_capacity_cleanup(monkeypatch, tmp_path):
    """⑫:超过 200 条时淘汰最旧,容量有界。"""
    _patch_env(monkeypatch, tmp_path)
    for i in range(main._TASK_MAX + 20):
        main._put_task(main._oauth_tasks, f"t{i}", {"state": "ok"})
    assert len(main._task_ts) == main._TASK_MAX
    assert len(main._oauth_tasks) == main._TASK_MAX
    assert "t0" not in main._oauth_tasks            # 最旧被淘汰
    assert f"t{main._TASK_MAX + 19}" in main._oauth_tasks


def test_oauth_status_404_for_unknown():
    with TestClient(main.app) as c:
        assert c.get("/api/oauth/status?task=nope").status_code == 404


# ---------- ⑤ totp 转发 code+task ----------

def test_totp_forwards_code_and_task(monkeypatch, tmp_path, client):
    """契约 5:{code, task} → set_manual_code(code, task);task 可选。"""
    _patch_env(monkeypatch, tmp_path)
    calls: list = []

    def fake_set_manual_code(code, task_id=""):
        calls.append((code, task_id))

    monkeypatch.setattr(main, "set_manual_code", fake_set_manual_code)

    r = client.post("/api/oauth/totp", json={"code": "123456", "task": "oauth_1"})
    assert r.status_code == 200 and calls == [("123456", "oauth_1")]
    r2 = client.post("/api/oauth/totp", json={"code": "654321"})     # task 可选
    assert r2.status_code == 200 and calls[-1] == ("654321", "")
    # 非 6 位码拒绝
    assert client.post("/api/oauth/totp", json={"code": "12"}).status_code == 400


# ---------- 路由顺序回归 + silent_auth 透传 ----------

def test_legacy_credentials_save_route_not_shadowed(monkeypatch, tmp_path, client):
    """回归:/api/credentials/verify 必须在动态路由 /api/credentials/{account_key}
    之前注册,否则 verify 被吞成 account_key="verify" 永远 404。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid = _seed_config(config, with_credential=True)
    cfg = config.load()
    cfg["sites"][0]["accounts"].append({"key": "a1", "alias": "主号"})
    config.save(cfg)
    _patch_authorize_capture(monkeypatch)
    # 静态路由可命中
    assert client.post("/api/credentials/verify", json={"id": cid}).status_code == 200
    # 旧动态路由仍可用(账号存在 ⇒ 200)
    r = client.post("/api/credentials/a1", json={"username": "g@x.com", "password": "pw"})
    assert r.status_code == 200


def test_silent_auth_forwards_task_and_state(monkeypatch, tmp_path):
    """契约 2:silent_auth.exchange 透传 task_id/on_state 给 authorize。"""
    from pc.engine import silent_auth as sa
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    cfg = config.load()
    site = {"key": "s1", "name": "站1", "baseUrl": "https://s1.example.com",
            "checkinType": "newapi"}
    acc = {"key": "a1", "alias": "主号"}
    got: dict = {}

    def fake_authorize(site, account, cfg, credential=None, headful=False,
                       task_id="", on_state=None):
        got["task_id"], got["on_state"] = task_id, on_state
        return _res("need_code", "要码")

    monkeypatch.setattr(sa, "authorize", fake_authorize)
    cb = lambda st: None
    sa.exchange(site, acc, cfg, force=True, task_id="t-9", on_state=cb)
    assert got["task_id"] == "t-9" and got["on_state"] is cb


def test_silent_auth_need_code_no_cooldown(monkeypatch, tmp_path):
    """need_code 表示等人工,不设 90s 冷却(否则拿到码后无法立刻重试)。"""
    from pc.engine import silent_auth as sa
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    cfg = config.load()
    site = {"key": "s1", "baseUrl": "https://s1.example.com", "checkinType": "newapi"}
    acc = {"key": "a1"}
    monkeypatch.setattr(sa, "authorize",
                        lambda *a, **k: _res("need_code", "要码"))
    r = sa.exchange(site, acc, cfg, force=True)
    assert r.state == "need_code"
    assert sa.in_cooldown("a1") is False
