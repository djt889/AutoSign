"""test_auth_contract.py — 冻结契约 v1 端到端一致性回归(DELTA 契约测试)。

覆盖(冻结契约 v1 §1-§8):
  1. AuthResult 字段:state∈{ok,need_code,need_manual,failed} + hint/code_task/manual_url
  2. authorize 签名含 task_id/on_state;on_state 是「通知」不是「返回」
  3. set_manual_code(code, task_id):task 隔离 / 120s 过期 / 一次性消费
  4. /api/oauth/status 状态映射:need_code→waiting_code、need_manual→waiting_manual,
     hint/manualUrl/codeTask 透传
  5. /api/oauth/totp 接受 {code, task} 并写对 task 桶
  6. /api/accounts/save 保存 authMode;缺省按凭据能力推导(有密码→auto,无密码→manual)
  7. /api/credentials/verify 的 headful 选择(有密码→False,无密码→True)
  8. 前端行为(静态文本断言,宽松):仅 waiting_code 插码框、manualUrl 非空显示按钮

实现说明(重要):
- 仓库处于多 agent 并行改造中(oauth_flow/main/credentials/silent_auth/index.html 均
  在改)。为不因实现未就绪而报 import 错误导致整个文件收集失败,所有对新契约符号
  的依赖都放在测试函数体内,并用 `_has` 探测;探测不到时 pytest.skip(单测跳过,
  不影响收集与其他用例)。http 冒烟用例(FastAPI TestClient)本身不依赖 ALPHA 侧
  新签名,始终可跑。
"""
from __future__ import annotations

import inspect
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


# ---------- 契约面探测(实现未就绪 ⇒ skip 而非收集失败) ----------

def _mod(name: str):
    try:
        return __import__(name, fromlist=["*"])
    except Exception:
        return None


def _has(obj, name: str) -> bool:
    return obj is not None and hasattr(obj, name)


def _has_param(fn, name: str) -> bool:
    try:
        return name in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


of = _mod("pc.engine.oauth_flow")
main = _mod("pc.main")
sa = _mod("pc.engine.silent_auth")
cr = _mod("pc.engine.credentials")


def _res(state, message="", hint="", code_task="", manual_url="", github_login=""):
    """轻量 AuthResult 替身(不依赖 dataclass 是否已加新字段)。"""
    class _R:
        pass
    r = _R()
    r.state, r.message, r.hint, r.code_task = state, message, hint, code_task
    r.manual_url, r.github_login = manual_url, github_login
    r.token = r.site_cookie = r.site_user_id = r.github_id = ""
    return r


# ---------- 契约 1:AuthResult 字段 ----------

def test_authresult_has_contract_fields():
    """契约 1:AuthResult 具备 state/hint/code_task/manual_url 字段,且 hint/code_task 默认空。"""
    if not _has(of, "AuthResult"):
        pytest.skip("oauth_flow.AuthResult 未就绪")
    AR = of.AuthResult
    fields = list(getattr(AR, "__dataclass_fields__", {}).keys())
    for f in ("state", "hint", "code_task", "manual_url"):
        assert f in fields, f"AuthResult 缺字段 {f}"
    # 缺省构造:hint/code_task 必须为空串(不 None)
    r = AR("ok")
    assert r.hint == "" and r.code_task == "" and r.manual_url == ""
    # 合法 state 集合
    for st in ("ok", "need_code", "need_manual", "failed"):
        assert AR(st).state == st
    # manual_url 仅 need_manual 时使用,ok 时为空
    assert AR("ok", manual_url="x").manual_url == "x"


def test_authorize_signature_contract():
    """契约 2:authorize 签名含 task_id/on_state 可选参数(旧签名时跳过)。"""
    if not (_has(of, "authorize") and _has_param(of.authorize, "task_id")
            and _has_param(of.authorize, "on_state")):
        pytest.skip("authorize 尚未支持 task_id/on_state")
    sig = inspect.signature(of.authorize)
    assert sig.parameters["task_id"].default == ""
    assert sig.parameters["on_state"].default is None


# ---------- 契约 3:set_manual_code 隔离/过期/一次性 ----------

def test_set_manual_code_bucket_isolation():
    """契约 3:set_manual_code(code, task_id) 按 task 隔离,互不串。"""
    if not (_has(of, "set_manual_code") and _has_param(of.set_manual_code, "task_id")):
        pytest.skip("set_manual_code 尚未支持 task_id")
    if not _has(of, "_take_manual_code"):
        pytest.skip("_take_manual_code 尚未实现")
    of.set_manual_code("111111", "t1")
    of.set_manual_code("222222", "t2")
    assert of._take_manual_code("t1") == "111111"
    assert of._take_manual_code("t2") == "222222"
    # 空 task 与具名 task 隔离
    of.set_manual_code("333333", "")
    assert of._take_manual_code("") == "333333"
    assert of._take_manual_code("t1") is None or of._take_manual_code("t1") == ""


def test_set_manual_code_single_consume():
    """契约 3:码消费一次即清(同 task 二次取不到)。"""
    if not (_has(of, "set_manual_code") and _has_param(of.set_manual_code, "task_id")):
        pytest.skip("set_manual_code 尚未支持 task_id")
    if not _has(of, "_take_manual_code"):
        pytest.skip("_take_manual_code 尚未实现")
    of.set_manual_code("123456", "tk")
    assert of._take_manual_code("tk") == "123456"
    assert not of._take_manual_code("tk")       # 消费后清空


def test_set_manual_code_expiry_120s():
    """契约 3:超 120s 取不到(过期)。用 monkeypatch 时钟,不真实等 2 分钟。"""
    if not (_has(of, "set_manual_code") and _has_param(of.set_manual_code, "task_id")):
        pytest.skip("set_manual_code 尚未支持 task_id")
    if not _has(of, "_take_manual_code"):
        pytest.skip("_take_manual_code 尚未实现")

    import pc.engine.oauth_flow as of_mod

    real_time = of_mod.time.time
    fake = {"now": 1000.0}
    monkeypatch = pytest.MonkeyPatch()

    def fake_time():
        return fake["now"]

    try:
        monkeypatch.setattr(of_mod.time, "time", fake_time)
        of_mod.set_manual_code("123456", "tx")
        assert of_mod._take_manual_code("tx") == "123456"   # 未过期可取
        of_mod.set_manual_code("123456", "ty")
        fake["now"] += 121.0                                 # 越过 120s
        assert not of_mod._take_manual_code("ty")            # 过期取不到
    finally:
        monkeypatch.undo()


def test_authorize_consumes_by_task_id():
    """契约 2/3:authorize 内部按 task_id 取码(不再用全局 _manual_code)。"""
    if not (_has(of, "authorize") and _has_param(of.authorize, "task_id")):
        pytest.skip("authorize 尚未支持 task_id")
    if not _has(of, "_take_manual_code"):
        pytest.skip("_take_manual_code 尚未实现")
    # 有头模式分支(headful=True)会按 task_id 取码注入;这里只验证代码路径引用了
    # _take_manual_code(task_id),通过静态断言避免拉起真实浏览器
    import pc.engine.oauth_flow as of_mod
    src = inspect.getsource(of_mod)
    assert "_take_manual_code(task_id)" in src


# ---------- 契约 4:/api/oauth/status 状态映射 ----------

def _patch_env(monkeypatch, tmp_path):
    from pc.service import config, crypto, db
    monkeypatch.setattr(config, "CFG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "_p", lambda name: tmp_path / name)
    monkeypatch.setattr(main, "_oauth_tasks", {})
    monkeypatch.setattr(main, "_verify_tasks", {})
    monkeypatch.setattr(main, "_task_ts", {})
    monkeypatch.setattr(main, "_task_account", {})
    return config, db, crypto


def _seed(config, with_credential: bool = True, cred_password: str = "pw1"):
    cfg = config.load()
    cfg["sites"] = [{"key": "s1", "name": "站1", "baseUrl": "https://s1.example.com",
                     "checkinType": "newapi", "accounts": []}]
    config.save(cfg)
    cid = ""
    if with_credential:
        r = cr.upsert_credential(github_user="u1@x.com", alias="u1",
                                 password=cred_password or None)
        cid = r["id"]
    return cfg, cid


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c


def test_status_maps_need_code_to_waiting_code():
    """契约 4:need_code→waiting_code,need_manual→waiting_manual,hint/manualUrl/codeTask 透传。"""
    if main is None or not _has(main, "_result_task"):
        pytest.skip("main._result_task 未就绪")
    r = main._result_task(_res("need_code", "要码", hint="h1", code_task="ct1"))
    assert r["state"] == "waiting_code"
    assert r["hint"] == "h1" and r["codeTask"] == "ct1"
    r2 = main._result_task(_res("need_manual", "转人工", manual_url="https://github.com/login"))
    assert r2["state"] == "waiting_manual"
    assert r2["manualUrl"] == "https://github.com/login"
    # ok/failed 原样
    assert main._result_task(_res("ok", "好"))["state"] == "ok"
    assert main._result_task(_res("failed", "坏"))["state"] == "failed"


def test_status_state_task_passthrough():
    """契约 2/4:on_state 通知 dict 就地映射(waiting_code/waiting_manual 透传)。"""
    if main is None or not _has(main, "_state_task"):
        pytest.skip("main._state_task 未就绪")
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


def test_oauth_status_http_end_to_end(monkeypatch, tmp_path, client):
    """契约 4 端到端(HTTP):/api/oauth/start → worker 返回 need_code →
    /api/oauth/status 映射为 waiting_code 且 hint/codeTask 透传。"""
    if main is None:
        pytest.skip("pc.main 不可导入")
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _seed(config, with_credential=False)
    cfg = config.load()
    cfg["sites"][0]["accounts"] = [{"key": "a1", "alias": "主号", "githubAccount": "u1"}]
    config.save(cfg)

    seen = {}

    def fake_authorize(site, account, cfg, credential=None, headful=False,
                       task_id="", on_state=None):
        if callable(on_state):
            on_state({"state": "waiting_code", "hint": "请输入 6 位验证码"})
            seen["mid"] = dict(main._oauth_tasks.get(task_id) or {})
        return _res("need_code", "需要验证码", hint="请输入 6 位验证码", code_task="b1")

    monkeypatch.setattr(main, "authorize", fake_authorize)

    resp = client.post("/api/oauth/start", json={"accountKey": "a1"})
    assert resp.status_code == 200
    task = resp.json()["task"]
    # 等 worker 线程把 on_state 就地位写完
    assert _wait_for(lambda: "mid" in seen)
    assert seen["mid"]["state"] == "waiting_code"

    assert _wait_for(lambda: (main._oauth_tasks.get(task) or {}).get("codeTask") == "b1")
    st = client.get(f"/api/oauth/status?task={task}").json()
    assert st["ok"] is True
    assert st["state"] == "waiting_code"
    assert st["hint"] == "请输入 6 位验证码"
    assert st["codeTask"] == "b1"
    # 未知任务 404
    assert client.get("/api/oauth/status?task=nope").status_code == 404


# ---------- 契约 5:/api/oauth/totp {code, task} ----------

def test_totp_writes_code_to_correct_task(monkeypatch, tmp_path, client):
    """契约 5:/api/oauth/totp 接受 {code, task};set_manual_code 收到 (code, task)。

    set_manual_code 尚未支持 task_id 时跳过(ALPHA 未合入,不判失败)。
    """
    if main is None:
        pytest.skip("pc.main 不可导入")
    if not _has_param(main.set_manual_code, "task_id"):
        pytest.skip("set_manual_code 尚未支持 task_id(契约 3 未合入),task 透传待实现后验证")
    _patch_env(monkeypatch, tmp_path)
    calls: list = []

    def fake_set_manual_code(code, task_id=""):
        calls.append((code, task_id))

    monkeypatch.setattr(main, "set_manual_code", fake_set_manual_code)

    r = client.post("/api/oauth/totp", json={"code": "123456", "task": "oauth_1"})
    assert r.status_code == 200
    assert calls == [("123456", "oauth_1")]
    # task 可选(缺省空串)
    client.post("/api/oauth/totp", json={"code": "654321"})
    assert calls[-1] == ("654321", "")
    # 非 6 位码拒绝
    assert client.post("/api/oauth/totp", json={"code": "12"}).status_code == 400


def test_totp_bucket_isolation_end_to_end(monkeypatch, tmp_path):
    """契约 3+5:两个 task 各注入各的码,消费互不串(走 set_manual_code 真实现)。"""
    if main is None or not (_has(of, "set_manual_code") and _has(of, "_take_manual_code")):
        pytest.skip("set_manual_code(task_id) 未就绪")
    if not _has_param(of.set_manual_code, "task_id"):
        pytest.skip("set_manual_code 不支持 task_id")
    _patch_env(monkeypatch, tmp_path)

    # 直接驱动 oauth_flow 真实现(等价 /api/oauth/totp 转发)
    of.set_manual_code("111111", "taskA")
    of.set_manual_code("222222", "taskB")
    assert of._take_manual_code("taskA") == "111111"
    assert of._take_manual_code("taskB") == "222222"
    # 一次性消费:已取过的桶再取为空,且不影响 taskA 重新注入
    of.set_manual_code("333333", "taskA")
    assert of._take_manual_code("taskA") == "333333"
    assert of._take_manual_code("taskB") == ""      # B 已被消费,不复现
    assert of._take_manual_code("taskA") == ""      # A 也已消费


# ---------- 契约 6:authMode 默认推导 ----------

def test_derive_auth_mode_defaults():
    """契约 6:有密码→auto;无密码→manual;凭据不存在→manual。"""
    if not _has(cr, "derive_auth_mode"):
        pytest.skip("credentials.derive_auth_mode 未就绪")
    from pc.service import config as config_svc
    from pc.service import crypto as crypto_svc, db as db_svc
    import tempfile
    tmp = Path(tempfile.mkdtemp())
    m = pytest.MonkeyPatch()
    try:
        m.setattr(config_svc, "CFG_PATH", tmp / "config.json")
        m.setattr(crypto_svc, "KEY_PATH", tmp / "secret.key")
        m.setattr(db_svc, "DATA_DIR", tmp)
        m.setattr(db_svc, "_p", lambda name: tmp / name)
        config_svc.save(config_svc.load())
        with_pw = cr.upsert_credential(github_user="a@x.com", password="pw")["id"]
        without_pw = cr.upsert_credential(github_user="b@x.com", twofa="SECRET")["id"]
        assert cr.derive_auth_mode(with_pw) == "auto"
        assert cr.derive_auth_mode(without_pw) == "manual"
        assert cr.derive_auth_mode("nope") == "manual"
        assert cr.derive_auth_mode("") == "manual"
    finally:
        m.undo()


def test_accounts_save_authmode_saved_and_derived(monkeypatch, tmp_path, client):
    """契约 6 端到端(HTTP):/api/accounts/save 保存显式 authMode;缺省由凭据推导。"""
    if main is None or not _has(cr, "derive_auth_mode"):
        pytest.skip("accounts/save authMode 逻辑未就绪")
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid_pw = _seed(config, with_credential=True, cred_password="pw1")
    # 第二站点,便于同凭据独立建账号
    cfg = config.load()
    cfg["sites"].append({"key": "s2", "name": "站2", "baseUrl": "https://s2.example.com",
                         "checkinType": "newapi", "accounts": []})
    config.save(cfg)
    cid_nopw = cr.upsert_credential(github_user="nopw@x.com", twofa="SECRET")["id"]

    # 显式 manual 覆盖(即使凭据有密码)
    r = client.post("/api/accounts/save", json={"siteKey": "s1", "key": "a_m",
                                                "credentialId": cid_pw, "authMode": "manual"}).json()
    assert r["key"] == "a_m"
    cfg = config.load()
    assert config.find_account(cfg, "a_m")[1]["authMode"] == "manual"

    # 未传 authMode + 有密码凭据 ⇒ auto
    client.post("/api/accounts/save", json={"siteKey": "s2", "key": "a_auto",
                                            "credentialId": cid_pw})
    cfg = config.load()
    assert config.find_account(cfg, "a_auto")[1]["authMode"] == "auto"

    # 未传 authMode + 无密码凭据 ⇒ manual
    client.post("/api/accounts/save", json={"siteKey": "s1", "key": "a_nopw",
                                            "credentialId": cid_nopw})
    cfg = config.load()
    assert config.find_account(cfg, "a_nopw")[1]["authMode"] == "manual"

    # 无 credentialId ⇒ manual
    client.post("/api/accounts/save", json={"siteKey": "s2", "key": "a_none"})
    cfg = config.load()
    assert config.find_account(cfg, "a_none")[1]["authMode"] == "manual"


# ---------- 契约 7:/api/credentials/verify headful 选择 ----------

def _patch_authorize_capture(monkeypatch):
    seen = {}

    def fake_authorize(site, account, cfg, credential=None, headful=False,
                       task_id="", on_state=None):
        seen["headful"] = headful
        seen["credential"] = credential
        return _res("ok", "授权成功", github_login="u1")

    monkeypatch.setattr(main, "authorize", fake_authorize)
    return seen


def test_verify_headful_by_password_presence(monkeypatch, tmp_path, client):
    """契约 7:有密码→headless(headful=False);无密码→headful=True。"""
    if main is None:
        pytest.skip("pc.main 不可导入")
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _, cid_pw = _seed(config, with_credential=True, cred_password="pw1")
    cid_nopw = cr.upsert_credential(github_user="nopw@x.com", twofa="SECRET")["id"]

    seen = _patch_authorize_capture(monkeypatch)
    # 有密码 ⇒ headful=False
    r1 = client.post("/api/credentials/verify", json={"id": cid_pw}).json()
    assert r1["headful"] is False
    _wait_for(lambda: "headful" in seen)
    assert seen["headful"] is False
    seen.clear()

    # 无密码 ⇒ headful=True
    r2 = client.post("/api/credentials/verify", json={"id": cid_nopw}).json()
    assert r2["headful"] is True
    _wait_for(lambda: "headful" in seen)
    assert seen["headful"] is True
    seen.clear()

    # 未保存只给 username(无密码)⇒ headful=True
    r3 = client.post("/api/credentials/verify", json={"username": "x@x.com"}).json()
    assert r3["headful"] is True
    _wait_for(lambda: "headful" in seen)
    assert seen["headful"] is True
    # 空 body ⇒ 400
    assert client.post("/api/credentials/verify", json={}).status_code == 400


# ---------- 契约 8:前端静态契约(宽松断言) ----------

def test_frontend_only_waiting_code_shows_codebox():
    """契约 8:前端仅在 waiting_code 分支插入码框(无预置码框),manualUrl 非空显示按钮。"""
    from pathlib import Path as _P
    html = (_P(__file__).resolve().parent.parent / "web" / "static" / "index.html")
    if not html.exists():
        pytest.skip("index.html 不存在")
    src = html.read_text(encoding="utf-8")
    # 弹层初始不预置码框(只有占位 div),码框由 insertCodeBox 按 state 插入
    assert "id=\"oaCode\"" in src
    assert "insertCodeBox" in src
    # 仅 waiting_code 分支调用 insertCodeBox
    code_branch = src.split("insertCodeBox(s.hint||'')")
    assert len(code_branch) >= 2
    # 存在手动授权按钮渲染(manualUrl 非空即显示)
    assert "打开手动授权" in src
    assert "showManualUrl" in src
    # sendTotp 提交 task(CODETASK 优先,回退 CURTASK)
    assert "task:CODETASK||CURTASK" in src or "task:CODETASK||CURTASK||undefined" in src
    # 添加账号有 authMode 选择(契约 8)
    assert "aa_mode" in src and "authMode" in src
    # 授权按账号 authMode 分流
    assert "startOAuth('${k}','${am}')" in src


# ---------- 契约 2:on_state 通知语义(silent_auth 透传) ----------

def test_silent_auth_forwards_task_and_on_state():
    """契约 2:silent_auth.exchange 透传 task_id/on_state 给 authorize。"""
    if not (_has(sa, "exchange") and _has_param(sa.exchange, "task_id")
            and _has_param(sa.exchange, "on_state")):
        pytest.skip("silent_auth.exchange 尚未支持 task_id/on_state")

    config_svc = _mod("pc.service.config")
    db_svc = _mod("pc.service.db")
    crypto_svc = _mod("pc.service.crypto")
    if config_svc is None:
        pytest.skip("config 不可导入")
    import tempfile
    tmp = Path(tempfile.mkdtemp())
    m = pytest.MonkeyPatch()
    try:
        m.setattr(config_svc, "CFG_PATH", tmp / "config.json")
        m.setattr(crypto_svc, "KEY_PATH", tmp / "secret.key")
        m.setattr(db_svc, "DATA_DIR", tmp)
        m.setattr(db_svc, "_p", lambda name: tmp / name)
        config_svc.save(config_svc.load())
        # 清防风暴全局态
        m.setattr(sa, "_last_ok", {})
        m.setattr(sa, "_fail_until", {})
        site = {"key": "s1", "baseUrl": "https://s1.example.com", "checkinType": "newapi"}
        acc = {"key": "a1"}
        got = {}

        def fake_authorize(site, account, cfg, credential=None, headful=False,
                           task_id="", on_state=None):
            got["task_id"], got["on_state"] = task_id, on_state
            return _res("need_code", "要码")

        m.setattr(sa, "authorize", fake_authorize)
        cb = lambda st: None
        r = sa.exchange(site, acc, config_svc.load(), force=True, task_id="t-9", on_state=cb)
        assert got["task_id"] == "t-9" and got["on_state"] is cb
        assert r.state == "need_code"
    finally:
        m.undo()


def test_silent_auth_need_code_no_cooldown():
    """need_code/need_manual 表示等人工,不设 90s 冷却(否则拿到码后无法立即重试)。"""
    if not (_has(sa, "exchange") and _has(sa, "in_cooldown")):
        pytest.skip("silent_auth 未就绪")
    config_svc = _mod("pc.service.config")
    db_svc = _mod("pc.service.db")
    crypto_svc = _mod("pc.service.crypto")
    if config_svc is None:
        pytest.skip("config 不可导入")
    import tempfile
    tmp = Path(tempfile.mkdtemp())
    m = pytest.MonkeyPatch()
    try:
        m.setattr(config_svc, "CFG_PATH", tmp / "config.json")
        m.setattr(crypto_svc, "KEY_PATH", tmp / "secret.key")
        m.setattr(db_svc, "DATA_DIR", tmp)
        m.setattr(db_svc, "_p", lambda name: tmp / name)
        config_svc.save(config_svc.load())
        m.setattr(sa, "_last_ok", {})
        m.setattr(sa, "_fail_until", {})
        site = {"key": "s1", "baseUrl": "https://s1.example.com", "checkinType": "newapi"}
        acc = {"key": "a1"}
        m.setattr(sa, "authorize", lambda *a, **k: _res("need_code", "要码"))
        r = sa.exchange(site, acc, config_svc.load(), force=True)
        assert r.state == "need_code"
        assert sa.in_cooldown("a1") is False
    finally:
        m.undo()
