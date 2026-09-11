"""test_oauth_engine.py — 授权引擎(oauth_flow.py)单测:⑤⑥⑦⑧ 契约面。

不发真实网络/浏览器:monkeypatch 网络与 StealthyFetcher.fetch,用 fake page
驱动 authorize 内部 action 循环,验证:
  ⑤ 手动码按 task_id 隔离 + 120s 过期 + 一次性消费
  ⑥ headless 进 2FA 页无自动码 ⇒ on_state(waiting_code) 通知一次而非静默空转
  ⑦ 同一码只提交一次(不每 2s 重复 fill)
  ⑧ headful 按 task_id 取码注入
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from pc.engine import oauth_flow as of  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_manual_codes():
    """每个用例前后清空手动码桶,防跨模块顺序污染(码是进程级全局状态)。"""
    of._clear_manual_codes()
    yield
    of._clear_manual_codes()


def _patch_env(monkeypatch, tmp_path):
    """把日志/密钥落到 tmp,避免写真实 data 目录。"""
    from pc.service import db, crypto
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "_p", lambda name: tmp_path / name)
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    of._clear_manual_codes()


def _cfg_site_account():
    cfg = {"UA": "T", "proxy": {"enabled": False}, "impersonate": ["chrome"]}
    site = {"key": "s1", "name": "站1", "baseUrl": "https://s1.example.com",
            "checkinType": "newapi"}
    account = {"key": "a1", "alias": "主号", "githubAccount": "u1"}
    return cfg, site, account


# ---------- ⑤ 手动码存储:task 隔离 / 过期 / 一次性 ----------

def test_manual_code_bucket_isolation():
    """⑤ 两个不同 task_id 互不串码;空 task 落默认桶。"""
    of._clear_manual_codes()
    of.set_manual_code("111111", "t1")
    of.set_manual_code("222222", "t2")
    assert of._take_manual_code("t1") == "111111"
    assert of._take_manual_code("t2") == "222222"
    # 默认桶:旧调用(不传 task_id)
    of.set_manual_code("333333", "")
    assert of._take_manual_code("") == "333333"
    assert of._take_manual_code("_default") == ""     # 已被消费


def test_manual_code_single_consume():
    """⑤ 消费一次即清除,再取返回空。"""
    of._clear_manual_codes()
    of.set_manual_code("123456", "tk")
    assert of._take_manual_code("tk") == "123456"
    assert of._take_manual_code("tk") == ""            # 已消费


def test_manual_code_expiry_120s(monkeypatch):
    """⑤ 注入后超 120s 取不到(monkeypatch 时钟,不真等)。"""
    of._clear_manual_codes()
    fake = {"now": 1000.0}
    monkeypatch.setattr(of.time, "time", lambda: fake["now"])
    of.set_manual_code("123456", "tx")
    assert of._take_manual_code("tx") == "123456"      # 未过期可取
    of.set_manual_code("123456", "ty")
    fake["now"] += 121.0                               # 越过 120s
    assert of._take_manual_code("ty") == ""            # 过期取不到


# ---------- fake page(驱动 authorize 的 action 循环) ----------

class _Locator:
    def __init__(self, page, sel):
        self._page = page
        self._sel = sel

    def count(self):
        # otp 输入框组合选择器含 one-time-code ⇒ 视为存在;
        # authenticator 切换链接选择器含 authenticator ⇒ 视为存在(页面通常有该入口)
        sel = self._sel
        if "one-time-code" in sel or "authenticator" in sel:
            return 1
        return 1 if sel in self._page.present else 0

    @property
    def first(self):
        return self

    def click(self):
        self._page.clicked.append(self._sel)

    def fill(self, value):
        self._page.filled.append((self._sel, value))

    def is_visible(self):
        return True


class _Page:
    """最小 fake page:固定在某个 URL,记录 fill/click 次数。"""

    def __init__(self, url, present=()):
        self.url = url
        self.present = set(present)
        self.clicked: list[str] = []
        self.filled: list[tuple[str, str]] = []

    def locator(self, sel):
        return _Locator(self, sel)

    def wait_for_timeout(self, ms):
        pass

    def on(self, event, cb):
        pass

    @property
    def main_frame(self):
        return self

    @property
    def context(self):
        return self

    def cookies(self, domain=None):
        return []

    def goto(self, url, wait_until=None):
        self.url = url

    def clear_cookies(self):
        pass


class _Resp:
    captured_xhr = []


def _bootstrap_authorize(monkeypatch, tmp_path, page, headful: bool = False):
    """patch 网络/浏览器边界,返回 (authorize_kwargs_extra, 结果容器)。"""
    _patch_env(monkeypatch, tmp_path)
    monkeypatch.setattr(of, "fetch_state",
                        lambda client: ("flow_tok", ""))
    monkeypatch.setattr(of, "fetch_client_id", lambda client: "cid")

    class _SF:
        @staticmethod
        def fetch(url, **kwargs):
            # 记录 page_action 并执行:用 fake page 驱动 action 循环
            action = kwargs.get("page_action")
            if action:
                action(page)
            return _Resp()

    monkeypatch.setattr("scrapling.fetchers.StealthyFetcher.fetch", _SF.fetch)
    if headful:
        monkeypatch.setattr(of, "ensure_manual_chrome", lambda: (True, "ok"))
        monkeypatch.setattr(of, "manual_cdp_url", lambda: "ws://127.0.0.1:19222")
    return page


def _otp_fill_count(page) -> int:
    """统计 otp 输入框的 fill 次数(组合选择器里含 one-time-code)。"""
    return sum(1 for sel, _ in page.filled if "one-time-code" in sel)


# ---------- ⑥ 进 2FA 页无自动码 ⇒ on_state(waiting_code) 一次 ----------

def test_2fa_waiting_code_notified_once(monkeypatch, tmp_path):
    """⑥ headless 进 2FA 页、无 TOTP 密钥也无注入码:on_state 被调用一次,
    state=waiting_code;不静默空转,流程继续循环等待。"""
    cfg, site, account = _cfg_site_account()
    credential = {"username": "u1", "password": "pw"}     # 有账密但无 totpSecret
    page = _Page("https://github.com/sessions/two-factor")
    _bootstrap_authorize(monkeypatch, tmp_path, page)

    states: list[dict] = []

    def on_state(st):
        states.append(st)

    r = of.authorize(site, account, cfg, credential, headful=False,
                     task_id="t6", on_state=on_state)
    # 只通知一次(去重),且是 waiting_code
    assert len(states) == 1
    assert states[0]["state"] == "waiting_code"
    assert "hint" in states[0] and states[0]["hint"]
    # 超时仍无码 ⇒ failed 且 manual_url 非空(前端还有手动出路)
    assert r.state in ("failed", "need_manual")
    assert r.manual_url
    assert r.code_task == "t6"


def test_2fa_email_device_hint_distinct(monkeypatch, tmp_path):
    """⑥ hint 区分邮箱设备验证码(url 含 verified-device/device)与 TOTP。"""
    cfg, site, account = _cfg_site_account()
    credential = {"username": "u1", "password": "pw"}

    email_page = _Page("https://github.com/verified-device")
    _bootstrap_authorize(monkeypatch, tmp_path, email_page)
    email_states: list[dict] = []
    of.authorize(site, account, cfg, credential, headful=False,
                 task_id="te", on_state=email_states.append)
    assert email_states and "邮箱" in email_states[0]["hint"]

    totp_page = _Page("https://github.com/sessions/two-factor/app")
    _bootstrap_authorize(monkeypatch, tmp_path, totp_page)
    totp_states: list[dict] = []
    of.authorize(site, account, cfg, credential, headful=False,
                 task_id="tt", on_state=totp_states.append)
    assert totp_states and ("验证码" in totp_states[0]["hint"])


# ---------- ⑦ 同码不重复提交 ----------

def test_2fa_code_submitted_once(monkeypatch, tmp_path):
    """⑦ 同一码只提交一次:注入码被消费后不再重复 fill,也不重复点 authenticator。"""
    cfg, site, account = _cfg_site_account()
    credential = {"username": "u1", "password": "pw", "totpSecret": ""}
    page = _Page("https://github.com/sessions/two-factor", present=["authenticator"])
    _bootstrap_authorize(monkeypatch, tmp_path, page)

    of.set_manual_code("654321", "t7")
    states: list[dict] = []
    r = of.authorize(site, account, cfg, credential, headful=False,
                     task_id="t7", on_state=states.append)
    # 码已注入 ⇒ 不报 waiting_code
    assert states == []
    # otp 只被 fill 一次
    assert _otp_fill_count(page) == 1
    # 认证器切换链接也只点一次
    assert sum(1 for c in page.clicked if "authenticator" in c) == 1


# ---------- ⑧ headful 按 task_id 取码 ----------

def test_headful_takes_code_by_task_id(monkeypatch, tmp_path):
    """⑧ 有头模式:按本任务 task_id 取码注入(不再用全局 _manual_code)。"""
    cfg, site, account = _cfg_site_account()
    credential = {"username": "u1", "password": "pw"}
    page = _Page("https://github.com/sessions/two-factor")
    _bootstrap_authorize(monkeypatch, tmp_path, page, headful=True)

    of.set_manual_code("888888", "t8")     # 只注入本任务
    of.set_manual_code("999999", "other")  # 别的任务桶不串
    states: list[dict] = []
    r = of.authorize(site, account, cfg, credential, headful=True,
                     task_id="t8", on_state=states.append)
    assert _otp_fill_count(page) == 1
    assert page.filled and page.filled[0][1] == "888888"   # 用的是本任务桶的码
    assert states == []
    assert r.state in ("failed", "need_manual")
