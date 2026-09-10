"""test_site_client.py — 契约测试(设计文档 §3.0)。

不发起真实网络:mock SiteClient._raw_call,验证:
1. 请求头按账号字段叠加(token/cookie/siteUserId 有哪个带哪个)
2. 429 退避重试 3 次
3. WAF 假 200 识别(200 + 非 JSON)
4. 签到流程:已签三态 / 未签 POST 成功 / POST 被拦需人机验证 / 站点未开启签到
5. 站点元信息解析(quota_per_unit / checkin_enabled)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from pc.engine.site_client import CallResult, SiteClient  # noqa: E402


def make_client(account: dict | None = None, site: dict | None = None) -> SiteClient:
    cfg = {
        "UA": "TestUA/1.0",
        "proxy": {"enabled": False},
        "impersonate": ["chrome"],
        "sites": [],
    }
    s = {
        "key": "test-site",
        "name": "测试站",
        "baseUrl": "https://test.example.com",
        "checkinType": "manual",
    }
    if site:
        s.update(site)
    return SiteClient(s, account or {}, cfg)


class FakeTransport:
    """按 path 返回预置响应,记录每次请求头供断言。"""

    def __init__(self, responses: dict[str, list[CallResult] | CallResult]):
        self.responses = {
            k: (v if isinstance(v, list) else [v]) for k, v in responses.items()
        }
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, method: str, path: str, body=None) -> CallResult:
        # 长键优先匹配,避免 "/api/user/checkin" 抢先命中 "?month=" 查询
        for pattern in sorted(self.responses, key=len, reverse=True):
            queue = self.responses[pattern]
            if pattern in path:
                self.calls.append((f"{method} {path}", self._last_headers))
                r = queue.pop(0) if len(queue) > 1 else queue[0]
                return r
        return CallResult(ok=True, status=404, raw="{}")

    _last_headers: dict = {}

    def bind(self, client: SiteClient):
        client._raw_call = self
        return client

    def with_headers(self, headers: dict):
        # SiteClient._headers() 在 _raw_call 前已组好,由 bind 捕获
        return self


def bind(client: SiteClient, responses: dict) -> tuple[SiteClient, FakeTransport]:
    ft = FakeTransport(responses)

    def raw(method: str, path: str, body=None) -> CallResult:
        ft._last_headers = client._headers()
        return ft(method, path, body)

    client._raw_call = raw
    return client, ft


# ---------- 1. 请求头叠加 ----------

def test_headers_full_credentials():
    """三凭据齐全:Bearer + Cookie + New-Api-User 全带(数据驱动,不问站点)。"""
    c = make_client({
        "token": "tok123",
        "siteCookie": "session=abc; other=x",
        "siteUserId": 42,
    })
    h = c._headers()
    assert h["Authorization"] == "Bearer tok123"
    assert h["Cookie"] == "session=abc; other=x"
    assert h["New-Api-User"] == "42"
    assert h["Accept"] == "application/json"
    assert h["User-Agent"] == "TestUA/1.0"


def test_headers_token_only():
    """token 型账号(多数站):只带 Bearer,不带 Cookie/New-Api-User。"""
    c = make_client({"token": "tok123"})
    h = c._headers()
    assert h["Authorization"] == "Bearer tok123"
    assert "Cookie" not in h
    assert "New-Api-User" not in h


def test_headers_cookie_only():
    """cookie 型账号(AgentRouter 实例):token 为 null ⇒ 只带 Cookie + New-Api-User。"""
    c = make_client({"token": None, "siteCookie": "session=zzz", "siteUserId": "u7"})
    h = c._headers()
    assert "Authorization" not in h
    assert h["Cookie"] == "session=zzz"
    assert h["New-Api-User"] == "u7"


def test_headers_null_and_empty_strings():
    """null/空串/'null' 字符串一律视为无该凭据。"""
    c = make_client({"token": "", "siteCookie": "null", "siteUserId": "null"})
    h = c._headers()
    assert "Authorization" not in h
    assert "Cookie" not in h
    assert "New-Api-User" not in h


# ---------- 2. 429 退避 ----------

def test_429_retries_then_succeeds(monkeypatch):
    """429 两次后成功:重试路径打通(退避 sleep 打桩避免测试变慢)。"""
    monkeypatch.setattr("time.sleep", lambda *_: None)
    c = make_client({"token": "t"})
    c.RETRY_BACKOFF = (0, 0, 0)
    c, ft = bind(c, {
        "/api/status": [
            CallResult(ok=True, status=429, raw="{}"),
            CallResult(ok=True, status=429, raw="{}"),
            CallResult(ok=True, status=200, raw='{"success":true}'),
        ]
    })
    r = c.call("get", "/api/status")
    assert r.status == 200
    assert r.data == {"success": True}


def test_429_exhausted(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    c = make_client({"token": "t"})
    c.RETRY_BACKOFF = (0, 0, 0)
    c, _ = bind(c, {
        "/api/status": CallResult(ok=True, status=429, raw="{}")
    })
    r = c.call("get", "/api/status")
    assert r.status == 429
    assert "429" in r.error


# ---------- 3. WAF 假 200 ----------

def test_waf_fake_200():
    """HTTP 200 但响应体非 JSON ⇒ blocked_by_waf,不清空调用方数据。"""
    c = make_client({"token": "t"})
    c, _ = bind(c, {
        "/api/user/self": CallResult(ok=True, status=200, raw="<html>Just a moment...</html>")
    })
    r = c.call("get", "/api/user/self")
    assert r.status == 200
    assert r.blocked_by_waf is True
    assert "WAF" in r.error or "拦截" in r.error


def test_legit_200_parses_json():
    c = make_client({"token": "t"})
    c, _ = bind(c, {
        "/api/user/self": CallResult(ok=True, status=200, raw='{"data":{"quota":100}}')
    })
    r = c.call("get", "/api/user/self")
    assert r.data == {"data": {"quota": 100}}
    assert r.blocked_by_waf is False


# ---------- 4. 签到流程 ----------

def _status_ok(checkin_enabled=True) -> str:
    return json.dumps({
        "success": True,
        "data": {"checkin_enabled": checkin_enabled,
                 "quota_per_unit": 500000, "turnstile_check": False},
    })


def test_checkin_site_disabled():
    """checkin_enabled=false ⇒ 跳过,不查当月不 POST。"""
    c = make_client({"token": "t"})
    c, ft = bind(c, {"/api/status": CallResult(ok=True, status=200, raw=_status_ok(False))})
    out = c.checkin_flow()
    assert out.state == "skipped"
    assert len(ft.calls) == 1  # 只有 status,没打 checkin


def test_checkin_already_with_award():
    """已签且有 quota_awarded:显示金额。"""
    today = __import__("datetime").date.today().strftime("%Y-%m-%d")
    month = __import__("datetime").date.today().strftime("%Y-%m")
    c = make_client({"token": "t"})
    c, _ = bind(c, {
        "/api/status": CallResult(ok=True, status=200, raw=_status_ok()),
        f"checkin?month={month}": CallResult(ok=True, status=200, raw=json.dumps({
            "data": {"stats": {"checked_in_today": True},
                     "records": [{"checkin_date": today, "quota_awarded": 14000000}]}
        })),
    })
    out = c.checkin_flow()
    assert out.state == "already"
    assert out.awarded == 28.0  # 14000000 / 500000


def test_checkin_already_zero_award():
    """已签但 quota_awarded=0:无奖励提示。"""
    import datetime as dt
    today, month = dt.date.today().strftime("%Y-%m-%d"), dt.date.today().strftime("%Y-%m")
    c = make_client({"token": "t"})
    c, _ = bind(c, {
        "/api/status": CallResult(ok=True, status=200, raw=_status_ok()),
        f"month={month}": CallResult(ok=True, status=200, raw=json.dumps({
            "data": {"stats": {}, "records": [{"date": today, "quota_awarded": 0}]}
        })),
    })
    out = c.checkin_flow()
    assert out.state == "already"
    assert out.awarded is None
    assert "无签到奖励" in out.message


def test_checkin_already_records_inside_stats():
    """回归:JustDoWork 把 records 放在 stats.records 内(顶层 records 为空)。

    旧实现只读 data.records ⇒ 找不到今日记录,金额丢失;必须兼容 stats.records。
    """
    import datetime as dt
    today, month = dt.date.today().strftime("%Y-%m-%d"), dt.date.today().strftime("%Y-%m")
    c = make_client({"token": "t"})
    c, ft = bind(c, {
        "/api/status": CallResult(ok=True, status=200, raw=_status_ok()),
        f"month={month}": CallResult(ok=True, status=200, raw=json.dumps({
            "data": {"stats": {"checked_in_today": True,
                               "records": [{"checkin_date": today, "quota_awarded": 12749913}]},
                     "records": []}
        })),
    })
    out = c.checkin_flow()
    assert out.state == "already"
    assert out.awarded == 25.5  # 12749913 / 500000,四舍五入
    # 已签且能读到记录时,不应再 POST 签到(防重复签到)
    assert not any(c0.startswith("post /api/user/checkin") for c0, _ in ft.calls)


def test_checkin_not_done_then_post_success():
    """未签 ⇒ POST 成功,带金额。"""
    import datetime as dt
    month = dt.date.today().strftime("%Y-%m")
    c = make_client({"token": "t"})
    c, ft = bind(c, {
        "/api/status": CallResult(ok=True, status=200, raw=_status_ok()),
        f"month={month}": CallResult(ok=True, status=200, raw='{"data":{"stats":{},"records":[]}}'),
        "/api/user/checkin": CallResult(ok=True, status=200,
                                        raw='{"success":true,"data":{"quota_awarded":2500000}}'),
    })
    out = c.checkin_flow()
    assert out.state == "done"
    assert out.awarded == 5.0
    # 验证 POST 确实发生
    assert any(c0.startswith("post /api/user/checkin") for c0, _ in ft.calls)


def test_checkin_post_needs_captcha():
    """POST 被拦(响应含人机验证字样)⇒ need_captcha。"""
    import datetime as dt
    month = dt.date.today().strftime("%Y-%m")
    c = make_client({"token": "t"})
    c, _ = bind(c, {
        "/api/status": CallResult(ok=True, status=200, raw=_status_ok()),
        f"month={month}": CallResult(ok=True, status=200, raw='{"data":{"stats":{},"records":[]}}'),
        "/api/user/checkin": CallResult(ok=True, status=403,
                                        raw='{"message":"请完成人机验证 (turnstile) 后重试"}'),
    })
    out = c.checkin_flow()
    assert out.state == "need_captcha"


def test_checkin_post_401():
    """401 ⇒ 凭据失效,交上层静默换新。"""
    import datetime as dt
    month = dt.date.today().strftime("%Y-%m")
    c = make_client({"token": "expired"})
    c, _ = bind(c, {
        "/api/status": CallResult(ok=True, status=200, raw=_status_ok()),
        f"month={month}": CallResult(ok=True, status=200, raw='{"data":{"stats":{},"records":[]}}'),
        "/api/user/checkin": CallResult(ok=True, status=401, raw="{}"),
    })
    out = c.checkin_flow()
    assert out.state == "failed"
    assert "401" in out.message


# ---------- 5. 站点元信息 ----------

def test_status_meta_fields():
    c = make_client({"token": "t"})
    c, _ = bind(c, {
        "/api/status": CallResult(ok=True, status=200, raw=json.dumps({
            "success": True,
            "data": {"quota_per_unit": 500000, "turnstile_check": True,
                     "turnstile_site_key": "0x4AAA", "github_client_id": "Iv23li",
                     "checkin_enabled": True},
        }))
    })
    r = c.status()
    d = r.data["data"]
    assert d["github_client_id"] == "Iv23li"
    assert d["turnstile_check"] is True


# ---------- 6. OAuth state 双形态(供 P2 用,先固化契约) ----------

def test_oauth_state_post_then_get_fallback():
    """POST 404 ⇒ 改 GET ?mode=login(契约:AgentRouter 型,404 才切换)。"""
    c = make_client({})
    c, ft = bind(c, {
        "/api/oauth/state": [
            CallResult(ok=True, status=404, raw="404 page not found"),
            CallResult(ok=True, status=200, raw='{"success":true,"data":"flow_token_x"}'),
        ]
    })
    # 第一次 POST 404
    r1 = c.call("post", "/api/oauth/state", {"provider": "github", "intent": "login"})
    assert r1.status == 404
    # 回退 GET
    r2 = c.call("get", "/api/oauth/state?mode=login")
    assert r2.status == 200
    assert r2.data["data"] == "flow_token_x"
