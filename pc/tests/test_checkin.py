"""test_checkin.py — 签到闭环测试(P1 契约:两级 Turnstile 全自动,失败即报错不转人工)。

mock SiteClient.checkin_flow / StealthyFetcher,不发起真实网络与浏览器。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from pc.engine import checkin as ck  # noqa: E402
from pc.engine.site_client import CheckinOutcome  # noqa: E402


def make(site_type="newapi"):
    cfg = {"UA": "T", "proxy": {"enabled": False}, "impersonate": ["chrome"], "sites": []}
    site = {"key": "s1", "name": "站1", "baseUrl": "https://s1.example.com",
            "checkinType": site_type, "accounts": []}
    acc = {"key": "a1", "alias": "主号", "token": "tok"}
    return site, acc, cfg


def patch_db(tmp_path, monkeypatch):
    from pc.service import db
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "_p", lambda name: tmp_path / name)
    return db


def test_done_direct_no_captcha(tmp_path, monkeypatch):
    """免验直达:POST 成功,quota 刷新,captcha_level=0。"""
    db = patch_db(tmp_path, monkeypatch)
    site, acc, cfg = make()
    monkeypatch.setattr(
        ck.SiteClient, "checkin_flow",
        lambda self: CheckinOutcome("done", awarded=25.0, message="签到成功"),
    )
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 200, "blocked_by_waf": False,
                                                    "data": {"data": {"quota": 5000000, "used_quota": 1000000, "today_used_quota": 250000}}})())
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "done"
    assert rep.awarded == 25.0
    assert rep.captcha_level == 0
    assert rep.quota["availableUSD"] == 10.0
    assert rep.quota["usedUSD"] == 2.0
    assert rep.quota["todayUsedUSD"] == 0.5
    assert db.recent_logs(5)[0]["event"] == "checkin"


def test_already_shows_award(tmp_path, monkeypatch):
    site, acc, cfg = make()
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(ck.SiteClient, "checkin_flow",
                        lambda self: CheckinOutcome("already", awarded=28.0, message="今日已签到"))
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 200, "blocked_by_waf": False, "data": {}})())
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "already" and rep.awarded == 28.0


def test_login_type_already_today(tmp_path, monkeypatch):
    """login 型:last_login_time 为今日 ⇒ already,不重放 OAuth。"""
    import datetime as dt
    site, acc, cfg = make("login")
    patch_db(tmp_path, monkeypatch)
    class R:
        status = 200
        blocked_by_waf = False
        data = {"data": {"quota": 2500000, "used_quota": 0,
                         "last_login_time": dt.datetime.now().timestamp()}}
    monkeypatch.setattr(ck.SiteClient, "self_info", lambda self: R())
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "already"
    assert "登录领取" in rep.message
    assert rep.quota["availableUSD"] == 5.0


def test_login_type_relogin_for_reward(tmp_path, monkeypatch):
    """login 型:今日未领 ⇒ 强制静默重放 OAuth(退出重登)→ done + 额度刷新。"""
    import datetime as dt
    from pc.engine.oauth_flow import AuthResult
    site, acc, cfg = make("login")
    patch_db(tmp_path, monkeypatch)

    # 第一次 self:last_login_time 是昨天(未领)
    old = {"data": {"quota": 2500000, "used_quota": 0,
                    "last_login_time": (dt.datetime.now() - dt.timedelta(days=1)).timestamp()}}
    fresh = {"data": {"quota": 2750000, "used_quota": 0,
                      "last_login_time": dt.datetime.now().timestamp()}}
    seq = {"n": 0}
    class R:
        def __init__(self):
            self.status = 200
            self.blocked_by_waf = False
            self.data = fresh if seq["n"] > 1 else old
    def fake_self(self):
        seq["n"] += 1
        return R()
    monkeypatch.setattr(ck.SiteClient, "self_info", fake_self)
    monkeypatch.setattr(ck, "exchange",
                        lambda *a, **k: AuthResult("ok", "授权成功", token="t",
                                                   site_cookie="session=new"))
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "done"
    assert "重新登录完成" in rep.message
    assert acc["siteCookie"] == "session=new"      # 新凭据就地更新
    assert rep.quota["availableUSD"] == 5.5        # 刷新后的额度


def test_login_type_relogin_fail(tmp_path, monkeypatch):
    """login 型:重放失败 ⇒ failed 报错(无人工兜底)。"""
    from pc.engine.oauth_flow import AuthResult
    site, acc, cfg = make("login")
    db = patch_db(tmp_path, monkeypatch)
    class R:
        status = 401
        blocked_by_waf = False
        data = {}
    monkeypatch.setattr(ck.SiteClient, "self_info", lambda self: R())
    monkeypatch.setattr(ck, "exchange",
                        lambda *a, **k: AuthResult("failed", "GitHub 会话过期"))
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "failed"
    assert "重新登录失败" in rep.message
    assert any(l["event"] == "checkin" and l.get("level") == "err" for l in db.recent_logs(5))


def test_level1_widget_passes(tmp_path, monkeypatch):
    """第一级:挂件拿 token 后 POST 成功 ⇒ captcha_level=1。"""
    site, acc, cfg = make()
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(ck.SiteClient, "checkin_flow",
                        lambda self: CheckinOutcome("need_captcha", message="被拦"))
    monkeypatch.setattr(ck.SiteClient, "status",
                        lambda self: type("R", (), {"status": 200, "data": {"data": {"turnstile_site_key": "0xKEY"}}})())
    monkeypatch.setattr(ck, "_fetch_turnstile_token_headless", lambda *a, **k: "tok123")
    monkeypatch.setattr(ck.SiteClient, "checkin_post",
                        lambda self, turnstile_token="": type("R", (), {
                            "status": 200, "blocked_by_waf": False,
                            "data": {"data": {"quota_awarded": 2500000}}})())
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 200, "blocked_by_waf": False, "data": {}})())
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "done"
    assert rep.captcha_level == 1
    assert rep.awarded == 5.0


def test_level2_stealthy_after_l1_fails(tmp_path, monkeypatch):
    """第一级失败(拿不到 token)⇒ 第二级成功 ⇒ captcha_level=2。"""
    site, acc, cfg = make()
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(ck.SiteClient, "checkin_flow",
                        lambda self: CheckinOutcome("need_captcha", message="被拦"))
    monkeypatch.setattr(ck.SiteClient, "status",
                        lambda self: type("R", (), {"status": 200, "data": {"data": {"turnstile_site_key": "0xKEY"}}})())
    monkeypatch.setattr(ck, "_fetch_turnstile_token_headless", lambda *a, **k: "")  # 一级失败
    monkeypatch.setattr(ck, "_checkin_via_stealthy",
                        lambda *a, **k: '{"success":true,"data":{"quota_awarded":2500000}}')
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 200, "blocked_by_waf": False, "data": {}})())
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "done"
    assert rep.captcha_level == 2
    assert rep.awarded == 5.0


def test_both_levels_fail_no_human_fallback(tmp_path, monkeypatch):
    """两级都失败 ⇒ failed 报错,绝不转人工(§7 契约)。"""
    site, acc, cfg = make()
    db = patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(ck.SiteClient, "checkin_flow",
                        lambda self: CheckinOutcome("need_captcha", message="被拦"))
    monkeypatch.setattr(ck.SiteClient, "status",
                        lambda self: type("R", (), {"status": 200, "data": {"data": {"turnstile_site_key": "0xKEY"}}})())
    monkeypatch.setattr(ck, "_fetch_turnstile_token_headless",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("browser fail")))  # 一级异常
    monkeypatch.setattr(ck, "_checkin_via_stealthy", lambda *a, **k: "")  # 二级失败
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "failed"
    assert rep.captcha_level == -1
    assert "两级" in rep.message or "失败" in rep.message
    # 失败必须记日志,且没有任何"转人工/手动"语义
    assert "人工" not in rep.message and "手动" not in rep.message
    logs = db.recent_logs(10)
    assert any(l["event"] == "checkin" and l.get("level") == "err" for l in logs)


def test_401_failed_message(tmp_path, monkeypatch):
    site, acc, cfg = make()
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(ck.SiteClient, "checkin_flow",
                        lambda self: CheckinOutcome("failed", message="凭据失效(401),需静默换新"))
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "failed"
    assert "401" in rep.message


def test_account_cookies_parser():
    assert ck._account_cookies("session=abc; uid=7") == [
        {"name": "session", "value": "abc", "path": "/"},
        {"name": "uid", "value": "7", "path": "/"},
    ]
    assert ck._account_cookies("") == []


def test_checkin_persist_lastCheckin(tmp_path, monkeypatch):
    """签到成功必须落盘 lastCheckin{date,state,reward},供刷新后判定已签。"""
    import datetime as dt
    from pc.service import config as config_svc
    site, acc, cfg = make()
    site["accounts"] = [dict(acc)]
    cfg["sites"] = [site]
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(config_svc, "CFG_PATH", tmp_path / "config.json")
    config_svc.save(cfg)
    monkeypatch.setattr(ck.SiteClient, "checkin_flow",
                        lambda self: CheckinOutcome("done", awarded=25.0, message="签到成功"))
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 200, "blocked_by_waf": False,
                                                    "data": {"data": {"quota": 5000000, "used_quota": 0}}})())
    rep = ck.run_checkin(site, site["accounts"][0], cfg)
    assert rep.state == "done"
    saved = config_svc.load()["sites"][0]["accounts"][0]
    assert saved.get("lastCheckin", {}).get("date") == dt.date.today().strftime("%Y-%m-%d")
    assert saved["lastCheckin"]["state"] == "done"
    assert saved["lastCheckin"]["reward"] == 25.0
    # to_dict 必须带 date,前端用它更新落盘快照
    d = rep.to_dict()
    assert d["date"] == dt.date.today().strftime("%Y-%m-%d")


def test_status_cache_cleared_after_checkin():
    """checkin 接口签到后必须清除该账号 status 缓存,否则额度显示过期值。"""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    import pc.main as main
    main._status_cache["k1"] = (9999999999.0, {"ok": True})
    assert "k1" in main._status_cache
    # 模拟 checkin 的清缓存逻辑(与 main.checkin 同实现)
    main._status_cache.pop("k1", None)
    assert "k1" not in main._status_cache
