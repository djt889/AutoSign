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


def test_login_type_refresh(tmp_path, monkeypatch):
    """login 型:不打签到接口,刷新即取奖励。"""
    site, acc, cfg = make("login")
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 200, "blocked_by_waf": False,
                                                    "data": {"data": {"quota": 2500000, "used_quota": 0}}})())
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "skipped"
    assert "登录即发额度" in rep.message
    assert rep.quota["availableUSD"] == 5.0


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
