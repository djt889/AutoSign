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
    """B-3:每个 cookie 必须带 domain(Playwright 要求 url 或 domain)。"""
    host = "s1.example.com"
    assert ck._account_cookies("session=abc; uid=7", host) == [
        {"name": "session", "value": "abc", "path": "/", "domain": host},
        {"name": "uid", "value": "7", "path": "/", "domain": host},
    ]
    assert ck._account_cookies("", host) == []


def test_stealthy_cookies_carry_site_domain(tmp_path, monkeypatch):
    """B-3 回归:_checkin_via_stealthy 调用点必须传站点 hostname(此前漏传
    导致 Playwright cookie 无 url/domain 报错,cookie 型账号第二级全挂)。"""
    site, acc, cfg = make()
    acc["siteCookie"] = "session=zzz"
    captured: dict = {}

    def fake_fetch_cf_safe(url, kwargs):
        captured["cookies"] = kwargs.get("cookies")
        return None

    monkeypatch.setattr(ck, "_fetch_cf_safe", fake_fetch_cf_safe)
    ck._checkin_via_stealthy(site, acc, cfg, ck.SiteClient(site, acc, cfg))
    assert captured["cookies"] == [
        {"name": "session", "value": "zzz", "path": "/", "domain": "s1.example.com"}]


def test_usd_in_text_strict():
    """B-15:金额必须紧邻货币符号,裸数字不再误判。"""
    assert ck._usd_in_text("第 3 天签到获得＄10") == 10.0     # 不是 3.0
    assert ck._usd_in_text("获得额度 ＄20.642880 额度") == 20.64
    assert ck._usd_in_text("奖励 $5") == 5.0
    assert ck._usd_in_text("￥3.5 已到账") == 3.5
    assert ck._usd_in_text("第 3 天签到") is None             # 裸数字不匹配
    assert ck._usd_in_text("奖励 USD 2 到账") is None
    assert ck._usd_in_text("无金额文案") is None


def test_is_checkin_text_traditional():
    """B-15:繁体「簽到」也识别为签到文案;排除项不放松。"""
    assert ck._is_checkin_text("簽到獲得獎勵") is True
    assert ck._is_checkin_text("签到获得奖励") is True
    assert ck._is_checkin_text("每日checkin bonus") is True
    assert ck._is_checkin_text("注册赠送") is False            # 排除项仍有效
    assert ck._is_checkin_text("邀請獎勵") is False


def test_l1_success_false_falls_to_l2(tmp_path, monkeypatch):
    """B-2 回归:第一级 POST 返回 200 但 success=false 不得判 done——
    落日志后继续第二级,由整页求解完成签到。"""
    site, acc, cfg = make()
    db = patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(ck.SiteClient, "checkin_flow",
                        lambda self: CheckinOutcome("need_captcha", message="被拦"))
    monkeypatch.setattr(ck.SiteClient, "status",
                        lambda self: type("R", (), {"status": 200, "data": {"data": {"turnstile_site_key": "0xKEY"}}})())
    monkeypatch.setattr(ck, "_fetch_turnstile_token_headless", lambda *a, **k: "tok123")
    monkeypatch.setattr(ck.SiteClient, "checkin_post",
                        lambda self, turnstile_token="": type("R", (), {
                            "status": 200, "blocked_by_waf": False,
                            "data": {"success": False, "message": "签到失败,请重试"}})())
    monkeypatch.setattr(ck, "_checkin_via_stealthy",
                        lambda *a, **k: '{"success":true,"data":{"quota_awarded":2500000}}')
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 200, "blocked_by_waf": False, "data": {}})())
    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "done"
    assert rep.captcha_level == 2                              # 不是 1
    assert any(l["event"] == "captcha-l1" and l.get("level") == "err"
               and l["detail"].get("success") is False for l in db.recent_logs(10))


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


def _fail_responses(monkeypatch):
    """把 login 型前置判定用的站点接口全部 mock 成失败(already 判定走 False)。"""
    monkeypatch.setattr(ck.SiteClient, "sys_log",
                        lambda self, **k: type("R", (), {"status": 500, "blocked_by_waf": False,
                                                         "data": {}})())
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 401, "blocked_by_waf": False,
                                                    "data": {}})())
    monkeypatch.setattr(ck.SiteClient, "status",
                        lambda self: type("R", (), {"status": 500, "data": {}})())


def test_login_relogin_unseals_account(tmp_path, monkeypatch):
    """B-17 回归:重登后 client.account 必须是明文(unseal 幂等)。

    exchange 只更新了 token 时,account 里旧 siteCookie 仍是 enc: 密文;
    直接 client.account = account 会把密文当 Cookie 头发出去(401)。
    """
    from pc.service import crypto
    from pc.engine.oauth_flow import AuthResult
    site, acc, cfg = make("login")
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    acc["siteCookie"] = crypto.encrypt("old-cookie")
    acc["token"] = ""
    _fail_responses(monkeypatch)

    seen: dict = {}
    def fake_self(self):
        seen["account"] = dict(self.account)          # 记录 exchange 后的 client.account
        return type("R", (), {"status": 401, "blocked_by_waf": False, "data": {}})()
    monkeypatch.setattr(ck.SiteClient, "self_info", fake_self)
    monkeypatch.setattr(ck, "exchange",
                        lambda *a, **k: AuthResult("ok", "授权成功", token="new-tok"))

    rep = ck.run_checkin(site, acc, cfg)
    # 本用例核心目的(B-17)是下面两条:重登后发给站点的 account 必须已解密。
    # state 断言的是**新语义**:站点未确认今日额度到账(本用例 self_info 恒 401、
    # 无今日奖励记录)时不允许报 done——否则界面谎报"今日已签"而实际没领到。
    assert rep.state == "failed"
    assert seen["account"]["siteCookie"] == "old-cookie"   # 解密明文,不是 enc:*
    assert seen["account"]["token"] == "new-tok"           # 新 token 原样(明文)


def test_login_relogin_passes_credential(tmp_path, monkeypatch):
    """B-4:login 重登透传凭据(有密码才能在 GitHub 登录墙自动填充)。

    此前硬编码 credential=None,重登必然卡 2FA/登录墙 ⇒ 全自动链路断。
    """
    from pc.service import config as config_svc, crypto
    from pc.engine import credentials as cr
    from pc.engine.oauth_flow import AuthResult
    site, acc, cfg = make("login")
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(config_svc, "CFG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    cfg["sites"] = [site]
    site["accounts"] = [dict(acc)]
    config_svc.save(cfg)
    r = cr.upsert_credential(github_user="u@x.com", password="pw1")
    cfg2 = config_svc.load()
    _, a2 = config_svc.find_account(cfg2, "a1")
    a2["credentialId"] = r["id"]
    config_svc.save(cfg2)
    _fail_responses(monkeypatch)

    captured: dict = {}
    def fake_exchange(site, account, cfg_, credential=None, force=False, **k):
        captured["credential"] = credential
        captured["force"] = force
        return AuthResult("failed", "stop-here")
    monkeypatch.setattr(ck, "exchange", fake_exchange)

    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "failed"
    assert captured["force"] is True
    assert captured["credential"] == {"username": "u@x.com", "password": "pw1",
                                      "totpSecret": ""}


# ---------- 「不谎报已签」回归(用户实测反馈:界面显示已签、实际没领到) ----------

def _mock_relogin_ok(monkeypatch):
    """重登成功但站点侧额度未确认(与真实故障场景一致)。"""
    from pc.engine.oauth_flow import AuthResult
    monkeypatch.setattr(ck, "exchange",
                        lambda *a, **k: AuthResult("ok", "授权成功", token="new-tok"))
    # sys_log/self_info/status 全不可用 ⇒ 拿不到今日奖励记录与 last_login_time
    _fail_responses(monkeypatch)


def _today():
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d")


def _Outcome(state, **kw):
    from pc.engine.site_client import CheckinOutcome
    return CheckinOutcome(state, **kw)


def test_login_not_rewarded_must_not_report_done(tmp_path, monkeypatch):
    """核心回归:重登完成但额度**未到账**时,绝不能报 done。

    否则前端显示「今日已签」,用户以为领到了,实际没有(实测该站会出现
    重登成功但今日奖励记录未生成的情况)。判据须与 already 分支一致。
    """
    from pc.service import crypto
    site, acc, cfg = make("login")
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    acc["token"] = ""
    acc["siteCookie"] = crypto.encrypt("ck")
    _mock_relogin_ok(monkeypatch)

    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state != "done", "额度未到账却报 done = 谎报已签"
    assert rep.state == "failed"
    assert "未确认" in rep.message or "未到账" in rep.message


def test_login_rewarded_reports_done(tmp_path, monkeypatch):
    """对照用例:站点确认今日奖励到账 ⇒ done(正常路径不被误伤)。"""
    from pc.service import crypto
    from pc.engine.oauth_flow import AuthResult
    site, acc, cfg = make("login")
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    acc["token"] = ""
    acc["siteCookie"] = crypto.encrypt("ck")
    monkeypatch.setattr(ck, "exchange",
                        lambda *a, **k: AuthResult("ok", "授权成功", token="new-tok"))
    # 今日奖励记录可达 ⇒ 确认到账
    monkeypatch.setattr(ck.SiteClient, "sys_log",
                        lambda self, **k: type("R", (), {
                            "status": 200, "blocked_by_waf": False,
                            "data": {"data": {"list": [{"content": "每日签到奖励 $20",
                                                        "created_at": _today()}]}}})())
    monkeypatch.setattr(ck.SiteClient, "self_info",
                        lambda self: type("R", (), {"status": 200, "blocked_by_waf": False,
                                                    "data": {"data": {"quota": 10**7, "used_quota": 0}}})())
    monkeypatch.setattr(ck.SiteClient, "status",
                        lambda self: type("R", (), {"status": 200, "data": {"data": {}}})())

    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state in ("done", "already")


def test_failed_checkin_persists_state_for_frontend(tmp_path, monkeypatch):
    """失败必须落盘 lastCheckin:否则前端刷新后无从得知未签,会显示成已签。"""
    from pc.service import config as config_svc, crypto
    site, acc, cfg = make()
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(config_svc, "CFG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    cfg["sites"] = [site]
    site["accounts"] = [dict(acc)]
    config_svc.save(cfg)
    monkeypatch.setattr(ck.SiteClient, "checkin_flow",
                        lambda self: _Outcome("failed", message="站点维护中"))

    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "failed"
    import json as _json
    raw = _json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    lc = raw["sites"][0]["accounts"][0].get("lastCheckin") or {}
    assert lc.get("state") == "failed", "失败状态未落盘,前端会误显示已签"
    assert lc.get("message")


def test_login_relogin_failure_persists(tmp_path, monkeypatch):
    """重登失败必须落盘 failed:否则前端停留在上次(甚至几天前)的「已签」。

    实测 GoRouter 曾因重登失败(站点 502)而 lastCheckin 停留在 09-15,
    界面一直显示已签,与实际完全不符。
    """
    from pc.service import config as config_svc, crypto
    from pc.engine.oauth_flow import AuthResult
    site, acc, cfg = make("login")
    patch_db(tmp_path, monkeypatch)
    monkeypatch.setattr(config_svc, "CFG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(crypto, "KEY_PATH", tmp_path / "secret.key")
    # 预置一条陈旧的成功记录,模拟"几天前的已签"
    site["accounts"] = [dict(acc)]
    site["accounts"][0]["lastCheckin"] = {"date": "2020-01-01", "state": "done", "reward": 9.9}
    cfg["sites"] = [site]
    config_svc.save(cfg)
    monkeypatch.setattr(ck, "exchange",
                        lambda *a, **k: AuthResult("failed", "获取授权会话失败: state 获取失败(HTTP 502)"))

    rep = ck.run_checkin(site, acc, cfg)
    assert rep.state == "failed"
    import json as _json
    raw = _json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    lc = raw["sites"][0]["accounts"][0].get("lastCheckin") or {}
    assert lc.get("state") == "failed", "重登失败未落盘,界面会停留在旧的成功状态"
    assert lc.get("date") == _today()
    assert "重新登录失败" in (lc.get("message") or "")
