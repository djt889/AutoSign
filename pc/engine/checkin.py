"""checkin.py — 签到闭环(P1)。

契约(设计文档 §3.0 签到流程 + §7 两级全自动):
1. 前置判定:GET /api/user/checkin?month → 已签直接返回(奖励三态)
2. POST /api/user/checkin;被拦(响应匹配人机验证)进入两级自动处理
3. 第一级:浏览器挂官方 Turnstile 挂件(interaction-only)拿 token 重试 POST
4. 第二级:StealthyFetcher solve_cloudflare 整页求解后重试 POST
5. 两级都失败 ⇒ 报错记日志,**不转人工**(签到 100% 自动化)
6. 成功后自动刷三额度(可用/已用/今日消耗)

浏览器依赖(scrapling install 的 Chromium)只在需要 Turnstile 时才拉起,
日常已签/免验签到零浏览器开销。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..service import db
from .site_client import CallResult, SiteClient

TURNSTILE_JS_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"


@dataclass
class CheckinReport:
    account_key: str
    site_key: str
    state: str                     # done / already / skipped / failed
    awarded: float | None = None
    message: str = ""
    captcha_level: int = 0         # 0=未遇验证 1=挂件通过 2=Stealthy 求解通过 -1=两级均失败
    quota: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ok": self.state in ("done", "already", "skipped"),
            "state": self.state,
            "awarded": self.awarded,
            "message": self.message,
            "captchaLevel": self.captcha_level,
            "quota": self.quota,
        }


# ---------- Turnstile 挂件令牌(第一级:官方挂件 interaction-only) ----------

_WIDGET_JS = """
(async () => {
  const sitekey = window.__TS_SITEKEY__;
  const box = document.createElement('div');
  document.body.appendChild(box);
  window.turnstile = undefined;
  const sc = document.createElement('script');
  sc.src = '%s';
  document.head.appendChild(sc);
  for (let i = 0; i < 50 && !(window.turnstile && window.turnstile.render); i++) {
    await new Promise(r => setTimeout(r, 200));
  }
  if (!window.turnstile || !window.turnstile.render) return '';
  return await new Promise(resolve => {
    try {
      window.turnstile.render(box, {
        sitekey,
        appearance: 'interaction-only',
        callback: t => resolve(t),
        'error-callback': () => resolve(''),
        'expired-callback': () => resolve(''),
      });
    } catch (e) { resolve(''); }
    setTimeout(() => resolve(''), 25000);
  });
})()
""" % TURNSTILE_JS_URL


def _fetch_turnstile_token_headless(base_url: str, site_key: str, sitekey: str,
                                    proxy: str | None) -> str:
    """第一级:headless 浏览器在站点同域挂 interaction-only 挂件,静默拿 token。

    必须在站点域下执行(Turnstile 校验域名),所以先加载站点任意页再注入;
    token 通过闭包变量带回(page_action 的返回值不会被 scrapling 透传)。
    """
    from scrapling.fetchers import StealthyFetcher

    holder: dict[str, str] = {"token": ""}

    def action(page):
        js = _WIDGET_JS.replace("window.__TS_SITEKEY__", json.dumps(sitekey))
        holder["token"] = page.evaluate(js) or ""

    kwargs: dict[str, Any] = dict(
        headless=True,
        solve_cloudflare=True,          # 顺带处理页面级 CF 挑战
        block_ads=True,
        network_idle=True,
        timeout=45000,
        page_action=action,
    )
    if proxy:
        kwargs["proxy"] = proxy
    StealthyFetcher.fetch(base_url + "/login", **kwargs)
    return holder["token"]


# ---------- 第二级:StealthyFetcher 整页求解后重试 ----------

def _checkin_via_stealthy(site: dict, account: dict, cfg: dict,
                          client: SiteClient) -> str:
    """第二级:StealthyFetcher 整页求解(solve_cloudflare)后,页面上下文内 POST 签到。

    返回响应体文本(空串 = 失败)。页面内 fetch 自动带上浏览器会话 cookie
    (credentials:'include'),适合 cookie 型账号;token/UID 头按账号字段注入。
    """
    from scrapling.fetchers import StealthyFetcher

    base_url = client.base_url
    token = (account.get("token") or "").strip()
    uid = str(account.get("siteUserId") or "").strip()
    holder: dict[str, str] = {"result": ""}

    js = """
      (async () => {
        const r = await fetch('/api/user/checkin', {
          method: 'POST',
          headers: Object.assign({'Accept': 'application/json'},
            TOKEN ? {'Authorization': 'Bearer ' + TOKEN} : {},
            UID ? {'New-Api-User': UID} : {}),
          credentials: 'include',
        });
        window.__CHECKIN_RESULT__ = await r.text();
      })()
    """.replace("TOKEN", json.dumps(token)).replace("UID", json.dumps(uid))

    def action(page):
        page.evaluate(js)
        page.wait_for_timeout(8000)
        holder["result"] = page.evaluate("window.__CHECKIN_RESULT__ || ''") or ""

    cookies = _account_cookies((account.get("siteCookie") or "").strip())
    kwargs: dict[str, Any] = dict(
        headless=True,
        solve_cloudflare=True,
        network_idle=True,
        timeout=60000,
        page_action=action,
    )
    if cookies:
        kwargs["cookies"] = cookies
    proxy = _proxy_url(cfg)
    if proxy:
        kwargs["proxy"] = proxy
    StealthyFetcher.fetch(base_url + "/login", **kwargs)
    return holder["result"]


def _account_cookies(cookie_header: str) -> list[dict]:
    """'k1=v1; k2=v2' → Playwright cookies 列表(域名由目标站决定)。"""
    out = []
    for pair in cookie_header.split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out.append({"name": k.strip(), "value": v.strip(), "path": "/"})
    return out


# ---------- 主流程 ----------

def run_checkin(site: dict, account: dict, cfg: dict) -> CheckinReport:
    key = account.get("key", "?")
    sk = site.get("key", "?")
    client = SiteClient(site, account, cfg)
    report = CheckinReport(account_key=key, site_key=sk, state="failed")

    # login 型站点:无签到接口,刷新即取奖励(契约 §1.3)
    if site.get("checkinType") == "login":
        r = client.self_info()
        if r.status == 200 and not r.blocked_by_waf:
            report.state = "skipped"
            report.message = "登录即发额度站点,刷新即取奖励"
            report.quota = _quota(client)
            db.append_log(sk, key, "checkin", {"state": "skipped", "type": "login"})
            return report
        report.message = r.error or f"刷新失败(HTTP {r.status})"
        db.append_log(sk, key, "checkin", {"state": "failed", "http": r.status}, "err")
        return report

    # 前置判定 + POST(契约 §3.0)
    outcome = client.checkin_flow()
    if outcome.state == "need_captcha":
        sitekey = _turnstile_sitekey(client)
        proxy = _proxy_url(cfg)

        # 第一级:官方挂件 interaction-only
        token = ""
        if sitekey:
            try:
                token = _fetch_turnstile_token_headless(client.base_url, sk, sitekey, proxy)
            except Exception as e:
                db.append_log(sk, key, "captcha-l1", {"error": str(e)[:120]}, "err")
        if token:
            r1 = client.checkin_post(turnstile_token=token)
            if r1.status == 200 and not r1.blocked_by_waf:
                report.state, report.captcha_level = "done", 1
                report.message = "签到成功(Turnstile 挂件自动通过)"
                report.awarded = _awarded_from(r1, client)
                _finish(report, client, sk, key)
                return report
            db.append_log(sk, key, "captcha-l1",
                          {"http": r1.status, "waf": r1.blocked_by_waf}, "err")

        # 第二级:StealthyFetcher 整页求解
        try:
            raw = _checkin_via_stealthy(site, account, cfg, client)
            if raw:
                report.state, report.captcha_level = "done", 2
                report.message = "签到成功(StealthyFetcher 整页求解)"
                try:
                    d = json.loads(raw)
                    dd = d.get("data") if isinstance(d, dict) else None
                    if isinstance(dd, dict) and dd.get("quota_awarded") is not None:
                        report.awarded = round(float(dd["quota_awarded"]) / 500000, 2)
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass
                _finish(report, client, sk, key)
                return report
            db.append_log(sk, key, "captcha-l2", {"raw": (raw or "")[:120]}, "err")
        except Exception as e:
            db.append_log(sk, key, "captcha-l2", {"error": str(e)[:120]}, "err")

        # 两级均失败 ⇒ 报错,不转人工(§7)
        report.state = "failed"
        report.captcha_level = -1
        report.message = ("人机验证两级自动处理均失败(挂件 + 整页求解),"
                          "本轮放弃;可更换代理节点后重试或等下轮调度")
        db.append_log(sk, key, "checkin", {"state": "failed", "captcha": -1}, "err")
        return report

    if outcome.state == "done":
        report.state = "done"
        report.awarded = outcome.awarded
        report.message = outcome.message or "签到成功"
        _finish(report, client, sk, key)
        return report

    if outcome.state == "already":
        report.state = "already"
        report.awarded = outcome.awarded
        report.message = outcome.message
        report.quota = _quota(client)
        db.append_log(sk, key, "checkin", {"state": "already", "awarded": outcome.awarded})
        return report

    # skipped / failed
    report.state = outcome.state
    report.message = outcome.message
    db.append_log(sk, key, "checkin", {"state": outcome.state}, 
                  "info" if outcome.state == "skipped" else "err")
    return report


# ---------- 辅助 ----------

def _finish(report: CheckinReport, client: SiteClient, sk: str, key: str) -> None:
    """签到成功后自动刷三额度(契约 §3.0:与手动刷新行为对齐)。"""
    report.quota = _quota(client)
    db.append_log(sk, key, "checkin", {
        "state": report.state, "awarded": report.awarded,
        "captchaLevel": report.captcha_level,
        "availableUSD": report.quota.get("availableUSD"),
    })


def _quota(client: SiteClient) -> dict:
    r = client.self_info()
    if r.status != 200 or r.blocked_by_waf or not isinstance(r.data, dict):
        return {}
    d = (r.data.get("data") or {})
    quota, used = float(d.get("quota") or 0), float(d.get("used_quota") or 0)
    today = d.get("today_used_quota")
    unit = 500000
    return {
        "availableUSD": round(quota / unit, 2),
        "usedUSD": round(used / unit, 2),
        "todayUsedUSD": round(float(today) / unit, 4) if today is not None else None,
    }


def _awarded_from(r: CallResult, client: SiteClient) -> float | None:
    try:
        d = (r.data or {}).get("data")
        if isinstance(d, dict) and d.get("quota_awarded") is not None:
            return round(float(d["quota_awarded"]) / 500000, 2)
    except Exception:
        pass
    return None


def _turnstile_sitekey(client: SiteClient) -> str:
    r = client.status()
    if r.status == 200 and isinstance(r.data, dict):
        return str(((r.data.get("data") or {}).get("turnstile_site_key")) or "")
    return ""


def _proxy_url(cfg: dict) -> str | None:
    p = cfg.get("proxy") or {}
    if not p.get("enabled"):
        return None
    return f"{p.get('type', 'socks5')}://{p.get('host', '127.0.0.1')}:{p.get('port', 10808)}"
