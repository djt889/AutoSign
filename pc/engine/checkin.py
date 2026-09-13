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
from urllib.parse import urlparse

from ..service import db
from ..service.secret_store import unseal_account
from .silent_auth import exchange
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
            "date": datetime.now().strftime("%Y-%m-%d"),
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
    _fetch_cf_safe(base_url + "/login", kwargs)
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

    cookies = _account_cookies((account.get("siteCookie") or "").strip(),
                               urlparse(client.base_url).hostname or "")
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
    _fetch_cf_safe(base_url + "/login", kwargs)
    return holder["result"]


def _fetch_cf_safe(url: str, kwargs: dict[str, Any]) -> Any:
    """StealthyFetcher.fetch + solve_cloudflare 降级(页面无挑战时 scrapling 抛错)。"""
    from scrapling.fetchers import StealthyFetcher
    try:
        return StealthyFetcher.fetch(url, **kwargs)
    except Exception as e:
        if "cloudflare" not in str(e).lower():
            raise
        kwargs.pop("solve_cloudflare", None)
        return StealthyFetcher.fetch(url, **kwargs)


def _account_cookies(cookie_header: str, site_host: str) -> list[dict]:
    """'k1=v1; k2=v2' → Playwright cookies 列表。

    B-3:Playwright 的 cookie 必须带 url 或 domain(否则报错),此处统一补
    domain=目标站 host;调用方传 urlparse(base_url).hostname。
    """
    out = []
    for pair in cookie_header.split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out.append({"name": k.strip(), "value": v.strip(), "path": "/",
                        "domain": site_host})
    return out


def _login_rewarded_today(client: SiteClient) -> bool:
    """login 型站点今日是否已「登录领取」:优先用今日系统奖励记录(上游 15f80fc 判据),
    回退到 /api/user/self 的 last_login_time。"""
    # ① 今日系统奖励记录:最可靠到账证据。接口可能返回 checked=false,但奖励日志已存在 ⇒ 已签
    if _today_bonus(client) is not None:
        return True
    # ② 回退:last_login_time 今日(站点无日志变体)
    r = client.self_info()
    if r.status != 200 or not isinstance(r.data, dict):
        return False
    d = r.data.get("data") or {}
    llt = d.get("last_login_time")
    try:
        ts = float(llt)
        today = datetime.now().strftime("%Y-%m-%d")
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d") == today
    except (TypeError, ValueError):
        return False


def _today_bonus(client: SiteClient) -> dict | None:
    """今日「每日签到」类奖励日志(上游 todayBonus 移植)。
    读 /api/log/self?type=4,取列表第一条「签到」类文案(排除注册/邀请/兑换),
    时间戳是今天 ⇒ 奖励已到账。返回该记录或 None。
    """
    r = client.sys_log(page=1, limit=30)
    if r.status != 200 or not isinstance(r.data, dict):
        return None
    d = (r.data.get("data") or {})
    items = d.get("items") or d.get("list") or d.get("data") or []
    if not isinstance(items, list):
        return None
    today = datetime.now().strftime("%Y-%m-%d")
    for o in items:
        if not isinstance(o, dict):
            continue
        text = str(o.get("content") or o.get("description") or "")
        if not _is_checkin_text(text):
            continue
        ts_raw = str(o.get("created_at") or o.get("time") or "")
        if not ts_raw:
            continue
        if _ts_is_today(ts_raw):
            return {"usd": _usd_in_text(text), "text": text, "time": ts_raw}
    return None


def _is_checkin_text(text: str) -> bool:
    """签到类文案(含繁体「簽到」);排除注册赠送/邀请赠送/兑换(与签到同为 type=4)。"""
    t = text.lower()
    if not ("签到" in text or "簽到" in text or "check-in" in t or "checkin" in t):
        return False
    return not ("注册" in text or "邀请" in text or "兑换" in text)


def _ts_is_today(ts_raw: str) -> bool:
    """给定时间字符串是否今天。兼容 unix 秒/毫秒与 ISO 串。"""
    today = datetime.now().strftime("%Y-%m-%d")
    try:
        ts = float(ts_raw)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d") == today
    except (TypeError, ValueError):
        try:
            return ts_raw[:10] == today
        except Exception:
            return False


def _usd_in_text(text: str) -> float | None:
    """从日志文案解析美元金额:「获得额度 ＄20.642880 额度」→ 20.64。

    B-15:金额必须紧邻货币符号(＄/$/￥),不再匹配裸数字——
    旧正则会把「第 3 天签到获得＄10」里的「3 天」误判成 3.0。
    """
    import re
    m = re.search(r"[\$￥＄]\s*(\d+(?:\.\d+)?)", text)
    if not m:
        return None
    try:
        return round(float(m.group(1)), 2)
    except ValueError:
        return None


# ---------- 主流程 ----------

def run_checkin(site: dict, account: dict, cfg: dict) -> CheckinReport:
    key = account.get("key", "?")
    sk = site.get("key", "?")
    client = SiteClient(site, account, cfg)
    report = CheckinReport(account_key=key, site_key=sk, state="failed")

    # login 型站点(AgentRouter 实测定案):无 checkin 接口(GET 403/POST 404)、
    # /api/user/self 无 checked_in 字段、日志无签到记录——**额度发放的唯一触发
    # 是「新登录」**。原版对此只能提示用户手动开网页;本版(契约 §7 无人工兜底)
    # 的做法:每日强制静默重放一次 OAuth(=「退出后重新登录」,拿全新 session,
    # 站点 last_login_time 更新并触发发放),再刷新额度。
    if site.get("checkinType") == "login":
        # 1) 先看今天是否已"登录领过":今日系统奖励记录到账 ⇒ 已签;
        #    回退判据 last_login_time 是今日 ⇒ 不重复重放
        bonus = _today_bonus(client)
        already = bonus is not None or _login_rewarded_today(client)
        if already:
            report.state = "already"
            if bonus is not None:
                report.awarded = bonus.get("usd")
                report.message = ("今日奖励已到账(登录即签 · 系统记录)" if bonus.get("usd")
                                  else "今日已签(登录即签 · 无奖励)")
            else:
                report.message = "今日已通过登录领取(站点 last_login_time 为今日)"
            report.quota = _quota(client)
            _persist_checkin(sk, key, report)
            db.append_log(sk, key, "checkin", {"state": "already", "type": "login",
                                                "bonusUSD": bonus.get("usd") if bonus else None})
            return report

        # 2) 强制静默重放 OAuth(等价退出重登;自动绕过 8s 复用,但受 90s 失败冷却)
        # B-4:透传凭据(有密码才能在 GitHub 登录墙自动填充),取不到留 None
        credential = None
        try:
            from .credentials import get_credential
            credential = get_credential(key) or None
        except Exception:
            credential = None
        r = exchange(site, account, cfg, credential=credential, force=True)
        if r.state != "ok":
            report.message = f"重新登录失败: {r.message}"
            db.append_log(sk, key, "checkin", {"state": "failed", "relogin": r.message[:100]}, "err")
            return report
        # 重放拿到新凭据,就地更新给 SiteClient 复用。
        # B-17:account 里原 token/siteCookie 可能还是 enc: 密文,直接
        # client.account = account 会把密文当 Bearer/Cookie 发出去——
        # unseal 幂等(明文原样返回),密文字段就地解密。
        if r.site_cookie or r.token:
            if r.site_cookie:
                account["siteCookie"] = r.site_cookie
            if r.token:
                account["token"] = r.token
            client.account = unseal_account(account)

        # 3) 刷新验证:优先今日奖励记录到账,回退 last_login_time;额度到位
        bonus = _today_bonus(client)
        rewarded = bonus is not None or _login_rewarded_today(client)
        # 重登本身已成功 ⇒ done;rewarded 只影响文案与日志(旧写成
        # "done" if rewarded else "done" 的 dead ternary,易误读为条件生效)
        report.state = "done"
        if bonus is not None:
            report.awarded = bonus.get("usd")
            report.message = ("重新登录完成,奖励已到账" if bonus.get("usd")
                              else "重新登录完成,今日已签(无奖励)")
        else:
            report.message = ("重新登录完成,额度发放已触发"
                              if rewarded else
                              "重新登录完成(last_login_time 未更新,额度可能未发放,等下轮验证)")
        report.quota = _quota(client)
        _persist_checkin(sk, key, report)
        db.append_log(sk, key, "checkin", {
            "state": "done", "type": "login-relogin",
            "rewarded": rewarded, "bonusUSD": bonus.get("usd") if bonus else None,
            "availableUSD": report.quota.get("availableUSD"),
        })
        return report

    # 前置判定 + POST(契约 §3.0)
    outcome = client.checkin_flow()
    # 401 ⇒ 静默换新一次再重试(B-4 闭环):凭据库有账密/TOTP 时全自动恢复,
    # 不再让"JWT 过期"直接变成当日签到失败(需人工点重新授权)
    if outcome.state == "failed" and "401" in (outcome.message or ""):
        try:
            from .credentials import get_credential
            cred = get_credential(key) or None
        except Exception:
            cred = None
        r = exchange(site, account, cfg, credential=cred)
        db.append_log(sk, key, "checkin", {"step": "reauth-on-401", "ok": r.state == "ok"})
        if r.state == "ok":
            if r.site_cookie:
                account["siteCookie"] = r.site_cookie
            if r.token:
                account["token"] = r.token
            client.account = unseal_account(account)
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
            d1 = r1.data if isinstance(r1.data, dict) else {}
            # B-2:HTTP 200 但 success=false 是站点业务失败,不判 done——
            # 落日志后继续走第二级(整页求解),不再误报"签到成功"
            if (r1.status == 200 and not r1.blocked_by_waf
                    and d1.get("success") is not False):
                report.state, report.captcha_level = "done", 1
                report.message = "签到成功(Turnstile 挂件自动通过)"
                report.awarded = _awarded_from(r1, client)
                _finish(report, client, sk, key)
                return report
            db.append_log(sk, key, "captcha-l1",
                          {"http": r1.status, "waf": r1.blocked_by_waf,
                           "success": d1.get("success"),
                           "msg": str(d1.get("message") or "")[:80]}, "err")

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
                        report.awarded = round(float(dd["quota_awarded"]) / _unit_of(client), 2)
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
        _persist_checkin(sk, key, report)
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
    """签到成功后自动刷三额度(契约 §3.0:与手动刷新行为对齐)。

    顺带把签到记录落盘到账号 lastCheckin{date,state,reward},供前端
    在刷新重渲染时保持"已签"状态(防重复点击签到)。
    """
    report.quota = _quota(client)
    _persist_checkin(sk, key, report)
    db.append_log(sk, key, "checkin", {
        "state": report.state, "awarded": report.awarded,
        "captchaLevel": report.captcha_level,
        "availableUSD": report.quota.get("availableUSD"),
    })


def _persist_checkin(site_key: str, account_key: str, report: CheckinReport) -> None:
    """签到记录落盘(幂等:只记录,前端按 date 判定今日状态)。

    走 config.update 原子事务:并发签到/刷新时不再互相覆盖丢账号。
    """
    from ..service import config as config_svc
    date = datetime.now().strftime("%Y-%m-%d")

    def _mut(cfg):
        found = config_svc.find_account(cfg, account_key)
        if not found:
            return
        _, a = found
        a["lastCheckin"] = {
            "date": date,
            "state": report.state,
            "reward": report.awarded,
        }

    config_svc.update(_mut)


def _quota(client: SiteClient) -> dict:
    r = client.self_info()
    if r.status != 200 or r.blocked_by_waf or not isinstance(r.data, dict):
        return {}
    d = (r.data.get("data") or {})
    quota, used = float(d.get("quota") or 0), float(d.get("used_quota") or 0)
    today = d.get("today_used_quota")
    unit = _unit_of(client)
    return {
        "availableUSD": round(quota / unit, 2),
        "usedUSD": round(used / unit, 2),
        "todayUsedUSD": round(float(today) / unit, 4) if today is not None else None,
    }


def _unit_of(client: SiteClient) -> float:
    """站点 quota_per_unit(与 /api/status 口径一致);取不到回退默认值。

    旧实现硬编码 500000,非默认单位的站点金额会与 /api/status 显示不一致。
    按 client 实例缓存,避免同一次签到里反复请求 /api/status。
    """
    from .site_client import QUOTA_PER_UNIT_DEFAULT
    cached = getattr(client, "_unit_cache", None)
    if cached:
        return cached
    unit = float(QUOTA_PER_UNIT_DEFAULT)
    try:
        r = client.status()
        if r.status == 200 and isinstance(r.data, dict):
            u = ((r.data.get("data") or {}).get("quota_per_unit"))
            if u:
                unit = float(u)
    except Exception:
        pass
    try:
        client._unit_cache = unit
    except Exception:
        pass
    return unit


def _awarded_from(r: CallResult, client: SiteClient) -> float | None:
    try:
        d = (r.data or {}).get("data")
        if isinstance(d, dict) and d.get("quota_awarded") is not None:
            return round(float(d["quota_awarded"]) / _unit_of(client), 2)
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
