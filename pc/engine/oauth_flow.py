"""oauth_flow.py — GitHub OAuth 授权流程(P2,契约 §3.0/§5.2)。

方式 A(默认):全程 headless StealthyFetcher,零弹窗:
  1. FetcherSession 纯 HTTP 拿 flow_token(state) + client_id
  2. headless 浏览器开 authorize URL(带 login=<期望账号> 防串号)
  3. 已有 GitHub 会话(user_data_dir 持久化)⇒ 直接 302 回调;
     无会话 ⇒ page_action 自动填充账密/2FA(AuthFill 契约 §3.0)
  4. 回调拦截(同域+code+state 严格匹配,OAuthCallback 规则)
  5. 服务端直调 /api/oauth/{provider}?code&state 交换,抓 Set-Cookie
  6. B1 身份校验(github_id 锚点分层)后落盘

浏览器导航到 GitHub 登录/2FA/设备验证页且自动填充失败 ⇒ need_manual
(授权的人工兜底保留,与签到不同,契约 §7)。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlparse, parse_qs

from ..service import config as config_svc
from ..service import db
from .site_client import CallResult, SiteClient

# GitHub 会话过期 ⇒ 需要人工(SilentAuth 契约:转人工 URL 清单)
NEED_MANUAL_URL_RE = re.compile(
    r"github\.com/(login|session|sessions)|/two-factor|verified-device|/sudo",
    re.IGNORECASE,
)

FALLBACK_CLIENT_ID = "Ov23liBGecTYSePKpXQC"   # 原版兜底值(JustDoWork 实测一致)


@dataclass
class AuthResult:
    state: str                          # ok / need_manual / failed
    message: str = ""
    token: str = ""
    site_cookie: str = ""
    site_user_id: str = ""
    github_login: str = ""
    github_id: str = ""
    manual_url: str = ""                # need_manual 时给用户的手动授权 URL


def profile_dir(site_key: str, account_key: str) -> str:
    """站点×账号独立 user_data_dir(等价原版 WebView Profile 分区)。"""
    from ..service.config import ROOT
    d = ROOT / "data" / "profiles" / site_key / account_key
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


# ---------- 第 1 步:flow_token + client_id(纯 HTTP) ----------

def fetch_state(client: SiteClient) -> tuple[str, str]:
    """POST /api/oauth/state;404 ⇒ GET ?mode=login(AgentRouter 型),形态记站点 meta。

    返回 (flow_token, err);err 非空表示失败。
    """
    body = {"provider": "github", "intent": "login"}
    r = client.call("post", "/api/oauth/state", body)
    if r.status == 404:
        r = client.call("get", "/api/oauth/state?mode=login")
        if r.status == 200:
            _remember_state_method(client, "get")
    elif r.status == 200:
        _remember_state_method(client, "post")

    if r.status == 429:
        return "", f"站点限流(429):{r.error}"
    if r.status != 200 or not isinstance(r.data, dict):
        if r.blocked_by_waf:
            return "", "站点防护拦截(WAF 假 200),建议更换代理节点"
        return "", f"state 获取失败(HTTP {r.status})"
    if not r.data.get("success"):
        return "", f"state 获取失败: {r.data.get('message', '')}"

    d = r.data.get("data")
    token = d if isinstance(d, str) else (
        (d or {}).get("flow_token") if isinstance(d, dict) else None
    )
    if not token:
        return "", "响应无 flow_token"
    return token, ""


def _remember_state_method(client: SiteClient, method: str) -> None:
    try:
        cfg = config_svc.load()
        config_svc.put_site_meta(cfg, client.site.get("key", ""), "stateMethod", method)
        config_svc.save(cfg)
    except Exception:
        pass


def fetch_client_id(client: SiteClient) -> str:
    r = client.status()
    if r.status == 200 and isinstance(r.data, dict):
        cid = ((r.data.get("data") or {}).get("github_client_id")) or ""
        if cid:
            return cid
    return FALLBACK_CLIENT_ID


# ---------- 回调判定(OAuthCallback 契约) ----------

@dataclass
class CallbackCheck:
    should_exchange: bool = False
    bad_state: bool = False
    missing_code: bool = False
    code: str = ""
    state: str = ""
    safe: str = ""      # 日志用:只含 host/path/参数名,不含值


def check_callback(raw_url: str, site_host: str, expected_state: str) -> CallbackCheck:
    c = CallbackCheck()
    try:
        u = urlparse(raw_url)
    except ValueError:
        return c
    host = (u.hostname or "").lower()
    c.safe = f"{host}{u.path}"
    same_host = bool(site_host) and host == site_host.lower()
    q = parse_qs(u.query)
    c.code = (q.get("code") or [""])[0]
    c.state = (q.get("state") or [""])[0]
    has_code, has_state = bool(c.code), bool(c.state)

    if same_host and has_code and has_state and c.state == expected_state:
        c.should_exchange = True
    elif same_host and not has_code:
        c.missing_code = True
    elif same_host and has_code and not (has_state and c.state == expected_state):
        c.bad_state = True
    return c


# ---------- 交换 + Set-Cookie 抓取(契约 §3.0 凭据规则,全站通用) ----------

def parse_set_cookies(set_cookie_values: list[str]) -> str:
    """['session=abc; Path=/; Max-Age=0', ...] → 'session2=v2'(跳过删除态/空值)。"""
    parts: list[str] = []
    for sc in set_cookie_values or []:
        pair = sc.split(";", 1)[0].strip()
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        k, v = k.strip(), v.strip()
        if not v or v.lower() == "deleted":
            continue
        # 删除态标记:Max-Age=0
        if re.search(r"max-age\s*=\s*0", sc, re.IGNORECASE):
            continue
        parts.append(f"{k}={v}")
    return "; ".join(parts)


def extract_credentials(body: dict) -> dict:
    """从交换响应 data 提取凭据(三字段 token 兼容 + 两层身份字段,B1 用)。"""
    d = body.get("data") or {}
    if not isinstance(d, dict):
        return {}
    token = ""
    for k in ("access_token", "accessToken", "token"):
        v = d.get(k)
        if isinstance(v, str) and v.strip() and v.strip().lower() != "null":
            token = v.strip()
            break
    login = ""
    user = d.get("user") if isinstance(d.get("user"), dict) else {}
    for src in (d, user):
        v = str(src.get("username") or "")
        if v and v.lower() != "null":
            login = v
            break
        v2 = str(src.get("login") or "")
        if v2 and v2.lower() != "null":
            login = v2
            break
    gid = ""
    for k in ("github_id", "github_user_id"):
        v = d.get(k)
        if v is not None and str(v).strip().lower() not in ("", "null"):
            gid = str(v).strip()
            break
    uid = str(d.get("id") or "").strip()
    return {
        "token": token, "github_login": login,
        "github_id": gid, "site_user_id": uid if uid.lower() != "null" else "",
    }


def b1_identity_check(creds: dict, account: dict) -> tuple[bool, str]:
    """B1 身份校验(锚点分层):强判据 github_id;弱判据 username;都无跳过。"""
    cached_gid = str(account.get("githubId") or "").strip()
    cached_login = str(account.get("githubAccount") or "").strip()
    resp_gid = creds.get("github_id", "")
    resp_login = creds.get("github_login", "")
    if resp_gid and cached_gid:
        if resp_gid != cached_gid:
            return False, f"github_id 不匹配(响应 {resp_gid[:4]}*** ≠ 缓存 {cached_gid[:4]}***)"
        return True, ""
    if resp_gid and not cached_gid:
        return True, ""       # 响应有锚点但无缓存,放行并落库
    if not resp_gid and cached_login and resp_login:
        if resp_login.lower() != cached_login.lower():
            return False, f"username 不匹配(响应 {resp_login} ≠ 缓存 {cached_login})"
        return True, ""
    return True, ""           # 都拿不到 ⇒ 跳过,不误拒


# ---------- 主流程(方式 A:headless 全自动) ----------

def authorize(site: dict, account: dict, cfg: dict,
              credential: dict | None = None, headful: bool = False) -> AuthResult:
    """OAuth 全流程。headful=False(默认,方式 A)headless 全自动;
    headful=True(方式 B 兜底)弹可见浏览器,用户现场登录一次,
    GitHub 会话存 user_data_dir,之后恢复全自动。
    """
    from scrapling.fetchers import StealthyFetcher

    sk, ak = site.get("key", "?"), account.get("key", "?")
    client = SiteClient(site, account, cfg)
    base = client.base_url
    site_host = urlparse(base).hostname or ""

    # 1. flow_token + client_id
    flow_token, err = fetch_state(client)
    if err:
        db.append_log(sk, ak, "oauth", {"step": "state", "error": err}, "err")
        return AuthResult("failed", f"获取授权会话失败: {err}")
    client_id = fetch_client_id(client)
    want_login = str(account.get("githubAccount") or "").strip()
    auth_url = ("https://github.com/login/oauth/authorize"
                f"?client_id={quote(client_id)}&state={quote(flow_token)}"
                f"&scope=user:email"
                + (f"&login={quote(want_login)}" if want_login else ""))
    db.append_log(sk, ak, "oauth", {"step": "authorize", "cid": client_id[:8] + "***",
                                    "loginParam": bool(want_login), "state": flow_token[:6] + "***"})

    # 2. headless 浏览器走授权(user_data_dir 持久化 GitHub 会话)
    holder: dict[str, Any] = {"final_url": "", "github_ok": False, "chain": []}
    prj = profile_dir(sk, ak)

    def action(page):
        # 导航链记录(等价原版 WebView onPageStarted:每一次跳转的 URL 都留痕,
        # 包括 OAuth 中间跳转——SPA 前端会消费 code 后跳 dashboard,终态轮询会漏)
        def on_nav(frame):
            try:
                if frame == page.main_frame:
                    holder["chain"].append(frame.url)
                    holder["final_url"] = frame.url
            except Exception:
                pass
        page.on("framenavigated", on_nav)

        # 等待最终落点:回调页(站点域)。
        # GitHub 登录墙出现时:有凭据 ⇒ 立即自动填充(登录/2FA)后继续等;
        # 无凭据或填充后仍过不去 ⇒ headless 判 need_manual,有头(方式 B)由用户现场操作。
        max_wait = 560 if headful else 90
        filled = {"login": False, "otp": False}
        for _ in range(max_wait):
            url = page.url
            host = urlparse(url).hostname or ""
            if host == site_host:
                # 站点域:URL 链里可能有带 code 的中间跳转,优先用链判定
                holder["github_ok"] = True
                return
            on_wall = bool(NEED_MANUAL_URL_RE.search(url))
            if on_wall and credential and not headful:
                # headless:2FA 页必须先判(/sessions/two-factor 含 "/session",
                # 若登录分支在前,2FA 页会被吞掉导致永远填不进码);
                # 登录页填账密(一次);2FA 页轮询填码(密钥码/手动码)
                if "two-factor" in url:
                    _fill_totp(page, credential)
                elif "login" in url or "/session" in url:
                    if not filled["login"] and _fill_login(page, credential):
                        filled["login"] = True
                page.wait_for_timeout(2000)
                continue
            if on_wall and headful and "two-factor" in url and globals()["_manual_code"]:
                # 有头模式:用户手机上的码通过 API 发来,直接注入(30s 窗口)
                _fill_totp(page, credential or {})
                globals()["_manual_code"] = ""
                page.wait_for_timeout(2000)
                continue
            if on_wall and not headful:
                # 无凭据(或未提供)⇒ 转人工
                holder["github_ok"] = False
                return
            page.wait_for_timeout(1000)
        holder["github_ok"] = False   # 超时

    kwargs: dict[str, Any] = dict(
        headless=not headful, solve_cloudflare=True, network_idle=True,
        timeout=600000 if headful else 180000,   # 有头模式给 10 分钟现场操作
        user_data_dir=prj, page_action=action,
        block_ads=True,
        # 捕获前端自发交换请求的响应(文档 §5.2 首选手段,URL 链判定之外的保险)
        capture_xhr=r"/api/oauth/",
    )
    proxy = _proxy_url(cfg)
    if proxy:
        kwargs["proxy"] = proxy
    resp = StealthyFetcher.fetch(auth_url, **kwargs)

    # 3b. capture_xhr 保险:回调页前端自己 GET /api/oauth/{provider}?code&state,
    #     响应里就有凭据——URL 链漏抓时直接从这里拿
    for xhr in (getattr(resp, "captured_xhr", None) or []):
        try:
            if "/api/oauth/" in (xhr.url or ""):
                body = json.loads(xhr.body.decode("utf-8") if isinstance(xhr.body, bytes) else str(xhr.body))
                if isinstance(body, dict) and body.get("success"):
                    creds = extract_credentials(body)
                    db.append_log(sk, ak, "oauth", {"step": "exchange-xhr",
                                                    "via": "capture_xhr"})
                    if creds.get("token") or creds.get("github_login"):
                        return _finish_auth(sk, ak, site, account, creds, cfg,
                                            xhr_headers=xhr.headers)
        except Exception:
            continue

    final_url = holder["final_url"]
    # 3. 回调判定:遍历导航链找带 code 的回调 URL
    #    (SPA 前端会消费 code 后跳 dashboard,终态 URL 不带 code——
    #     这是原版 onPageStarted 拦中间跳转的等价实现)
    cb = CallbackCheck()
    for u in holder["chain"] or [final_url]:
        c = check_callback(u, site_host, flow_token)
        if c.should_exchange:
            cb = c
            break
        if c.bad_state:
            cb = c
            break
        if c.missing_code:
            cb = c          # 记下来但继续找后面的带 code 跳转
    if not cb.should_exchange and not cb.bad_state and not cb.missing_code:
        cb = check_callback(final_url, site_host, flow_token)
    if cb.bad_state:
        db.append_log(sk, ak, "oauth", {"step": "callback", "verdict": "bad-state",
                                        "url": cb.safe}, "err")
        return AuthResult("failed", "授权回调 state 校验失败(防串流),请重试", manual_url=auth_url)
    if cb.missing_code:
        db.append_log(sk, ak, "oauth", {"step": "callback", "verdict": "missing-code",
                                        "url": cb.safe}, "err")
        return AuthResult("failed", "未获取到授权码(可能授权被拒绝)", manual_url=auth_url)
    if not cb.should_exchange:
        if NEED_MANUAL_URL_RE.search(final_url):
            db.append_log(sk, ak, "oauth", {"step": "github-wall", "url": final_url[:80]}, "err")
            return AuthResult("need_manual",
                              "GitHub 会话过期且无法自动填充,需手动授权一次(之后恢复全自动)",
                              manual_url=auth_url)
        db.append_log(sk, ak, "oauth", {"step": "callback", "verdict": "timeout",
                                        "url": final_url[:80]}, "err")
        return AuthResult("failed", f"授权超时(最终落点 {urlparse(final_url).hostname})", manual_url=auth_url)

    # 4. 交换(服务端直调,主交换响应直接抓 Set-Cookie;code 一次性,不重放)
    ex = client.call("get", f"/api/oauth/github?code={quote(cb.code)}&state={quote(cb.state)}")
    if ex.status != 200 or not isinstance(ex.data, dict) or not ex.data.get("success"):
        msg = ex.error or f"交换失败(HTTP {ex.status})"
        db.append_log(sk, ak, "oauth", {"step": "exchange", "http": ex.status}, "err")
        return AuthResult("failed", msg)

    return _finish_auth(sk, ak, site, account, extract_credentials(ex.data), cfg,
                        set_cookies=ex.set_cookies)


def _finish_auth(sk: str, ak: str, site: dict, account: dict, creds: dict,
                 cfg: dict, set_cookies: list[str] | None = None,
                 xhr_headers: Any = None) -> AuthResult:
    """凭据落库收尾(主交换路径与 capture_xhr 保险路径共用):B1 校验 + Set-Cookie。"""
    ok, why = b1_identity_check(creds, account)
    if not ok:
        db.append_log(sk, ak, "oauth", {"step": "b1", "error": why}, "err")
        return AuthResult("failed", f"身份校验失败:{why}")

    site_cookie = ""
    if set_cookies:
        site_cookie = parse_set_cookies(set_cookies)
    elif xhr_headers is not None:
        # XHR 保险路径:从捕获的响应头里抓 Set-Cookie
        vals: list[str] = []
        try:
            get_list = getattr(xhr_headers, "get_list", None)
            if callable(get_list):
                vals = list(get_list("set-cookie") or [])
            else:
                single = xhr_headers.get("set-cookie")
                vals = [single] if isinstance(single, str) else list(single or [])
        except Exception:
            pass
        site_cookie = parse_set_cookies(vals)

    db.append_log(sk, ak, "oauth", {"step": "done", "hasToken": bool(creds["token"]),
                                    "hasCookie": bool(site_cookie),
                                    "login": creds["github_login"]})
    return AuthResult(
        "ok", "授权成功",
        token=creds["token"], site_cookie=site_cookie,
        site_user_id=creds["site_user_id"],
        github_login=creds["github_login"], github_id=creds["github_id"],
    )


# ---------- AuthFill(契约 §3.0 选择器,逐一平移 AuthFillJs) ----------

def _fill_login(page, credential: dict) -> bool:
    """GitHub 登录页:填账密并提交。人机验证挂件存在 ⇒ 只填不点(契约)。

    返回是否成功提交(没提交=需要人工过验证或凭据缺失)。
    """
    acct = credential.get("username", "")
    pwd = credential.get("password", "")
    if not acct or not pwd:
        return False
    try:
        login_f = page.locator("#login_field")
        if not login_f.count():
            return False
        if not login_f.first.input_value():
            login_f.first.fill(acct)
        page.locator("#password").first.fill(pwd)
        # 人机验证挂件存在 ⇒ 只填不点(契约 §3.0)
        if page.locator(".cf-turnstile, #cf-turnstile, [data-sitekey]").count():
            return False
        page.locator("input[name=commit], button[type=submit]").first.click()
        return True
    except Exception:
        return False


def _fill_totp(page, credential: dict) -> bool:
    """2FA 页:默认非 TOTP 时先切「Use authenticator app」,再填 6 位码。

    TOTP 码满 6 位自动提交;无 TOTP 密钥 ⇒ False(交人工)。
    """
    code = globals().get("_manual_code", "") or _totp_code(credential)
    if not code:
        return False
    try:
        link = page.locator(
            "a:has-text('authenticator'), button:has-text('authenticator')")
        if link.count():
            link.first.click()
            page.wait_for_timeout(1500)
        otp = page.locator(
            "#app_totp, #otp, input[autocomplete='one-time-code']").first
        otp.fill(code)                       # 满 6 位 GitHub 自动提交
        return True
    except Exception:
        return False


# 用户实时提供的 6 位码(有头模式:手机 App 上看到的码发来即填,30s 有效)
_manual_code: str = ""


def set_manual_code(code: str) -> None:
    global _manual_code
    _manual_code = str(code).strip()[:6]


def _totp_code(credential: dict) -> str:
    secret = credential.get("totpSecret", "")
    if not secret:
        return ""
    try:
        import pyotp
        return pyotp.TOTP(secret).now()
    except Exception:
        return ""


def _proxy_url(cfg: dict) -> str | None:
    p = cfg.get("proxy") or {}
    if not p.get("enabled"):
        return None
    return f"{p.get('type', 'socks5')}://{p.get('host', '127.0.0.1')}:{p.get('port', 10808)}"
