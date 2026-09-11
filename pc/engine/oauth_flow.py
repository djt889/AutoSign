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
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlparse, parse_qs

from ..service import config as config_svc
from ..service import db
from .site_client import CallResult, SiteClient

# GitHub 会话过期 ⇒ 需要人工(SilentAuth 契约:转人工 URL 清单)。
# verified-device/device = GitHub 新设备验证(含邮箱验证码 - 设备验证邮件里的
# 6 位数字码同样走本页输入,与 TOTP 无关,见 _fill_totp 的 email-code 分支)
NEED_MANUAL_URL_RE = re.compile(
    r"github\.com/(login|session|sessions)|/two-factor|verified-device|/device|/sudo",
    re.IGNORECASE,
)

FALLBACK_CLIENT_ID = "Ov23liBGecTYSePKpXQC"   # 原版兜底值(JustDoWork 实测一致)


@dataclass
class AuthResult:
    state: str                          # ok / need_code / need_manual / failed
    message: str = ""
    token: str = ""
    site_cookie: str = ""
    site_user_id: str = ""
    github_login: str = ""
    github_id: str = ""
    manual_url: str = ""                # need_manual/等码超时给用户的手动授权 URL
    hint: str = ""                      # 需人工介入时的提示(区分 TOTP/邮箱设备验证码)
    code_task: str = ""                 # 本授权对应的 task_id(手动码注入桶)


def _cookie_names(cookie_header: str) -> list[str]:
    """只取 cookie 名(不取值),供日志记录——避免凭据明文落日志/回显到 UI。"""
    return [p.split("=", 1)[0].strip() for p in (cookie_header or "").split(";") if "=" in p]


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


def b1_identity_check(creds: dict, account: dict, trusted: bool = False) -> tuple[bool, str]:
    """B1 身份校验(锚点分层):强判据 github_id;弱判据 username;都无跳过。

    trusted=True 表示本次是「用本账号凭据现场登录」取得的会话——此时身份可信,
    站点返回的用户名是站点自动生成的命名空间(如 AgentRouter 的 github_494101),
    与用户填的 GitHub 登录名(DeanCastiel)本就不同,不应据此拒绝,否则正常账号
    会被误拦。仅当非可信(残余会话/浏览器 cookie 路径)时才强制比对,防串流。
    """
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
            # 用凭据现场登录成功 ⇒ 身份可信;站点用户名多为自动生成命名空间
            if trusted:
                return True, ""
            return False, f"username 不匹配(响应 {resp_login} ≠ 缓存 {cached_login})"
        return True, ""
    return True, ""           # 都拿不到 ⇒ 跳过,不误拒


# ---------- 主流程(方式 A:headless 全自动) ----------

def authorize(site: dict, account: dict, cfg: dict,
              credential: dict | None = None, headful: bool = False,
              task_id: str = "", on_state=None) -> AuthResult:
    """OAuth 全流程。headful=False(默认,方式 A)headless 全自动;
    headful=True(方式 B 兜底)弹可见浏览器,用户现场登录一次,
    GitHub 会话存 user_data_dir,之后恢复全自动。

    task_id:  本次授权的任务标识,用于手动码(task_id)隔离与结果回带。
    on_state: 需要用户介入时调用(可多次,同一状态只报一次);流程继续等待注入码,
              不返回;超时后才返回。dict 形如 {"state":"waiting_code","hint":...}
              或 {"state":"waiting_manual","manualUrl":...}。
    """
    from scrapling.fetchers import StealthyFetcher

    sk, ak = site.get("key", "?"), account.get("key", "?")
    # state/client_id 是公开接口:用匿名 client(不带旧凭据头)——
    # 实测 JustDoWork 对带失效 Bearer 的 state 请求回 401
    anon_client = SiteClient(site, {}, cfg)
    client = SiteClient(site, account, cfg)
    base = client.base_url
    site_host = urlparse(base).hostname or ""

    # 1. flow_token + client_id
    flow_token, err = fetch_state(anon_client)
    if err:
        db.append_log(sk, ak, "oauth", {"step": "state", "error": err}, "err")
        return AuthResult("failed", f"获取授权会话失败: {err}")
    client_id = fetch_client_id(anon_client)
    want_login = str(account.get("githubAccount") or "").strip()
    # 有账密 ⇒ 本次是"用本账号凭据现场登录",身份可信(站点返回的用户名是
    # 站点自动生成的命名空间,与 GitHub 登录名不同,不应据此拒绝)
    cred_trusted = bool(credential and credential.get("password"))
    auth_url = ("https://github.com/login/oauth/authorize"
                f"?client_id={quote(client_id)}&state={quote(flow_token)}"
                f"&scope=user:email"
                + (f"&login={quote(want_login)}" if want_login else ""))
    db.append_log(sk, ak, "oauth", {"step": "authorize", "cid": client_id[:8] + "***",
                                    "loginParam": bool(want_login), "state": flow_token[:6] + "***"})

    # 2. headless 浏览器走授权(user_data_dir 持久化 GitHub 会话)
    holder: dict[str, Any] = {"final_url": "", "github_ok": False, "chain": [],
                              "site_cookies": "",
                              "waiting": set()}   # 已通知过的状态(waiting_code/...)
    prj = profile_dir(sk, ak)

    def action(page):
        # on_state 同一状态只报一次(契约 §2):用 holder["waiting"] 跨循环去重
        def _notify(st: dict) -> None:
            key = st.get("state", "")
            if key in holder["waiting"]:
                return
            holder["waiting"].add(key)
            try:
                if on_state is not None:
                    on_state(st)
            except Exception:
                pass

        def _waiting_code_hint(url: str) -> str:
            if "verified-device" in url or "/device" in url:
                return ("GitHub 正在向你的登录邮箱发送设备验证码:请查收邮箱(或手机上的"
                        "GitHub App),把 6 位数字码填入下方输入框;该码在浏览器里自动提交。"
                        "若邮箱收不到,可改用右上角手动授权。")
            return ("需要 GitHub 两步验证(2FA):请在下方输入框填入当前有效的 6 位验证码"
                    "(已配置 TOTP 自动码时无需手动填)。若未配置 TOTP 密钥,请输入手机"
                    "认证器上的 6 位动态码。")

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
        # 请求级监听(比 framenavigated 更底层):整页 302、XHR、fetch 全捕。
        # 实测 AgentRouter 回调是整页跳转,framenavigated 抓不到中间 URL,
        # 但每个导航前的 request 会带完整 ?code= 查询串。
        def on_request(req):
            try:
                u = req.url
                if "code=" in u and ("oauth" in u or site_host in u):
                    holder["chain"].append(u)
            except Exception:
                pass
        page.on("request", on_request)

        # 跨账号残留会话预清:profile 里若登录着**别的** GitHub 账号,GitHub 会
        # 无视 login= 参数直接用旧会话授权(实测:目标 DeanCastiel 却落到
        # github_494101)。判据用凭据里的 GitHub 登录名(credential.username,
        # 与 dotcom_user 同命名空间),不能用 account.githubAccount(那是站点
        # 自动生成的用户名,如 github_473221,命名空间不同会误清)。
        if credential and credential.get("username"):
            try:
                gck = page.context.cookies("https://github.com")
                dotcom = next((c.get("value") or "" for c in gck
                               if c.get("name") == "dotcom_user"), "")
            except Exception:
                dotcom = ""
            if dotcom and dotcom.lower() != str(credential["username"]).lower():
                db.append_log(sk, ak, "oauth", {"step": "session-switch",
                                                "from": dotcom,
                                                "to": credential["username"]})
                try:
                    page.context.clear_cookies()
                    page.goto(auth_url, wait_until="domcontentloaded")
                    page.wait_for_timeout(1500)
                except Exception:
                    pass

        # 等待最终落点:回调页(站点域)。
        # GitHub 登录墙出现时:有凭据 ⇒ 立即自动填充(登录/2FA)后继续等;
        # 无凭据或填充后仍过不去 ⇒ headless 判 need_manual,有头(方式 B)由用户现场操作。
        max_wait = 560 if headful else 90
        filled = {"login": False, "otp": False}
        for _ in range(max_wait):
            url = page.url
            host = urlparse(url).hostname or ""
            # GitHub 授权确认页(带 login= 参数或首次授权时出现):自动点 Authorize
            if host == "github.com" and "/oauth/authorize" in url:
                try:
                    # 只点明确的授权按钮(防误点 Cancel/拒绝被 GitHub 记忆成 deny)
                    btn = page.locator("#oauth-authorize-authorization-code")
                    if not btn.count():
                        btn = page.locator("button.js-oauth-authorize-btn")
                    if btn.count() and btn.first.is_visible():
                        btn.first.click()
                        page.wait_for_timeout(2000)
                        continue
                except Exception:
                    pass
            if host == site_host:
                # 站点域:URL 链里可能有带 code 的中间跳转,优先用链判定;
                # 同时导出浏览器站点 cookie(httpOnly session 完整版——
                # 服务端 FetcherSession 抓 Set-Cookie 会漏,实测 AgentRouter 只抓到
                # WAF 的 acw_tc,真凭据 session 只存在于浏览器上下文)
                # 站点 SPA 落地后仍要 fire 一次 /api/oauth/... 前端交换才拿到
                # session cookie;若立刻返回会只抓到 WAF 的 acw_tc(假成功 401)。
                # 因此落地后轮询等"非 WAF 的 session cookie"出现,最多 ~12s。
                def _export():
                    try:
                        all_cookies = page.context.cookies()
                        ar = [c for c in all_cookies if site_host in (c.get("domain") or "")]
                        holder["site_cookies"] = "; ".join(
                            f"{c['name']}={c['value']}" for c in ar)
                        return ar
                    except Exception:
                        return []

                ar = _export()
                for _ in range(12):
                    if any((c.get("name") or "").lower() not in
                           ("acw_tc", "acw_sc__v2", "cdn_sec_tc") for c in ar):
                        break                      # 真 session 已出现
                    page.wait_for_timeout(1000)
                    ar = _export()
                holder["github_ok"] = True
                return
            on_wall = bool(NEED_MANUAL_URL_RE.search(url))
            if on_wall and credential and not headful:
                # headless:2FA 页必须先判(/sessions/two-factor 含 "/session",
                # 若登录分支在前,2FA 页会被吞掉导致永远填不进码);
                # 登录页填账密(一次);2FA/设备验证页轮询填码(密钥码/手动码/邮箱码)
                if "two-factor" in url or "verified-device" in url or "/device" in url:
                    if not filled["otp"]:
                        # ⑦ 同一页/同一码只提交一次:填过就置位跳过(防每 2s 重复 fill)
                        code = _take_manual_code(task_id)   # 取一次即消费,不重复取
                        auto = "" if ("verified-device" in url or "/device" in url) \
                            else _totp_code(credential)
                        if not code and not auto:
                            # ⑥ 无自动码(TOTP 密钥)也无已注入码 ⇒ 通知前端等待用户填码,
                            #    继续循环等注入(不静默空转)
                            _notify({"state": "waiting_code",
                                     "hint": _waiting_code_hint(url)})
                        elif _fill_totp(page, credential, code=code):
                            filled["otp"] = True
                elif "login" in url or "/session" in url:
                    if not filled["login"] and _fill_login(page, credential):
                        filled["login"] = True
                page.wait_for_timeout(2000)
                continue
            if on_wall and headful and ("two-factor" in url or "verified-device" in url
                                        or "/device" in url):
                # 有头模式:用户手机/邮箱上的码通过 API 发来(task_id 隔离),直接注入
                # ⑧ 按本任务 task_id 取码(不再用全局 _manual_code)
                code = _take_manual_code(task_id)
                if not filled["otp"] and code:
                    if _fill_totp(page, credential or {}, code=code):
                        filled["otp"] = True
                    page.wait_for_timeout(2000)
                    continue
            if on_wall and not headful:
                # 无凭据(或未提供)⇒ 转人工
                holder["github_ok"] = False
                return
            page.wait_for_timeout(1000)
        holder["github_ok"] = False   # 超时

    kwargs: dict[str, Any] = dict(
        solve_cloudflare=True,
        # 不用 network_idle:AgentRouter console 页持续轮询,idle 永不满足,
        # page_action 会被卡到 timeout(实测);等待逻辑由 action 内循环承担
        timeout=600000 if headful else 180000,   # 有头模式给 10 分钟现场操作
        user_data_dir=prj, page_action=action,
        block_ads=True,
        # 捕获前端自发交换请求的响应(文档 §5.2 首选手段,URL 链判定之外的保险)
        capture_xhr=r"/api/oauth/",
    )
    if headful:
        # 有头模式:CDP 接管用户真实 Chrome(真窗口可见)。
        # 原因:scrapling 0.4.11 底层 patchright 的 headless=False 不弹真实窗口,
        # 必须连用户 Chrome 的远程调试端口才能让人看到并操作。
        ok, msg = ensure_manual_chrome()
        db.append_log(sk, ak, "oauth", {"step": "manual-chrome", "ok": ok, "msg": msg[:80]})
        if not ok:
            return AuthResult("failed", msg)
        kwargs["cdp_url"] = manual_cdp_url()
        kwargs.pop("user_data_dir", None)  # CDP 接管时 profile 由 Chrome 进程侧管理
    else:
        kwargs["headless"] = True
    proxy = _proxy_url(cfg)
    if proxy:
        kwargs["proxy"] = proxy
    try:
        resp = StealthyFetcher.fetch(auth_url, **kwargs)
    except Exception as e:
        # scrapling 实测:页面无 CF 挑战时 solve_cloudflare 抛
        # 'No Cloudflare challenge found' —— 降级重试(去掉求解参数)
        if "cloudflare" not in str(e).lower():
            raise
        kwargs.pop("solve_cloudflare", None)
        db.append_log(sk, ak, "oauth", {"step": "fetch-retry-no-cf"}, "err")
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
                                            xhr_headers=xhr.headers,
                                            browser_cookies=holder["site_cookies"],
                                            trusted=cred_trusted,
                                            task_id=task_id)
        except Exception:
            continue

    final_url = holder["final_url"]
    # 3. 落库判定(v1.4 实战定案,优先级):
    #    a) 已落站点域 + 浏览器有站点 session cookie ⇒ 前端已完成交换,
    #       浏览器 cookie 就是生效凭据,直接落库(code/交换响应都不需要——
    #       code 一次性,前端消费后服务端再换必失败,实测 AgentRouter)
    #    b) 导航链上有带 code 的回调 ⇒ 服务端直调交换(纯 token 型站)
    #    c) capture_xhr 捕获前端交换响应(备用)
    landed = urlparse(final_url).hostname == site_host or any(
        urlparse(u).hostname == site_host for u in (holder["chain"] or []))
    if landed and holder["site_cookies"]:
        creds = {"token": "", "github_login": want_login,
                 "github_id": "", "site_user_id": ""}
        probe_ok = False
        try:
            probe = SiteClient(site, {**account, "siteCookie": holder["site_cookies"]}, cfg)
            sr = probe.call("get", "/api/user/self")
            if sr.status == 200 and isinstance(sr.data, dict):
                d = sr.data.get("data") or {}
                creds.update({
                    "github_login": d.get("username") or want_login,
                    "github_id": str(d.get("github_user_id") or d.get("github_id") or ""),
                    "site_user_id": str(d.get("id") or ""),
                })
                probe_ok = True
        except Exception:
            pass
        # 关键:必须探测通过才认成功。浏览器上下文里常只有 WAF 的 acw_tc
        # (非 session),若无脑按"有 cookie"落库会假成功(401 账号显示已授权)。
        # 探测失败 ⇒ 不落库,继续走回调 code 交换路径。
        if probe_ok:
            db.append_log(sk, ak, "oauth", {"step": "done-via-browser-cookie",
                                            "hasCookie": True})
            return _finish_auth(sk, ak, site, account, creds, cfg,
                                browser_cookies=holder["site_cookies"],
                                trusted=cred_trusted, task_id=task_id)
        db.append_log(sk, ak, "oauth", {"step": "browser-cookie-probe-fail",
                                        "cookieNames": _cookie_names(holder["site_cookies"])}, "err")

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
        # GitHub 显式拒绝(error=access_denied):授权偏好被记忆为 deny,
        # 需到 GitHub Settings→Applications 撤销该应用后重试
        denied = "access_denied" in final_url
        db.append_log(sk, ak, "oauth", {"step": "callback", "verdict": "missing-code",
                                        "denied": denied, "url": cb.safe}, "err")
        msg = ("GitHub 拒绝了授权(error=access_denied):请到 GitHub → Settings → "
               "Applications → Authorized OAuth Apps 撤销该应用后重试"
               if denied else "未获取到授权码(可能授权被拒绝)")
        return AuthResult("failed", msg, manual_url=auth_url)
    if not cb.should_exchange:
        if NEED_MANUAL_URL_RE.search(final_url):
            db.append_log(sk, ak, "oauth", {"step": "github-wall", "url": final_url[:80]}, "err")
            return AuthResult("need_manual",
                              "GitHub 会话过期且无法自动填充,需手动授权一次(之后恢复全自动)",
                              manual_url=auth_url,
                              code_task=task_id)
        db.append_log(sk, ak, "oauth", {"step": "callback", "verdict": "timeout",
                                        "url": final_url[:80]}, "err")
        # ⑥ 等码超时仍无码:返回 failed 且 manual_url 非空(前端还能给手动出路);
        #    带 code_task 让前端知道是哪个任务在等码。若本次确实卡在等码,
        #    把 waiting_code 的提示带上,用户才知道"失败原因=没填验证码"。
        waited_code = "waiting_code" in holder.get("waiting", set())
        hint = ""
        if waited_code:
            hint = ("等待验证码超时:本次授权需要 6 位验证码(2FA 或邮箱设备码),"
                    "超时未收到。可重新授权并在提示出现后填码,或点下方手动授权。")
        return AuthResult("failed",
                          ("等待验证码超时" if waited_code
                           else f"授权超时(最终落点 {urlparse(final_url).hostname})"),
                          manual_url=auth_url, code_task=task_id, hint=hint)

    # 4. 交换(服务端直调,主交换响应直接抓 Set-Cookie;code 一次性,不重放)
    ex = anon_client.call("get", f"/api/oauth/github?code={quote(cb.code)}&state={quote(cb.state)}")
    if ex.status != 200 or not isinstance(ex.data, dict) or not ex.data.get("success"):
        msg = ex.error or f"交换失败(HTTP {ex.status})"
        db.append_log(sk, ak, "oauth", {"step": "exchange", "http": ex.status}, "err")
        return AuthResult("failed", msg)

    return _finish_auth(sk, ak, site, account, extract_credentials(ex.data), cfg,
                        set_cookies=ex.set_cookies,
                        browser_cookies=holder["site_cookies"],
                        trusted=cred_trusted, task_id=task_id)


def _finish_auth(sk: str, ak: str, site: dict, account: dict, creds: dict,
                 cfg: dict, set_cookies: list[str] | None = None,
                 xhr_headers: Any = None,
                 browser_cookies: str = "", trusted: bool = False,
                 task_id: str = "", hint: str = "") -> AuthResult:
    """凭据落库收尾(主交换/capture_xhr 保险路径共用):B1 校验 + 凭据合成。

    site_cookie 取三者并集:浏览器上下文导出(最全,含 httpOnly session)
    > 服务端 Set-Cookie 解析 > capture_xhr 响应头。实测依据:AgentRouter 的
    真凭据 session 是 httpOnly,服务端 FetcherSession 只抓到 WAF acw_tc。
    trusted:本次是否用本账号凭据现场登录(是则站点自动生成的用户名可放行)。
    task_id/hint:回带授权结果(契约 §5),前端据此知道是哪个任务的码。
    """
    ok, why = b1_identity_check(creds, account, trusted=trusted)
    if not ok:
        db.append_log(sk, ak, "oauth", {"step": "b1", "error": why}, "err")
        return AuthResult("failed", f"身份校验失败:{why}")

    parts: dict[str, str] = {}
    for source in (browser_cookies,
                   parse_set_cookies(set_cookies or []),
                   _xhr_set_cookies(xhr_headers)):
        for pair in source.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                if v and not v.lower() == "deleted":
                    parts.setdefault(k.strip(), v.strip())
    site_cookie = "; ".join(f"{k}={v}" for k, v in parts.items())

    db.append_log(sk, ak, "oauth", {"step": "done", "hasToken": bool(creds["token"]),
                                    "hasCookie": bool(site_cookie),
                                    "login": creds["github_login"]})
    return AuthResult(
        "ok", "授权成功",
        token=creds["token"], site_cookie=site_cookie,
        site_user_id=creds["site_user_id"],
        github_login=creds["github_login"], github_id=creds["github_id"],
        code_task=task_id, hint=hint,
    )


def _xhr_set_cookies(xhr_headers: Any) -> str:
    """从 capture_xhr 响应头抓 Set-Cookie(失败返回空串)。"""
    if xhr_headers is None:
        return ""
    try:
        get_list = getattr(xhr_headers, "get_list", None)
        if callable(get_list):
            return parse_set_cookies(list(get_list("set-cookie") or []))
        single = xhr_headers.get("set-cookie")
        return parse_set_cookies([single] if isinstance(single, str) else list(single or []))
    except Exception:
        return ""


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


def _fill_totp(page, credential: dict, code: str = "") -> bool:
    """2FA 页:默认非 TOTP 时先切「Use authenticator app」,再填 6 位码。

    code: 调用方已取出的手动码(一次性,取即消费);为空时退回 TOTP 密钥生成。
    TOTP 码满 6 位自动提交;两者都无 ⇒ False(交人工)。

    邮箱验证码页(verified-device/device):GitHub 给登录邮箱发 6 位数字码,
    同样走 6 位输入框提交 —— 手动码(前端填码框注入,见 /api/oauth/totp)
    在此分支同样生效,无需 TOTP 密钥。
    """
    url = ""
    try:
        url = page.url or ""
    except Exception:
        pass
    is_email_code = ("verified-device" in url) or ("/device" in url and "two-factor" not in url)
    code = str(code or "").strip() or ("" if is_email_code else _totp_code(credential))
    if not code:
        return False
    try:
        if not is_email_code:
            link = page.locator(
                "a:has-text('authenticator'), button:has-text('authenticator')")
            if link.count():
                link.first.click()
                page.wait_for_timeout(1500)
        otp = page.locator(
            "#app_totp, #otp, #device-code, input[autocomplete='one-time-code'], "
            "input[name='code'], input[inputmode='numeric']").first
        otp.fill(code)                       # 满 6 位 GitHub 自动提交
        return True
    except Exception:
        return False


# ---------- 手动码存储(契约 5/3):按 task_id 隔离 + 120s 过期 + 一次性消费 ----------

_MANUAL_CODE_TTL = 120.0                # 注入后有效期(秒)
_manual_codes: dict[str, tuple[str, float]] = {}
_DEFAULT_BUCKET = "_default"            # 未传 task_id 的旧调用落入的桶


def set_manual_code(code: str, task_id: str = "") -> None:
    """注入 6 位码(契约 5):码按 task_id 隔离存储,注入后 120s 过期。

    task_id 为空(旧调用)⇒ 落入 _default 桶;消费一次即清除(防串码/防残留)。
    """
    code = str(code or "").strip()[:6]
    bucket = task_id or _DEFAULT_BUCKET
    _manual_codes[bucket] = (code, time.time() + _MANUAL_CODE_TTL)


def _take_manual_code(task_id: str = "") -> str:
    """按 task_id 取手动码:取即消费(清除),过期/无码返回空。"""
    bucket = task_id or _DEFAULT_BUCKET
    item = _manual_codes.get(bucket)
    if not item:
        return ""
    code, exp = item
    if time.time() > exp:
        _manual_codes.pop(bucket, None)    # 过期即清
        return ""
    _manual_codes.pop(bucket, None)        # 一次性消费
    return code


def _peek_manual_code(task_id: str = "") -> str:
    """不消费地查码(仅测试/调试用):过期视为无。"""
    item = _manual_codes.get(task_id or _DEFAULT_BUCKET)
    if not item:
        return ""
    code, exp = item
    if time.time() > exp:
        return ""
    return code


def _clear_manual_codes() -> None:
    """清空全部手动码(测试隔离用)。"""
    _manual_codes.clear()


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


# ---------- 有头授权:CDP 接管用户真实 Chrome ----------

MANUAL_CDP_PORT = 19222
MANUAL_PROFILE_DIR = "manual-chrome-profile"


def manual_profile_dir() -> str:
    """手动授权专用 Chrome profile(独立目录,不污染用户日常配置)。"""
    from ..service.config import ROOT
    d = ROOT / "data" / MANUAL_PROFILE_DIR
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def ensure_manual_chrome() -> tuple[bool, str]:
    """启动带远程调试端口的用户真实 Chrome(有头可见)。

    返回 (ok, msg)。Chrome 已在该端口监听则直接复用。
    """
    import json as _json
    import subprocess
    import urllib.request
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{MANUAL_CDP_PORT}/json/version", timeout=3) as r:
            info = _json.loads(r.read().decode("utf-8", "replace"))
            if info.get("webSocketDebuggerUrl"):
                return True, "已连接已有 Chrome 调试会话"
    except Exception:
        pass
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    exe = next((c for c in candidates if os.path.exists(c)), None)
    if not exe:
        return False, "未找到 Chrome,请先安装 Google Chrome"
    try:
        subprocess.Popen(
            [exe, f"--remote-debugging-port={MANUAL_CDP_PORT}",
             f"--user-data-dir={manual_profile_dir()}",
             "--no-first-run", "--no-default-browser-check",
             "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as e:
        return False, f"Chrome 启动失败: {e}"
    for _ in range(30):
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{MANUAL_CDP_PORT}/json/version", timeout=2) as r:
                info = _json.loads(r.read().decode("utf-8", "replace"))
                if info.get("webSocketDebuggerUrl"):
                    return True, "Chrome 已弹出,请在窗口里完成登录/验证"
        except Exception:
            pass
        time.sleep(1)
    return False, "Chrome 调试端口无响应,请检查 Chrome 是否被拦截"


def manual_cdp_url() -> str:
    """返回 ws:// 调试地址(scrapling 的 cdp_url 只接受 ws/wss scheme)。"""
    import json as _json
    import urllib.request
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{MANUAL_CDP_PORT}/json/version", timeout=3) as r:
            info = _json.loads(r.read().decode("utf-8", "replace"))
            ws = info.get("webSocketDebuggerUrl") or ""
            if ws.startswith("ws"):
                return ws
    except Exception:
        pass
    return f"ws://127.0.0.1:{MANUAL_CDP_PORT}"
