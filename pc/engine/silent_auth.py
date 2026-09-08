"""silent_auth.py — 静默换凭据(P2,契约 §3.0「重新登录」语义 + §5.3)。

全站统一路径:不实现 logout,凭据过期 = 静默重放一遍 GitHub OAuth。
- 触发:JWT exp 剩余 <60s 预判;业务请求 401 兜底
- 防风暴三重:同账号串行(锁)+ 成功 8s 复用 + 失败 90s 冷却(手动授权可清)
- 成功判据:token 或 siteCookie 任一变化(数据驱动,全站通用)
"""
from __future__ import annotations

import base64
import json
import time
from threading import RLock

from ..service import config as config_svc
from ..service import db
from .oauth_flow import AuthResult, authorize
from .site_client import SiteClient

REUSE_MS = 8 * 1000            # 成功后 8s 内复用
FAIL_COOLDOWN_MS = 90 * 1000   # 失败后 90s 冷却
EXP_THRESHOLD_S = 60           # JWT 剩余 <60s 视为即将过期

_locks: dict[str, RLock] = {}
_last_ok: dict[str, float] = {}
_fail_until: dict[str, float] = {}
_meta_lock = RLock()


def _lock_of(key: str) -> RLock:
    with _meta_lock:
        if key not in _locks:
            _locks[key] = RLock()
        return _locks[key]


def in_cooldown(account_key: str) -> bool:
    with _meta_lock:
        until = _fail_until.get(account_key)
        return until is not None and time.time() * 1000 < until


def clear_cooldown(account_key: str) -> None:
    with _meta_lock:
        _fail_until.pop(account_key, None)


def jwt_exp_epoch(token: str) -> float | None:
    """解析 JWT exp(不验签,只读声明);非 JWT/解析失败返回 None。"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad))
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


def token_expiring(token: str) -> bool:
    """token 为空或剩余 <60s ⇒ 需要换新。"""
    if not token or token == "null":
        return True
    exp = jwt_exp_epoch(token)
    if exp is None:
        return False           # 非 JWT(系统令牌)无法预判,等 401 兜底
    return (exp - time.time()) < EXP_THRESHOLD_S


def _persist(site: dict, account: dict, r: AuthResult) -> None:
    """落盘:token/siteCookie/siteUserId/github 锚点;任一变化即算成功。

    token/siteCookie 落盘前加密(AES-256-GCM,§7 凭据安全)。
    """
    from ..service.secret_store import seal
    cfg = config_svc.load()
    found = config_svc.find_account(cfg, account["key"])
    if not found:
        return
    s, a = found
    if r.token:
        a["token"] = seal(r.token)
    if r.site_cookie:
        a["siteCookie"] = seal(r.site_cookie)
    if r.site_user_id:
        a["siteUserId"] = r.site_user_id
    if r.github_login:
        a["githubAccount"] = r.github_login
    if r.github_id:
        a["githubId"] = r.github_id
    a["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    config_svc.save(cfg)


def exchange(site: dict, account: dict, cfg: dict, credential: dict | None = None,
             force: bool = False, headful: bool = False) -> AuthResult:
    """静默换凭据(带三重防风暴)。force=True 跳过冷却与复用(手动授权用)。"""
    ak = account.get("key", "?")
    sk = site.get("key", "?")

    with _lock_of(ak):                       # 同账号串行
        now = time.time() * 1000
        if not force:
            with _meta_lock:
                if _last_ok.get(ak, 0) > now - REUSE_MS:
                    return AuthResult("ok", "冷却复用(8s 内刚换过)")   # 复用:不重复交换
                if _fail_until.get(ak, 0) > now:
                    return AuthResult("failed", "失败冷却中(90s),稍后自动重试或手动授权")

        r = authorize(site, account, cfg, credential, headful=headful)

        with _meta_lock:
            if r.state == "ok":
                _last_ok[ak] = time.time() * 1000
                _fail_until.pop(ak, None)
            else:
                _fail_until[ak] = time.time() * 1000 + FAIL_COOLDOWN_MS

        if r.state == "ok":
            _persist(site, account, r)
            db.append_log(sk, ak, "silent-auth", {
                "hasToken": bool(r.token), "hasCookie": bool(r.site_cookie),
                "login": r.github_login,
            })
        else:
            db.append_log(sk, ak, "silent-auth",
                          {"state": r.state, "error": r.message[:120]}, "err")
        return r


def ensure_token(site: dict, account: dict, cfg: dict,
                 credential: dict | None = None) -> str:
    """token 即将过期(JWT exp<60s)⇒ 预判换新;返回可用 token(可空)。"""
    token = (account.get("token") or "").strip()
    if not token_expiring(token):
        return token
    cookie = (account.get("siteCookie") or "").strip()
    if token or cookie:                       # 有任一凭据才尝试静默换新
        r = exchange(site, account, cfg, credential)
        if r.state == "ok" and r.token:
            account["token"] = r.token         # 就地更新,调用方立即受益
        if r.site_cookie:
            account["siteCookie"] = r.site_cookie
    return (account.get("token") or "").strip()


def call_with_auto_reauth(site: dict, account: dict, cfg: dict, method: str, path: str,
                          credential: dict | None = None):
    """带 401 自动静默换凭据重试的请求(平移 Engine.callWithAuth)。

    返回 CallResult;换新成功(token 或 cookie 任一变化)自动重试一次并标记 reauthed。
    """
    client = SiteClient(site, account, cfg)
    ensure_token(site, account, cfg, credential)
    r = client.call(method, path)
    if r.status != 401:
        return r

    old_token = (account.get("token") or "").strip()
    old_cookie = (account.get("siteCookie") or "").strip()
    fresh = exchange(site, account, cfg, credential)
    token_changed = bool(fresh.token) and fresh.token != old_token
    cookie_changed = bool(fresh.site_cookie) and fresh.site_cookie != old_cookie
    if not (token_changed or cookie_changed):
        return r

    account.update({k: v for k, v in {
        "token": fresh.token, "siteCookie": fresh.site_cookie,
        "siteUserId": fresh.site_user_id,
    }.items() if v})
    r2 = client.call(method, path)
    r2.reauthed = True
    return r2
