"""site_client.py — 站点 API 客户端(契约见设计文档 §3.0,全部规则数据驱动、不按站点名特判)。

接口契约复用原仓库已实测清单,传输层换 Scrapling FetcherSession:
- 请求头按账号字段叠加:有 token ⇒ Bearer;有 siteCookie ⇒ Cookie;有 siteUserId ⇒ New-Api-User
- 429:读 Retry-After 退避(4s×attempt,共 3 次);连续失败触发换代理
- WAF 假 200:HTTP 200 但响应体非合法 JSON ⇒ 判拦截,不清空调用方已有数据
- 签到:先只读查当月记录,未签才 POST;POST 被拦文本匹配人机验证 ⇒ 需 Turnstile
"""
from __future__ import annotations


import json
import random
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

QUOTA_PER_UNIT_DEFAULT = 500000
NEED_CAPTCHA_RE = re.compile(
    r"turnstile|captcha|验证|校验|人机|challenge|robot", re.IGNORECASE
)


@dataclass
class CallResult:
    ok: bool
    status: int = 0
    data: Any = None          # 解析后的 JSON(可能为 None)
    raw: str = ""             # 原始响应体
    error: str = ""           # 网络层错误信息
    reauthed: bool = False
    blocked_by_waf: bool = False

    def is_401(self) -> bool:
        return self.status == 401


@dataclass
class CheckinOutcome:
    state: str                # done / already / skipped / need_captcha / failed
    awarded: float | None = None
    message: str = ""


class WafBlockedError(Exception):
    """HTTP 200 但响应体非 JSON —— WAF 拦截页(契约 §3.0 通用规则 3)。"""


class SiteClient:
    RETRY_BACKOFF = (4, 8, 12)            # 429 退避:4s × (attempt+1)
    TIMEOUT_CONNECT, TIMEOUT_READ = 15, 20

    def __init__(self, site: dict, account: dict, cfg: dict):
        self.site = site
        self.account = account or {}
        self.cfg = cfg
        self.base_url = str(site.get("baseUrl", "")).rstrip("/")

    # ---------- 请求头组装(按账号字段叠加,有哪个带哪个) ----------

    def _headers(self) -> dict[str, str]:
        h = {
            "User-Agent": self.cfg.get("UA", "Mozilla/5.0"),
            "Accept": "application/json",
        }
        token = (self.account.get("token") or "").strip()
        if token and token != "null":
            h["Authorization"] = f"Bearer {token}"
        cookie = (self.account.get("siteCookie") or "").strip()
        if cookie and cookie != "null":
            h["Cookie"] = cookie
        uid = str(self.account.get("siteUserId") or "").strip()
        if uid and uid != "null":
            h["New-Api-User"] = uid
        return h

    # ---------- 代理 ----------

    def _proxy_url(self) -> str | None:
        p = self.cfg.get("proxy") or {}
        if not p.get("enabled"):
            return None
        return f"{p.get('type', 'socks5')}://{p.get('host', '127.0.0.1')}:{p.get('port', 10808)}"

    # ---------- 单次请求(FetcherSession 语义,可注入 mock) ----------

    def _raw_call(self, method: str, path: str, body: Any = None) -> CallResult:
        """同步 HTTP:scrapling FetcherSession(curl_cffi,TLS 指纹伪装)。

        实测(scrapling 0.4.11):retries=0 会触发 'No active session available',
        故传 retries=1(只发一次);重试语义由本类 429 逻辑管理。
        """
        from scrapling.fetchers import FetcherSession

        url = self.base_url + path
        impersonate = self.cfg.get("impersonate") or ["chrome"]
        with FetcherSession(
            impersonate=random.choice(impersonate) if isinstance(impersonate, list) else impersonate,
            stealthy_headers=False,           # 头由 _headers() 契约组装
            timeout=self.TIMEOUT_READ,
            retries=1,
            proxy=self._proxy_url(),
        ) as s:
            kwargs: dict[str, Any] = {"headers": self._headers()}
            if body is not None:
                kwargs["json"] = body
            r = getattr(s, method)(url, **kwargs)
            body_str = r.body.decode("utf-8", "replace") if isinstance(r.body, bytes) else str(r.body)
            return CallResult(ok=True, status=r.status, raw=body_str)

    # ---------- 通用调用(含 429 退避 + WAF 假 200 识别) ----------

    def call(self, method: str, path: str, body: Any = None) -> CallResult:
        result = CallResult(ok=False)
        last_err = ""
        for attempt in range(3):
            try:
                result = self._raw_call(method, path, body)
            except Exception as e:            # 网络层失败(代理不可达等)
                last_err = f"{type(e).__name__}: {e}"
                result = CallResult(ok=False, error=last_err)
                continue

            if result.status == 429:
                if attempt < 2:
                    import time
                    time.sleep(self.RETRY_BACKOFF[attempt])
                    continue
                result.error = "站点限流(429),已重试 3 次"
                return result

            if result.status == 200:
                try:
                    result.data = json.loads(result.raw) if result.raw.strip() else None
                except json.JSONDecodeError:
                    # WAF 假 200:拦截页冒充 200,契约要求不清空调用方数据
                    result.blocked_by_waf = True
                    result.error = "站点防护拦截(WAF 假 200),建议更换代理节点"
                return result

            # 其余状态码(401/404/5xx 等):透传给调用方判定
            try:
                result.data = json.loads(result.raw) if result.raw.strip() else None
            except json.JSONDecodeError:
                pass
            return result

        result.error = result.error or f"网络请求失败(重试 3 次): {last_err}"
        return result

    # ---------- 业务接口(契约 §3.0 表) ----------

    def status(self) -> CallResult:
        """站点元信息:quota_per_unit / turnstile_check / github_client_id / checkin_enabled。"""
        return self.call("get", "/api/status")

    def self_info(self) -> CallResult:
        return self.call("get", "/api/user/self")

    def checkin_state(self) -> CallResult:
        """只读前置判定:GET /api/user/checkin?month=YYYY-MM(不触发人机验证)。"""
        month = datetime.now().strftime("%Y-%m")
        return self.call("get", f"/api/user/checkin?month={month}")

    def checkin_post(self, turnstile_token: str = "") -> CallResult:
        path = "/api/user/checkin"
        if turnstile_token:
            from urllib.parse import quote
            path += "?turnstile=" + quote(turnstile_token)
        return self.call("post", path)

    def usage_log(self, category: str = "系统", page: int = 1, limit: int = 20) -> CallResult:
        return self.call(
            "get",
            f"/api/log/self?category={category}&page={page}&limit={limit}",
        )

    # ---------- 签到流程(前置判定 → POST → 人机验证检测) ----------

    def checkin_flow(self) -> CheckinOutcome:
        st = self.status()
        st_data = (st.data or {}).get("data") or {}
        if st_data.get("checkin_enabled") is False:
            return CheckinOutcome("skipped", message="站点未开启签到")

        month_raw = self.checkin_state()
        if month_raw.status == 200 and isinstance(month_raw.data, dict):
            data = month_raw.data.get("data") or {}
            stats = data.get("stats") or {}
            today = datetime.now().strftime("%Y-%m-%d")
            records = data.get("records") or []
            today_rec = next(
                (r for r in records
                 if str(r.get("checkin_date") or r.get("date") or "") == today),
                None,
            )
            if stats.get("checked_in_today") or today_rec:
                # 奖励三态:有金额显金额;==0 无奖励;查不到只显已签
                if today_rec is not None and today_rec.get("quota_awarded"):
                    unit = st_data.get("quota_per_unit") or QUOTA_PER_UNIT_DEFAULT
                    return CheckinOutcome(
                        "already",
                        awarded=round(float(today_rec["quota_awarded"]) / unit, 2),
                        message="今日已签到",
                    )
                if today_rec is not None:
                    return CheckinOutcome("already", message="今日已签到(本站无签到奖励)")
                return CheckinOutcome("already", message="今日已签到")

        # 未签(或查询失败)⇒ POST
        post = self.checkin_post()
        if post.status == 200 and isinstance(post.data, dict):
            d = post.data.get("data")
            awarded = None
            if isinstance(d, dict) and d.get("quota_awarded") is not None:
                unit = st_data.get("quota_per_unit") or QUOTA_PER_UNIT_DEFAULT
                awarded = round(float(d["quota_awarded"]) / unit, 2)
            return CheckinOutcome("done", awarded=awarded, message="签到成功")
        if post.blocked_by_waf:
            return CheckinOutcome("failed", message=post.error)
        if NEED_CAPTCHA_RE.search(post.raw or ""):
            return CheckinOutcome("need_captcha", message="签到被拦,需要人机验证")
        if post.status == 401:
            return CheckinOutcome("failed", message="凭据失效(401),需静默换新")
        return CheckinOutcome("failed", message=f"签到失败(HTTP {post.status})")
