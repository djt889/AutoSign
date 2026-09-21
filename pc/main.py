"""main.py — FastAPI 入口(WebUI 服务端 + 全部 API 端点)。

包含:health / 静态 WebUI / 站点与账号 CRUD / 额度状态(10 分钟缓存) /
签到 / 凭据库与凭据验证 / OAuth 授权(无头+有头兜底) / 定时调度 / SSE 实时日志。

启动:python -m pc.main   (默认 127.0.0.1:37421,可用 JUSTSIGN_HOST/JUSTSIGN_PORT 覆盖;
设 JUSTSIGN_HOST=0.0.0.0 才对外暴露——服务无鉴权,对外风险自负)
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .engine.checkin import run_checkin
from .engine.credentials import (delete_credential, derive_auth_mode,
                              get_credential, list_credentials,
                              migrate_legacy_enc, save_credential,
                              upsert_credential)
from .engine.oauth_flow import AuthResult, authorize, set_manual_code
from .engine.site_client import QUOTA_PER_UNIT_DEFAULT, SiteClient
from .engine.silent_auth import clear_cooldown, exchange
from .service import config, db
from .service.scheduler import run_all_once, scheduler_status, start_scheduler

app = FastAPI(title="AutoSign", version="1.0.4")

STATIC_DIR = Path(__file__).resolve().parent / "web" / "static"
HOST = os.environ.get("JUSTSIGN_HOST", "127.0.0.1")
PORT = int(os.environ.get("JUSTSIGN_PORT", "37421"))


def _mask(token: str | None) -> str | None:
    """只显示尾部 4 字符:避免明文前缀泄露(token 前缀往往是最有信息量的部分)。"""
    return ("…" + token[-4:]) if token else None


def _mask_site(s: dict) -> dict:
    out = dict(s)
    out["accounts"] = [
        {**a, "token": _mask(a.get("token")), "siteCookie": _mask(a.get("siteCookie"))}
        for a in (s.get("accounts") or [])
    ]
    return out


@app.get("/api/health")
def health():
    return {"ok": True, "engine": "python-scrapling", "version": app.version}


@app.post("/api/setup")
def setup_builtin_sites():
    """初始化:装入内置四站(已存在的跳过,用户删除的不复活)。"""
    cfg = config.setup_builtin()
    return {"ok": True, "sites": [_mask_site(s) for s in cfg.get("sites", [])]}


@app.get("/api/sites")
def list_sites():
    cfg = config.load()
    return {"ok": True, "sites": [_mask_site(s) for s in cfg.get("sites", [])]}


@app.get("/api/accounts")
def list_accounts():
    cfg = config.load()
    flat = []
    for s in cfg.get("sites", []):
        for a in s.get("accounts") or []:
            cred_name = ""
            if a.get("credentialId"):
                for _c in (cfg.get("credentials") or []):
                    if _c.get("id") == a.get("credentialId"):
                        cred_name = (_c.get("alias") or _c.get("githubUser")
                                     or a.get("credentialId"))
                        break
            flat.append({
                **{k: v for k, v in a.items() if k != "encCredential"},
                "token": _mask(a.get("token")),
                "siteCookie": _mask(a.get("siteCookie")),
                "encCredential": bool(a.get("encCredential")),
                "credentialId": a.get("credentialId") or "",
                "credentialName": cred_name,
                "checkinType": s.get("checkinType"),
                "siteKey": s["key"], "siteName": s.get("name", s["key"]),
            })
    return {"ok": True, "tokens": flat}


_status_cache: dict[str, tuple[float, dict]] = {}   # account_key → (ts, result)
_STATUS_CACHE_TTL = 600                              # 10 分钟:余额按需获取,不轮询站点


@app.get("/api/status/{account_key}")
def account_status(account_key: str, force: int = 0):
    """账号额度(按需获取:页面加载/手动刷新才调;10 分钟缓存防多端重复打站点,
    force=1 绕过缓存)。"""
    import time as _time
    cached = _status_cache.get(account_key)
    now = _time.time()
    if cached and not force and now - cached[0] < _STATUS_CACHE_TTL:
        return cached[1]

    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")
    site, acc = found
    from .engine.silent_auth import call_with_auto_reauth
    self_r = call_with_auto_reauth(site, acc, cfg, "get", "/api/user/self")
    cl = SiteClient(site, acc, cfg)
    st_r = cl.status()
    if self_r.status != 200 or self_r.blocked_by_waf:
        db.append_log(site["key"], account_key, "status",
                      {"http": self_r.status, "waf": self_r.blocked_by_waf}, "err")
        raise HTTPException(502, self_r.error or f"站点请求失败(HTTP {self_r.status})")
    d = ((self_r.data or {}).get("data") or {})
    unit = ((st_r.data or {}).get("data") or {}).get("quota_per_unit") or QUOTA_PER_UNIT_DEFAULT
    quota, used = float(d.get("quota") or 0), float(d.get("used_quota") or 0)
    result = {
        "ok": True,
        "account": account_key, "site": site.get("name"), "siteKey": site["key"],
        "authorized": True,
        "availableUSD": round(quota / unit, 2),
        "usedUSD": round(used / unit, 2),
        "user": d.get("display_name") or d.get("username") or d.get("github_id"),
        "todayUsed": round(float(d.get("today_used_quota") or 0) / unit, 4) or None,
        "cachedAt": int(now),
    }
    _status_cache[account_key] = (now, result)
    db.append_log(site["key"], account_key, "status", {"availableUSD": result["availableUSD"]})
    return result


@app.post("/api/checkin/{account_key}")
def checkin(account_key: str):
    """手动签到:两级 Turnstile 全自动,失败即报错(不转人工,契约 §7)。"""
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")
    site, acc = found
    report = run_checkin(site, acc, cfg)
    # 签到后额度已变化:清除该账号 status 缓存,接下来的刷新必然打站点拿新值
    _status_cache.pop(account_key, None)
    return report.to_dict()


# ---------- 设置 / 调度 / SSE ----------

@app.get("/api/settings")
def get_settings():
    cfg = config.load()
    sch = dict(cfg.get("schedule") or {})
    sch.update(scheduler_status())
    return {"ok": True, "schedule": sch, "proxy": cfg.get("proxy") or {}}


@app.post("/api/settings/save")
def settings_save(body: dict):
    def _mut(cfg):
        if isinstance(body.get("schedule"), dict):
            s = body["schedule"]
            cfg["schedule"] = {
                "enabled": bool(s.get("enabled")),
                "time": str(s.get("time") or "09:05"),
            }
        if isinstance(body.get("proxy"), dict):
            p = body["proxy"]
            raw_port = p.get("port")           # 区分缺省(None→10808)与显式 0(非法)
            try:
                port = 10808 if raw_port is None else int(raw_port)
            except (TypeError, ValueError):
                raise HTTPException(400, f"proxy.port 非法:需要整数,收到 {raw_port!r}")
            if not (1 <= port <= 65535):
                raise HTTPException(400, f"proxy.port 超出范围(1-65535): {port}")
            cfg["proxy"] = {
                "enabled": bool(p.get("enabled")), "type": "socks5",
                "host": str(p.get("host") or "127.0.0.1"),
                "port": port,
            }

    cfg = config.update(_mut)
    start_scheduler()          # 保存即生效(重启或停用)
    db.append_log("*", "*", "settings-save",
                  {"schedule": cfg.get("schedule"), "proxyEnabled": (cfg.get("proxy") or {}).get("enabled")})
    return {"ok": True}


@app.post("/api/run-all")
def run_all():
    """立即对所有已授权账号串行跑一轮(手动触发,与 cron 同一入口)。"""
    def worker():
        try:
            run_all_once(trigger="manual")
        except Exception as e:
            db.append_log("*", "*", "run-all", {"error": str(e)[:200]}, "err")
    threading.Thread(target=worker, daemon=True, name="run-all").start()
    return {"ok": True, "message": "已触发(后台串行执行,看实时日志)"}


@app.post("/api/seal-existing")
def seal_existing():
    """迁移:把存量明文 token/siteCookie 一次性加密(幂等)。"""
    from .service.secret_store import seal_account
    counter = {"n": 0}

    def _mut(cfg):
        for s in cfg.get("sites", []):
            for a in s.get("accounts") or []:
                before_token, before_ck = a.get("token"), a.get("siteCookie")
                seal_account(a)
                if (before_token and str(before_token) != a.get("token")) or \
                        (before_ck and str(before_ck) != a.get("siteCookie")):
                    counter["n"] += 1

    config.update(_mut)
    db.append_log("*", "*", "seal-existing", {"sealed_accounts": counter["n"]})
    return {"ok": True, "sealed_accounts": counter["n"]}


@app.get("/api/events")
async def events():
    """SSE 实时日志流:按 db.seq 增量推送(seq > last_seq 才推),断线由前端
    EventSource 自动重连。首连回放最近 20 条,之后只推新条目——
    旧实现按"条数差"增量,多客户端并发/日志截断时会同一条重复推或整段漏推。"""
    import asyncio
    from fastapi.responses import StreamingResponse

    def _seq_of(l: dict) -> int:
        try:
            return int(l.get("seq") or 0)
        except (TypeError, ValueError):
            return 0

    async def gen():
        # 基线只取回放条目的最大 seq:不能用 max_seq() 兜底——它会把基线抬到
        # 计数器当前值,吞掉"回放开始后、读取前"恰好落盘的日志(seq == 基线)
        last_seq = 0
        logs = db.recent_logs(20)              # 首连回放最近 20 条(最新在前)
        for l in reversed(logs):
            last_seq = max(last_seq, _seq_of(l))
            yield f"data: {json.dumps(l, ensure_ascii=False)}\n\n"
        while True:
            logs = db.recent_logs(300)
            fresh = [l for l in logs if _seq_of(l) > last_seq]
            for l in reversed(fresh):          # 按时间正序推
                last_seq = max(last_seq, _seq_of(l))
                yield f"data: {json.dumps(l, ensure_ascii=False)}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/config")
def get_config():
    """原版 WebUI 兼容:返回带 cfg 包装的配置(token/cookie 打码)。

    凭据库(credentials[])从响应中剔除——它含加密的 password/twofa 密文与
    账号元数据,前端只应通过 /api/credentials(明文/密文均不回显)访问。
    """
    cfg = config.load()
    safe = {k: v for k, v in cfg.items() if k != "credentials"}
    safe["sites"] = [_mask_site(s) for s in cfg.get("sites", [])]
    return {"ok": True, "cfg": safe}


@app.get("/api/logs/{account_key}")
def account_logs(account_key: str, category: str = "系统", limit: int = 50, page: int = 1):
    """原版 WebUI 兼容:站点使用日志 + lastBonus(找「签到」记录)。
    category/page/limit 经 urlencode 传给站点(category 可能含中文/&等);
    limit/page 钳制到 1-200,防异常值打爆站点接口。"""
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")
    site, acc = found
    limit = max(1, min(int(limit), 200))
    page = max(1, min(int(page), 200))
    from urllib.parse import urlencode
    from .engine.silent_auth import call_with_auto_reauth
    r = call_with_auto_reauth(site, acc, cfg, "get",
                              f"/api/log/self?{urlencode({'category': category, 'page': page, 'limit': limit})}")
    data = (r.data or {}).get("data") or {}
    items = data.get("list") or data.get("items") or (data if isinstance(data, list) else [])

    def _row(x):
        if not isinstance(x, dict):
            return {"time": "", "category": category, "text": str(x), "quota": None}
        return {
            "time": str(x.get("created_at") or x.get("time") or "")[:19],
            "category": x.get("category") or category,
            "text": x.get("description") or x.get("content") or x.get("remark"),
            "quota": x.get("quota"),
        }

    rows = [_row(x) for x in (items or [])]
    # 只认「签到」类文案(排除注册赠送/邀请赠送——同为系统日志但非每日签到)
    last_bonus = next((row for row in rows if "签到" in str(row["text"])
                       and not any(w in str(row["text"]) for w in ("注册", "邀请", "兑换"))), None)
    db.append_log(site["key"], account_key, "logs", {"http": r.status, "rows": len(rows)})
    return {"ok": r.status == 200, "http": r.status, "rows": rows, "lastBonus": last_bonus}


@app.post("/api/credentials/migrate")
def credentials_migrate():
    """迁移旧 encCredential(账号内嵌)到全局凭据库。"""
    n = migrate_legacy_enc()
    db.append_log("*", "*", "credential-migrate", {"migrated": n})
    return {"ok": True, "migrated": n}


@app.get("/api/history")
def history():
    return {"ok": True, "data": db.recent_logs(300)}


# ---------- 站点/账号管理(写操作) ----------

@app.post("/api/sites/save")
def sites_save(body: dict):
    base_url = str(body.get("baseUrl", "")).strip().rstrip("/")
    if not base_url:
        raise HTTPException(400, "需要 baseUrl")
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    checkin_type = "manual" if body.get("checkinType") == "manual" else (
        "newapi" if body.get("checkinType") == "newapi" else "login")
    out = {"key": ""}

    def _mut(cfg):
        if body.get("key"):
            s = next((x for x in cfg["sites"] if x["key"] == body["key"]), None)
            if not s:
                raise HTTPException(404, "站点不存在")
            s["name"] = body.get("name") or s.get("name")
            s["baseUrl"] = base_url
            s["checkinType"] = checkin_type
            out["key"] = body["key"]
        else:
            key = config.site_key_of(base_url)
            if any(x["key"] == key for x in cfg["sites"]):
                raise HTTPException(409, "该站点已存在(按地址识别)")
            cfg["sites"].append({
                "key": key, "name": body.get("name") or key,
                "baseUrl": base_url, "checkinType": checkin_type, "accounts": [],
            })
            out["key"] = key

    cfg = config.update(_mut)
    db.append_log(out["key"], "*", "site-save", {"baseUrl": base_url})
    return {"ok": True, "sites": [_mask_site(s) for s in cfg["sites"]]}


@app.delete("/api/sites/{site_key}")
def sites_delete(site_key: str):
    found = {"ok": False}

    def _mut(cfg):
        before = len(cfg["sites"])
        cfg["sites"] = [s for s in cfg["sites"] if s["key"] != site_key]
        found["ok"] = len(cfg["sites"]) != before
        if found["ok"]:
            config.mark_builtin_removed(cfg, site_key)     # 内置站删除后不复活

    config.update(_mut)
    if not found["ok"]:
        raise HTTPException(404, "站点不存在")
    db.append_log(site_key, "*", "site-delete", None)
    return {"ok": True}


@app.post("/api/accounts/save")
def accounts_save(body: dict):
    """新增/更新账号。原子事务:并发(签到/刷新/授权)时不互相覆盖丢账号
    ——这是"前端拿旧 key 报账号不存在"的根因。
    同站点同凭据去重(契约 9):已存在则复用其 key,不重复建账号。"""
    from .service.secret_store import seal
    out = {"key": "", "deduplicated": False}

    def _mut(cfg):
        site = next((s for s in cfg["sites"] if s["key"] == body.get("siteKey")), None)
        if not site:
            raise HTTPException(400, "siteKey 无效")
        site.setdefault("accounts", [])
        cid = str(body.get("credentialId", "") or "")
        # uuid 后 8 位代替毫秒时间戳:并发建号同毫秒必撞(实测丢账号),
        # 前端对 key 无格式假设
        key = body.get("key") or f"acc_{uuid.uuid4().hex[:8]}"
        acc = next((a for a in site["accounts"] if a["key"] == key), None)
        if acc is None and cid:
            # 契约 9:同站点同凭据已存在 ⇒ 复用其 key(在事务内判,防并发重复建)
            dup = next((a for a in site["accounts"]
                        if (a.get("credentialId") or "") == cid), None)
            if dup:
                acc, key, out["deduplicated"] = dup, dup["key"], True
        if not acc:
            acc = {"key": key, "alias": body.get("alias") or key}
            site["accounts"].append(acc)
        if body.get("alias"):
            acc["alias"] = str(body["alias"]).strip()
        # 凭据库引用(原版模型):绑定的凭据决定 githubAccount / 自动填充
        if cid:
            acc["credentialId"] = cid
            for _c in (cfg.get("credentials") or []):
                if _c.get("id") == cid:
                    gh = _c.get("githubUser") or _c.get("siteAccount") or ""
                    if gh:
                        acc["githubAccount"] = gh
                    break
        for f in ("githubAccount", "siteUserId"):
            if body.get(f) is not None:
                acc[f] = body[f]
        # 授权方式(契约 6):显式传值优先;否则由凭据能力推导(有密码→auto,
        # 无密码→manual),已存在则不覆盖
        am = str(body.get("authMode", "") or "")
        if am in ("auto", "manual"):
            acc["authMode"] = am
        elif not acc.get("authMode"):
            acc["authMode"] = derive_auth_mode(cid) if cid else "manual"
        for f in ("token", "siteCookie"):
            if body.get(f) is not None:
                acc[f] = seal(body[f])
        acc["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        out["key"] = key

    config.update(_mut)
    db.append_log(body.get("siteKey", "*"), out["key"], "account-save",
                  {"hasToken": bool(body.get("token")),
                   "deduplicated": out["deduplicated"]})
    return {"ok": True, "key": out["key"], "deduplicated": out["deduplicated"]}


@app.delete("/api/accounts/{account_key}")
def accounts_delete(account_key: str):
    found = {"ok": False}

    def _mut(cfg):
        for s in cfg["sites"]:
            n = len(s.get("accounts") or [])
            s["accounts"] = [a for a in (s.get("accounts") or []) if a["key"] != account_key]
            if len(s["accounts"]) < n:
                found["ok"] = True

    config.update(_mut)
    if not found["ok"]:
        raise HTTPException(404, "账号不存在")
    db.append_log("*", account_key, "account-delete", None)
    return {"ok": True}


# ---------- 凭据库 ----------

@app.get("/api/credentials")
def credentials_list():
    """全局凭据库:同一 GitHub 账号一条,与站点解耦(对齐原版 v0.2.0)。"""
    return {"ok": True, "credentials": list_credentials()}


@app.post("/api/credentials")
def credentials_upsert(body: dict):
    """新增/更新全局凭据;同 githubUser 自动去重返回已有。"""
    try:
        r = upsert_credential(
            alias=str(body.get("alias", "") or ""),
            github_user=str(body.get("githubUser", "") or ""),
            site_account=str(body.get("siteAccount", "") or ""),
            password=body.get("password") if "password" in body else None,
            twofa=body.get("twofa") if "twofa" in body else None,
            note=str(body.get("note", "") or ""),
            credential_id=str(body.get("id", "") or ""),
        )
    except ValueError as e:
        raise HTTPException(404, str(e))
    db.append_log("*", r["id"], "credential-save",
                  {"githubUser": body.get("githubUser", ""), "dup": r["duplicated"]})
    return {"ok": True, **r, "hint": "已加密存储(读不回显)"}


@app.delete("/api/credentials/{credential_id}")
def credentials_delete(credential_id: str):
    if not delete_credential(credential_id):
        raise HTTPException(404, "凭据不存在")
    db.append_log("*", credential_id, "credential-delete", None)
    return {"ok": True}


# ---------- OAuth 授权(方式 A headless;长任务异步句柄) ----------

_oauth_tasks: dict[str, dict] = {}
_verify_tasks: dict[str, dict] = {}
_task_lock = threading.Lock()
_task_ts: dict[str, float] = {}      # task_id → 写入时间(清理用,不出现在响应里)
_task_account: dict[str, str] = {}   # task_id → accountKey(同账号授权去重用)
_TASK_TTL_S = 3600                   # 任务状态保留 1 小时(契约 12)
_TASK_MAX = 200                      # 最多保留 200 条(契约 12)

# 活任务状态:清理(TTL/容量淘汰)不得删除,否则前端轮询会 404、
# waiting_* 等人工输入的任务直接丢失
_LIVE_STATES = ("running", "waiting_code", "waiting_manual")

# AuthResult.state → 前端任务 state(契约 4:need_code/need_manual 分流)
_AUTH_STATE_TO_TASK = {
    "need_code": "waiting_code",
    "need_manual": "waiting_manual",
    "ok": "ok",
    "failed": "failed",
}


def _is_live_locked(task_id: str) -> bool:
    """该 task_id 是否处于活任务状态(须持 _task_lock)。"""
    t = _oauth_tasks.get(task_id) or _verify_tasks.get(task_id)
    return bool(t) and t.get("state") in _LIVE_STATES


def _cleanup_tasks_locked() -> None:
    """清理任务状态(须持 _task_lock):先删超 1h 的,再按最旧淘汰到容量上限。
    running/waiting_* 的活任务一律跳过(TTL 和容量淘汰都不得删活任务;
    终态任务照常清理),因此清理后容量可能暂时略超 _TASK_MAX。"""
    now = time.time()
    for k in [k for k, ts in _task_ts.items()
              if now - ts > _TASK_TTL_S and not _is_live_locked(k)]:
        _task_ts.pop(k, None)
        _oauth_tasks.pop(k, None)
        _verify_tasks.pop(k, None)
        _task_account.pop(k, None)
    overflow = len(_task_ts) - _TASK_MAX
    if overflow > 0:
        for k in sorted(_task_ts, key=lambda k: _task_ts[k]):
            if overflow <= 0:
                break
            if _is_live_locked(k):
                continue
            _task_ts.pop(k, None)
            _oauth_tasks.pop(k, None)
            _verify_tasks.pop(k, None)
            _task_account.pop(k, None)
            overflow -= 1


def _active_oauth_task(account_key: str) -> str:
    """同账号是否已有进行中的授权任务(running/waiting_*),有则返回其 task_id。
    用于防止重复发起导致并发双 Chrome(须持 _task_lock 调用)。"""
    for tid, owner in _task_account.items():
        if owner == account_key and tid in _oauth_tasks \
                and _oauth_tasks[tid].get("state") in _LIVE_STATES:
            return tid
    return ""


def _put_task(store: dict, task_id: str, payload: dict) -> None:
    """线程安全写任务状态 + 顺带清理(契约 12);写入后容量严格 ≤ _TASK_MAX。"""
    with _task_lock:
        store[task_id] = payload
        _task_ts[task_id] = time.time()
        _cleanup_tasks_locked()


def _state_task(st: dict) -> dict:
    """on_state 通知 → 任务负载(契约 2/4):waiting_code/waiting_manual 就地展示。"""
    return {
        "state": st.get("state") or "running",
        "message": st.get("message") or "",
        "hint": st.get("hint") or "",
        "codeTask": st.get("codeTask") or st.get("code_task") or "",
        "manualUrl": st.get("manualUrl") or st.get("manual_url") or "",
        "login": st.get("login") or "",
    }


def _result_task(r: AuthResult, message: str | None = None) -> dict:
    """AuthResult → 任务负载(契约 4 映射:need_code→waiting_code 等)。"""
    return {
        "state": _AUTH_STATE_TO_TASK.get(getattr(r, "state", ""), "failed"),
        "message": (r.message if message is None else message) or "",
        "hint": getattr(r, "hint", "") or "",
        "codeTask": getattr(r, "code_task", "") or "",
        "manualUrl": getattr(r, "manual_url", "") or "",
        "login": getattr(r, "github_login", "") or "",
    }


def _has_param(fn, name: str) -> bool:
    """authorize/set_manual_code 是否已支持新契约参数(兼容 ALPHA 尚未合入)。"""
    try:
        import inspect
        return name in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _run_authorize(site, account, cfg, credential, headful: bool, task_id: str, on_state):
    """调用 authorize 并按契约 2/3 传入 task_id/on_state(旧签名自动降级)。"""
    kw: dict = {}
    if _has_param(authorize, "task_id"):
        kw["task_id"] = task_id
    if _has_param(authorize, "on_state"):
        kw["on_state"] = on_state
    return authorize(site, account, cfg, credential, headful=headful, **kw)


@app.post("/api/oauth/start")
def oauth_start(body: dict):
    account_key = body.get("accountKey", "")
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")

    # 同账号去重:已有 running/waiting_* 的授权任务直接复用,不再起新线程
    # (否则连点两次授权 = 并发双 Chrome 抢同一账号)
    with _task_lock:
        existing = _active_oauth_task(account_key)
    if existing:
        return {"ok": True, "task": existing, "reused": True,
                "hint": "该账号已有进行中的授权任务,已复用(看原任务状态)"}

    site, acc = found
    clear_cooldown(account_key)               # 手动授权清冷却

    task_id = f"oauth_{uuid.uuid4().hex[:8]}"
    with _task_lock:
        _task_account[task_id] = account_key

    def worker():
        _put_task(_oauth_tasks, task_id,
                  {"state": "running", "message": "headless 授权中…",
                   "hint": "", "codeTask": "", "manualUrl": "", "login": ""})
        try:
            cred = get_credential(account_key)
            r: AuthResult = _run_authorize(
                site, acc, cfg, cred or None, False, task_id,
                lambda st: _put_task(_oauth_tasks, task_id, _state_task(st)))
            # 结束态只在 authorize 返回时写(waiting_* 已由 on_state 就地写入)
            _put_task(_oauth_tasks, task_id, _result_task(r))
            if r.state == "ok":
                # 落盘复用 silent_auth._persist(任一变化即成功)
                from .engine.silent_auth import _persist
                _persist(site, acc, r)
        except Exception as e:
            _put_task(_oauth_tasks, task_id,
                      {"state": "failed", "message": str(e)[:200],
                       "hint": "", "codeTask": "", "manualUrl": "", "login": ""})

    threading.Thread(target=worker, daemon=True, name=f"oauth-{account_key}").start()
    return {"ok": True, "task": task_id, "reused": False}


@app.post("/api/oauth/manual")
def oauth_manual(body: dict):
    """有头浏览器授权:弹可见浏览器,凭据库有账密则自动填充,
    用户自己完成 2FA/设备验证(如邮箱验证码)。
    GitHub 会话存 user_data_dir,之后恢复全自动。"""
    account_key = body.get("accountKey", "")
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")

    # 同账号去重(B-12):headful 与 headless 共用 _oauth_tasks,防并发双 Chrome
    with _task_lock:
        existing = _active_oauth_task(account_key)
    if existing:
        return {"ok": True, "task": existing, "reused": True,
                "hint": "该账号已有进行中的授权任务,已复用(看原任务状态)"}

    site, acc = found
    clear_cooldown(account_key)

    task_id = f"oauthh_{uuid.uuid4().hex[:8]}"
    with _task_lock:
        _task_account[task_id] = account_key

    def worker():
        _put_task(_oauth_tasks, task_id,
                  {"state": "running",
                   "message": "有头授权中:请在弹出的浏览器里完成登录/验证",
                   "hint": "", "codeTask": "", "manualUrl": "", "login": ""})
        try:
            cred = get_credential(account_key)
            r: AuthResult = _run_authorize(
                site, acc, cfg, cred or None, True, task_id,
                lambda st: _put_task(_oauth_tasks, task_id, _state_task(st)))
            _put_task(_oauth_tasks, task_id, _result_task(r))
            if r.state == "ok":
                from .engine.silent_auth import _persist
                _persist(site, acc, r)
        except Exception as e:
            _put_task(_oauth_tasks, task_id,
                      {"state": "failed", "message": str(e)[:200],
                       "hint": "", "codeTask": "", "manualUrl": "", "login": ""})

    threading.Thread(target=worker, daemon=True, name=f"oauth-h-{account_key}").start()
    return {"ok": True, "task": task_id, "reused": False,
            "hint": "浏览器已弹出:账密已自动填充(如有),2FA/邮箱验证码请在授权弹层填入"}


@app.get("/api/oauth/status")
def oauth_status(task: str):
    """任务状态(契约 4):state ∈ running|waiting_code|waiting_manual|ok|failed,
    带 message/hint/codeTask/manualUrl/login。oauth 与 verify 任务共用。"""
    with _task_lock:
        t = _oauth_tasks.get(task) or _verify_tasks.get(task)
    if not t:
        raise HTTPException(404, "任务不存在")
    return {"ok": True, **t}


# 验证探测站回退常量(仅当凭据无绑定站点、cfg 无站点时才用,契约 11)
VERIFY_FALLBACK_SITE = {"key": "__verify__", "name": "凭据验证",
                        "baseUrl": "https://api.justwoker.icu", "checkinType": "newapi"}


def _probe_site_for_credential(cfg: dict, credential_id: str = "") -> dict:
    """选凭据验证的探测站(契约 11):优先该凭据已绑定的任一站点(在
    cfg.sites[].accounts[] 里找 credentialId 匹配),否则 cfg.sites[0],都没有
    才回退 JustDoWork 常量。返回站点副本,用其自身 baseUrl/checkinType。
    """
    sites = cfg.get("sites") or []
    if credential_id:
        for s in sites:
            if any((a.get("credentialId") or "") == credential_id
                   for a in (s.get("accounts") or [])):
                return {**s, "key": s.get("key") or "__verify__"}
    if sites:
        s0 = sites[0]
        return {**s0, "key": s0.get("key") or "__verify__"}
    return dict(VERIFY_FALLBACK_SITE)


@app.post("/api/credentials/verify")
def credentials_verify(body: dict):
    """验证凭据:用凭据已绑定的站点(没有则 cfg.sites[0],再没有才 JustDoWork)作
    探测站,profile 隔离不污染真实账号。
    有密码 ⇒ headless 自验(headful=False,零弹窗);无密码 ⇒ headful=True(契约 7)。
    通过 ⇒ verified=ok(以后复用);失败 ⇒ verified=failed + 原因。
    凭据未保存也可验证:传 username/password/twofa 明文(不落盘,只验一次)。
    body: {id?|username?,password?,twofa?}"""
    from .engine.credentials import mark_verified
    cfg = config.load()
    cid = str(body.get("id", "") or "")
    if cid:
        found_c = next((c for c in (cfg.get("credentials") or [])
                        if c.get("id") == cid), None)
        if not found_c:
            raise HTTPException(404, "凭据不存在")
        try:
            from .service import crypto
            gh = found_c.get("githubUser") or ""
            pw = crypto.decrypt(found_c["password"]) if found_c.get("password") else ""
            tp = crypto.decrypt(found_c["twofa"]) if found_c.get("twofa") else ""
        except Exception:
            raise HTTPException(500, "凭据解密失败")
        label = found_c.get("alias") or gh or cid
    else:
        gh = str(body.get("username", "") or "")
        pw = str(body.get("password", "") or "")
        tp = str(body.get("twofa", "") or "")
        label = gh or "未保存凭据"
        if not gh:
            raise HTTPException(400, "需要 username(未保存模式不落盘)")
        # 无密码的未保存凭据同样允许:走 headful 人工登录验证(契约 7)

    # 契约 7:有密码走 headless 自验;无密码才弹浏览器(headful)
    headful = not pw
    site = _probe_site_for_credential(cfg, cid if cid else "")
    # 探测 profile 用**稳定** key(按凭据/用户名),不用时间戳:
    # 一是复用同一 Chrome profile,二次验证可命中已登录 GitHub 会话(更快);
    # 二是避免每次验证都在 data/profiles/<site>/ 下新建目录导致无限增长。
    if cid:
        probe_key = f"__verify_{cid}"
    else:
        probe_key = "__verify_" + "".join(
            ch if ch.isalnum() else "_" for ch in (gh or "unsaved"))[:40]
    pseudo = {"key": probe_key,
              "alias": f"验证:{label}", "githubAccount": gh}
    credential = {"username": gh, "password": pw, "totpSecret": tp}
    task_id = f"verify_{uuid.uuid4().hex[:8]}"
    start_msg = ("验证中:请在弹出的 Chrome 里完成登录/2FA/邮箱码" if headful
                 else "验证中:后台静默自验(账密自动填充,无需操作)")

    def worker():
        _put_task(_verify_tasks, task_id,
                  {"state": "running", "message": start_msg,
                   "hint": "", "codeTask": "", "manualUrl": "", "login": ""})
        try:
            r: AuthResult = _run_authorize(
                site, pseudo, cfg, credential, headful, task_id,
                lambda st: _put_task(_verify_tasks, task_id, _state_task(st)))
            # 结束态只在 authorize 返回时写;waiting_* 已由 on_state 就地写入。
            # state 映射走契约 4(need_code→waiting_code / need_manual→waiting_manual)
            payload = _result_task(r)
            if r.state == "ok":
                payload["message"] = "验证通过:GitHub 登录成功,以后绑定站点直接复用"
            _put_task(_verify_tasks, task_id, payload)
            # 仅 ok/failed 是最终结论;need_code/need_manual 是"等人工",不算验失败
            if cid and r.state in ("ok", "failed"):
                mark_verified(cid, r.state == "ok", "" if r.state == "ok" else r.message)
        except Exception as e:
            _put_task(_verify_tasks, task_id,
                      {"state": "failed", "message": str(e)[:200],
                       "hint": "", "codeTask": "", "manualUrl": "", "login": ""})
            if cid:
                mark_verified(cid, False, str(e)[:200])

    threading.Thread(target=worker, daemon=True, name=f"verify-{label}").start()
    return {"ok": True, "task": task_id, "headful": headful, "probeSite": site.get("key"),
            "hint": ("Chrome 已弹出:账密已自动填充,2FA/邮箱码请在授权弹层填入" if headful
                     else "已开始后台静默验证(有密码,无需弹浏览器)")}


# 旧路径兼容:放在 /api/credentials/verify 之后注册,否则 FastAPI 按注册顺序
# 会用本动态路由吞掉 /api/credentials/verify(account_key="verify" ⇒ 永远 404)。
@app.post("/api/credentials/{account_key}")
def credentials_save(account_key: str, body: dict):
    """旧路径兼容:为账号写/绑定凭据(自动建全局凭据并引用)。"""
    if not save_credential(
        account_key,
        username=str(body.get("username", "") or ""),
        password=str(body.get("password", "") or ""),
        totp_secret=str(body.get("totpSecret", "") or ""),
    ):
        raise HTTPException(404, "账号不存在或凭据为空")
    return {"ok": True, "hint": "已加密存储(读不回显)"}


@app.post("/api/oauth/totp")
def oauth_totp(body: dict):
    """注入 6 位码(契约 5):接受 {code, task};转发 set_manual_code(code, task)。
    task 可选(缺省空串走默认桶),兼容只传 code 的旧调用。"""
    code = str(body.get("code", "")).strip()
    if not (code.isdigit() and len(code) == 6):
        raise HTTPException(400, "需要 6 位数字码")
    task = str(body.get("task", "") or "")
    if _has_param(set_manual_code, "task_id"):
        set_manual_code(code, task)
    else:
        set_manual_code(code)
    return {"ok": True, "task": task, "hint": "已注入,授权任务会立即使用"}


@app.post("/api/reauth/{account_key}")
def reauth(account_key: str):
    """手动触发静默换凭据(force,清冷却)。"""
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")
    site, acc = found
    clear_cooldown(account_key)
    cred = get_credential(account_key)
    r = exchange(site, acc, cfg, cred or None, force=True)
    return {"ok": r.state == "ok", "state": r.state, "message": r.message}


# 静态 WebUI(原 src/index.html 迁入,P3 打磨)
if STATIC_DIR.exists():
    app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


@app.on_event("startup")
def _start():
    start_scheduler()


@app.get("/")
def index():
    index_html = STATIC_DIR / "index.html"
    if index_html.exists():
        return FileResponse(index_html)
    return JSONResponse({"ok": True, "hint": "WebUI 尚未迁入,API 文档见 /docs"})


def main():
    import uvicorn
    print(f"justsign(py) → http://{HOST}:{PORT}  (docs: /docs)")
    if HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"[警告] 绑定地址 {HOST} 为非回环:服务已对外暴露且无鉴权,风险自负!"
              f"(仅本机使用请勿设置 JUSTSIGN_HOST)")
    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    main()
