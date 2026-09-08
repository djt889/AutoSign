"""main.py — FastAPI 入口(P0 最小版)。

P0 范围:/api/health + 静态 WebUI 托管 + 站点/账号只读 API。
P1+ 再挂:checkin / oauth / credentials / scheduler / SSE(见设计文档 §4.3)。

启动:python -m pc.main   (默认 0.0.0.0:7300)
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .engine.checkin import run_checkin
from .engine.credentials import get_credential, save_credential
from .engine.oauth_flow import AuthResult, authorize, set_manual_code
from .engine.site_client import QUOTA_PER_UNIT_DEFAULT, SiteClient
from .engine.silent_auth import clear_cooldown, exchange
from .service import config, db
from .service.scheduler import run_all_once, scheduler_status, start_scheduler

app = FastAPI(title="justsign", version="0.1.0-py")

STATIC_DIR = Path(__file__).resolve().parent / "web" / "static"
HOST = os.environ.get("JUSTSIGN_HOST", "0.0.0.0")
PORT = int(os.environ.get("JUSTSIGN_PORT", "7300"))


def _mask(token: str | None) -> str | None:
    return (token[:8] + "…") if token else None


def _mask_site(s: dict) -> dict:
    out = dict(s)
    out["accounts"] = [
        {**a, "token": _mask(a.get("token"))} for a in (s.get("accounts") or [])
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
            flat.append({
                **{k: v for k, v in a.items() if k != "encCredential"},
                "token": _mask(a.get("token")),
                "siteCookie": _mask(a.get("siteCookie")),
                "encCredential": bool(a.get("encCredential")),
                "checkinType": s.get("checkinType"),
                "siteKey": s["key"], "siteName": s.get("name", s["key"]),
            })
    return {"ok": True, "tokens": flat}


@app.get("/api/status/{account_key}")
def account_status(account_key: str):
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")
    site, acc = found
    cl = SiteClient(site, acc, cfg)
    self_r = cl.self_info()
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
    }
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
    cfg = config.load()
    if isinstance(body.get("schedule"), dict):
        s = body["schedule"]
        cfg["schedule"] = {
            "enabled": bool(s.get("enabled")),
            "time": str(s.get("time") or "09:05"),
        }
    if isinstance(body.get("proxy"), dict):
        p = body["proxy"]
        cfg["proxy"] = {
            "enabled": bool(p.get("enabled")), "type": "socks5",
            "host": str(p.get("host") or "127.0.0.1"),
            "port": int(p.get("port") or 10808),
        }
    config.save(cfg)
    start_scheduler()          # 保存即生效(重启或停用)
    db.append_log("*", "*", "settings-save",
                  {"schedule": cfg.get("schedule"), "proxyEnabled": (cfg.get("proxy") or {}).get("enabled")})
    return {"ok": True}


@app.post("/api/run-all")
def run_all():
    """立即对所有已授权账号串行跑一轮(手动触发,与 cron 同一入口)。"""
    def worker():
        run_all_once(trigger="manual")
    threading.Thread(target=worker, daemon=True, name="run-all").start()
    return {"ok": True, "message": "已触发(后台串行执行,看实时日志)"}


@app.get("/api/events")
async def events():
    """SSE 实时日志流:订阅 db 追加,断线由前端 EventSource 自动重连。"""
    import asyncio
    from fastapi.responses import StreamingResponse

    async def gen():
        last_idx = 0
        while True:
            logs = db.recent_logs(300)
            if len(logs) > 0:
                # recent_logs 最新在前;发送比上次多的部分
                new = logs[:max(0, len(logs) - last_idx)] if last_idx else logs[:20]
                for l in reversed(new):
                    yield f"data: {json.dumps(l, ensure_ascii=False)}\n\n"
                last_idx = len(logs)
            await asyncio.sleep(2)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
    cfg = config.load()
    if body.get("key"):
        s = next((x for x in cfg["sites"] if x["key"] == body["key"]), None)
        if not s:
            raise HTTPException(404, "站点不存在")
        s["name"] = body.get("name") or s.get("name")
        s["baseUrl"] = base_url
        s["checkinType"] = checkin_type
    else:
        key = config.site_key_of(base_url)
        if any(x["key"] == key for x in cfg["sites"]):
            raise HTTPException(409, "该站点已存在(按地址识别)")
        cfg["sites"].append({
            "key": key, "name": body.get("name") or key,
            "baseUrl": base_url, "checkinType": checkin_type, "accounts": [],
        })
    config.save(cfg)
    db.append_log(body.get("key") or key, "*", "site-save", {"baseUrl": base_url})
    return {"ok": True, "sites": [_mask_site(s) for s in cfg["sites"]]}


@app.delete("/api/sites/{site_key}")
def sites_delete(site_key: str):
    cfg = config.load()
    before = len(cfg["sites"])
    cfg["sites"] = [s for s in cfg["sites"] if s["key"] != site_key]
    if len(cfg["sites"]) == before:
        raise HTTPException(404, "站点不存在")
    config.mark_builtin_removed(cfg, site_key)     # 内置站删除后不复活
    config.save(cfg)
    db.append_log(site_key, "*", "site-delete", None)
    return {"ok": True}


@app.post("/api/accounts/save")
def accounts_save(body: dict):
    cfg = config.load()
    site = next((s for s in cfg["sites"] if s["key"] == body.get("siteKey")), None)
    if not site:
        raise HTTPException(400, "siteKey 无效")
    site.setdefault("accounts", [])
    key = body.get("key") or f"acc_{int(time.time() * 1000)}"
    acc = next((a for a in site["accounts"] if a["key"] == key), None)
    if not acc:
        acc = {"key": key, "alias": body.get("alias") or key}
        site["accounts"].append(acc)
    if body.get("alias"):
        acc["alias"] = str(body["alias"]).strip()
    for f in ("githubAccount", "token", "siteCookie", "siteUserId"):
        if body.get(f) is not None:
            acc[f] = body[f]
    acc["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    config.save(cfg)
    db.append_log(site["key"], key, "account-save", {"hasToken": bool(acc.get("token"))})
    return {"ok": True, "key": key}


@app.delete("/api/accounts/{account_key}")
def accounts_delete(account_key: str):
    cfg = config.load()
    removed = False
    for s in cfg["sites"]:
        n = len(s.get("accounts") or [])
        s["accounts"] = [a for a in (s.get("accounts") or []) if a["key"] != account_key]
        if len(s["accounts"]) < n:
            removed = True
    if not removed:
        raise HTTPException(404, "账号不存在")
    config.save(cfg)
    db.append_log("*", account_key, "account-delete", None)
    return {"ok": True}


# ---------- 凭据库 ----------

@app.post("/api/credentials/{account_key}")
def credentials_save(account_key: str, body: dict):
    if not save_credential(
        account_key,
        username=str(body.get("username", "") or ""),
        password=str(body.get("password", "") or ""),
        totp_secret=str(body.get("totpSecret", "") or ""),
    ):
        raise HTTPException(404, "账号不存在或凭据为空")
    return {"ok": True, "hint": "已加密存储(读不回显)"}


# ---------- OAuth 授权(方式 A headless;长任务异步句柄) ----------

_oauth_tasks: dict[str, dict] = {}
_task_lock = threading.Lock()


@app.post("/api/oauth/start")
def oauth_start(body: dict):
    account_key = body.get("accountKey", "")
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")
    site, acc = found
    clear_cooldown(account_key)               # 手动授权清冷却

    task_id = f"oauth_{int(time.time() * 1000)}"

    def worker():
        with _task_lock:
            _oauth_tasks[task_id] = {"state": "running", "message": "headless 授权中…"}
        try:
            cred = get_credential(account_key)
            r: AuthResult = authorize(site, acc, cfg, cred or None)
            with _task_lock:
                _oauth_tasks[task_id] = {
                    "state": r.state, "message": r.message,
                    "manualUrl": r.manual_url,
                    "login": r.github_login,
                }
            if r.state == "ok":
                # 落盘复用 silent_auth._persist(任一变化即成功)
                from .engine.silent_auth import _persist
                _persist(site, acc, r)
        except Exception as e:
            with _task_lock:
                _oauth_tasks[task_id] = {"state": "failed", "message": str(e)[:200]}

    threading.Thread(target=worker, daemon=True, name=f"oauth-{account_key}").start()
    return {"ok": True, "task": task_id}


@app.post("/api/oauth/headful")
def oauth_headful(body: dict):
    """方式 B 兜底:弹服务器可见浏览器,用户现场登录 GitHub 一次,
    会话存 user_data_dir,之后恢复全自动(headless)。"""
    account_key = body.get("accountKey", "")
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")
    site, acc = found
    clear_cooldown(account_key)

    task_id = f"oauth-h_{int(time.time() * 1000)}"

    def worker():
        with _task_lock:
            _oauth_tasks[task_id] = {"state": "running",
                                     "message": "有头授权中:请在弹出的浏览器里登录 GitHub 并完成授权"}
        try:
            cred = get_credential(account_key)
            r: AuthResult = authorize(site, acc, cfg, cred or None, headful=True)
            with _task_lock:
                _oauth_tasks[task_id] = {
                    "state": r.state, "message": r.message,
                    "manualUrl": r.manual_url, "login": r.github_login,
                }
            if r.state == "ok":
                from .engine.silent_auth import _persist
                _persist(site, acc, r)
        except Exception as e:
            with _task_lock:
                _oauth_tasks[task_id] = {"state": "failed", "message": str(e)[:200]}

    threading.Thread(target=worker, daemon=True, name=f"oauth-h-{account_key}").start()
    return {"ok": True, "task": task_id, "hint": "浏览器已弹出,完成后自动落盘凭据"}


@app.post("/api/oauth/manual")
def oauth_manual(body: dict):
    """手动登录授权模式(给不存密码/2FA 的账号):
    弹可见浏览器,用户自己完成 GitHub 登录+2FA+授权,
    登录态存 user_data_dir —— 之后静默换凭据全走已存会话,零凭据存储。
    """
    account_key = body.get("accountKey", "")
    cfg = config.load()
    found = config.find_account(cfg, account_key)
    if not found:
        raise HTTPException(404, "账号不存在")
    site, acc = found
    clear_cooldown(account_key)

    task_id = f"oauth-m_{int(time.time() * 1000)}"

    def worker():
        with _task_lock:
            _oauth_tasks[task_id] = {"state": "running",
                                     "message": "手动授权中:请在弹出的浏览器里完成 GitHub 登录(密码/2FA 由你自己输入)"}
        try:
            # credential=None:绝不自动填充;用户全手动,但 GitHub 会话仍持久化
            r: AuthResult = authorize(site, acc, cfg, None, headful=True)
            with _task_lock:
                _oauth_tasks[task_id] = {
                    "state": r.state, "message": r.message,
                    "manualUrl": r.manual_url, "login": r.github_login,
                }
            if r.state == "ok":
                from .engine.silent_auth import _persist
                _persist(site, acc, r)
        except Exception as e:
            with _task_lock:
                _oauth_tasks[task_id] = {"state": "failed", "message": str(e)[:200]}

    threading.Thread(target=worker, daemon=True, name=f"oauth-m-{account_key}").start()
    return {"ok": True, "task": task_id,
            "hint": "浏览器已弹出;登录一次后 GitHub 会话持久化,之后全自动"}


@app.get("/api/oauth/status")
def oauth_status(task: str):
    with _task_lock:
        t = _oauth_tasks.get(task)
    if not t:
        raise HTTPException(404, "任务不存在")
    return {"ok": True, **t}


@app.post("/api/oauth/totp")
def oauth_totp(body: dict):
    """实时注入 2FA 码(有头模式:手机 App 上当前 6 位码,30s 有效)。"""
    code = str(body.get("code", "")).strip()
    if not (code.isdigit() and len(code) == 6):
        raise HTTPException(400, "需要 6 位数字码")
    set_manual_code(code)
    return {"ok": True, "hint": "已注入,授权任务会立即使用"}


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
    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    main()
