"""main.py — FastAPI 入口(P0 最小版)。

P0 范围:/api/health + 静态 WebUI 托管 + 站点/账号只读 API。
P1+ 再挂:checkin / oauth / credentials / scheduler / SSE(见设计文档 §4.3)。

启动:python -m pc.main   (默认 0.0.0.0:7300)
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .engine.checkin import run_checkin
from .engine.site_client import QUOTA_PER_UNIT_DEFAULT, SiteClient
from .service import config, db

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
                **a, "token": _mask(a.get("token")),
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


@app.get("/api/history")
def history():
    return {"ok": True, "data": db.recent_logs(300)}


# 静态 WebUI(原 src/index.html 迁入,P3 打磨)
if STATIC_DIR.exists():
    app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


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
