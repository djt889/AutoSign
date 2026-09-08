"""scheduler.py — P4 定时调度(APScheduler,Asia/Shanghai)。

动作(契约 §11 P4):
- newapi 型:完整签到流程(前置判定 → POST → 两级 Turnstile,失败报错不转人工)
- login 型:强制静默重登领取(last_login_time 判已领)
- 全账号串行,单账号失败不阻断后续;全部完成后写汇总日志
"""
from __future__ import annotations

import threading
from datetime import datetime

from . import config as config_svc
from . import db
from ..engine.checkin import run_checkin
from ..engine.silent_auth import ensure_token


def run_all_once(trigger: str = "manual") -> dict:
    """所有已授权账号串行跑一轮;返回汇总。同进程内互斥(防手动+定时撞车)。"""
    with _run_lock:
        cfg = config_svc.load()
        results = []
        for site in cfg.get("sites", []):
            for acc in site.get("accounts") or []:
                if not (acc.get("token") or acc.get("siteCookie")):
                    continue          # 未授权账号跳过
                try:
                    # token 即将过期的先静默换新(等 401 兜底也行,这里提前做)
                    ensure_token(site, acc, cfg)
                    rep = run_checkin(site, acc, cfg)
                    results.append({
                        "account": acc["key"], "site": site["key"],
                        "state": rep.state, "message": rep.message[:80],
                    })
                except Exception as e:
                    db.append_log(site["key"], acc["key"], "run-all",
                                  {"error": str(e)[:120]}, "err")
                    results.append({
                        "account": acc["key"], "site": site["key"],
                        "state": "failed", "message": str(e)[:80],
                    })
        done = sum(1 for r in results if r["state"] in ("done", "already", "skipped"))
        summary = {
            "trigger": trigger, "total": len(results), "ok": done,
            "failed": len(results) - done, "at": datetime.now().isoformat(timespec="seconds"),
        }
        db.append_log("*", "*", "run-all", summary, "info" if done == len(results) else "err")
        return summary


_run_lock = threading.Lock()

# ---------------- APScheduler ----------------

_scheduler = None


def _cron_minute_hour(time_str: str) -> tuple[int, int]:
    try:
        hh, mm = time_str.strip().split(":")
        return int(hh), int(mm)
    except Exception:
        return 9, 5       # 默认 09:05(错开整点 WAF 高峰)


def start_scheduler() -> None:
    """按 config.schedule 启动/重启调度(每日一次,Asia/Shanghai)。"""
    global _scheduler
    cfg = config_svc.load()
    sch = cfg.get("schedule") or {}

    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:
            pass
        _scheduler = None

    if not sch.get("enabled"):
        return

    from apscheduler.schedulers.background import BackgroundScheduler
    hh, mm = _cron_minute_hour(str(sch.get("time", "09:05")))
    _scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    _scheduler.add_job(
        lambda: run_all_once(trigger="cron"),
        trigger="cron", hour=hh, minute=mm,
        id="daily-checkin", replace_existing=True,
        misfire_grace_time=3600,        # 错过(服务器重启等)1h 内补跑
    )
    _scheduler.start()
    db.append_log("*", "*", "scheduler",
                  {"enabled": True, "time": f"{hh:02d}:{mm:02d}", "tz": "Asia/Shanghai"})


def scheduler_status() -> dict:
    if _scheduler is None:
        return {"enabled": False}
    try:
        job = _scheduler.get_job("daily-checkin")
        return {
            "enabled": True,
            "time": str(job.next_run_time.strftime("%H:%M")) if job else "?",
            "next": str(job.next_run_time) if job else None,
        }
    except Exception:
        return {"enabled": True}
