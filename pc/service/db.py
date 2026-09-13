"""db.py — 日志/快照读写(JSON,兼容原 data/logs.json 格式)。

原版格式:{time, site, account, event, detail} 数组,上限 10000 条。
本模块追加 level 字段(info/err)与 seq 字段(进程内单调递增,SSE 增量基线,
重启时从现有文件恢复基线避免 seq 回退),其余字段名保持不变,旧文件可直接读。
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import ROOT

DATA_DIR = Path(os.environ.get("JUSTSIGN_DATA", ROOT / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()
MAX_LOGS = 10_000


def _p(name: str) -> Path:
    return DATA_DIR / name


def load(name: str) -> Any:
    try:
        return json.loads(_p(name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _restore_seq() -> int:
    """启动时从现有 logs.json 恢复 seq 基线(否则重启后 seq 从 1 重新计数,
    会撞上旧条目的 seq,SSE 按 seq 增量续传就会漏推/错序)。"""
    m = 0
    for e in (load("logs.json") or []):
        if isinstance(e, dict) and isinstance(e.get("seq"), int):
            m = max(m, e["seq"])
    return m


_seq = _restore_seq()


def save(name: str, data: Any) -> None:
    fp = _p(name)
    tmp = fp.with_suffix(fp.suffix + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(fp)


def append_log(
    site: str,
    account: str,
    event: str,
    detail: Any = None,
    level: str = "info",
) -> None:
    global _seq
    with _lock:
        _seq += 1
        entry = {
            "time": datetime.now(timezone.utc).isoformat(),
            "site": site,
            "account": account,
            "event": event,
            "detail": detail,
            "level": level,
            "seq": _seq,
        }
        logs = load("logs.json") or []
        logs.append(entry)
        if len(logs) > MAX_LOGS:
            logs = logs[len(logs) - MAX_LOGS:]
        save("logs.json", logs)


def max_seq() -> int:
    """当前进程内日志 seq(单调递增);SSE 增量拉取的基线。"""
    with _lock:
        return _seq


def recent_logs(limit: int = 300) -> list[dict]:
    logs = load("logs.json") or []
    return list(reversed(logs[-limit:]))
