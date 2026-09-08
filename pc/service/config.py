"""config.py — 配置加载/保存(兼容原 config.json 站点→账号两级结构)。

契约见 docs/设计文档-justsign魔改.md §3.0:
- sites[] = 站点(name/baseUrl/checkinType/stateMethod 等站点 meta)
- site.accounts[] = 账号(token/siteCookie/siteUserId/githubAccount 等凭据字段)
- 顶层 proxy/schedule/UA 引擎设置
"""
from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
CFG_PATH = Path(os.environ.get("JUSTSIGN_CONFIG", ROOT / "config.json"))

DEFAULTS: dict[str, Any] = {
    "proxy": {"enabled": False, "type": "socks5", "host": "127.0.0.1", "port": 10808},
    "UA": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "impersonate": ["chrome", "firefox"],  # 多指纹轮换(§3.2A)
    "schedule": {"enabled": False, "cron": "0 3 * * *"},
    "sites": [],
}

_lock = RLock()


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load() -> dict[str, Any]:
    with _lock:
        if CFG_PATH.exists():
            try:
                raw = json.loads(CFG_PATH.read_text(encoding="utf-8"))
                merged = _deep_merge(DEFAULTS, raw)
                if not isinstance(merged.get("sites"), list):
                    merged["sites"] = []
                return merged
            except (json.JSONDecodeError, OSError):
                pass
        return deepcopy(DEFAULTS)


def save(cfg: dict[str, Any]) -> None:
    with _lock:
        CFG_PATH.write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8"
        )


def site_key_of(base_url: str) -> str:
    """与原版 siteKeyOf 同规则:域名小写、非法字符转 -。"""
    import re

    k = re.sub(r"^https?://", "", str(base_url or "site").lower())
    k = re.sub(r"[^a-z0-9]+", "-", k).strip("-")
    return k or "site"


def find_site(cfg: dict, key: str) -> dict | None:
    return next((s for s in cfg.get("sites", []) if s.get("key") == key), None)


def find_account(cfg: dict, key: str) -> tuple[dict, dict] | None:
    """返回 (site, account);账号 key 全局唯一(与原版一致)。"""
    for s in cfg.get("sites", []):
        for a in s.get("accounts", []) or []:
            if a.get("key") == key:
                return s, a
    return None


def site_meta(cfg: dict, site_key: str, name: str, default: Any = None) -> Any:
    s = find_site(cfg, site_key)
    if not s:
        return default
    meta = s.get("meta") or {}
    return meta.get(name, default)


def put_site_meta(cfg: dict, site_key: str, name: str, value: Any) -> None:
    s = find_site(cfg, site_key)
    if not s:
        return
    meta = s.setdefault("meta", {})
    meta[name] = value
