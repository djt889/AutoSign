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

# 内置四站(原 Catalog.java 同源;2026-09-08 实测 /api/status 全部 200)。
# 仅 setup 初始化时装入,load() 不强制注入——用户删除后不被复活。
BUILTIN_SITES: list[dict[str, Any]] = [
    {
        "key": "agentrouter-org", "name": "AgentRouter",
        "baseUrl": "https://agentrouter.org", "checkinType": "login",
        "affUrl": "https://agentrouter.org/register?aff=nc7C",
        "note": "注册 $175 + 每日登录 $25;login 型(checkin_enabled 缺失,无签到接口)",
        "accounts": [],
    },
    {
        "key": "api-justwoker-icu", "name": "JustDoWork",
        "baseUrl": "https://api.justwoker.icu", "checkinType": "newapi",
        "affUrl": "https://api.justwoker.icu/sign-up?aff=wFQu",
        "note": "注册 $90 + 每日签到 $20;newapi 型,Turnstile 开启",
        "accounts": [],
    },
    {
        "key": "gorouter-app", "name": "GoRouter",
        "baseUrl": "https://gorouter.app", "checkinType": "login",
        "affUrl": "https://gorouter.app/sign-up?aff=Dr35",
        "note": "注册 $70 + 每日登录 $10;Turnstile 开启",
        "accounts": [],
    },
    {
        "key": "kktoken-cc", "name": "KKtoken AI",
        "baseUrl": "https://kktoken.cc", "checkinType": "newapi",
        "affUrl": "https://kktoken.cc/sign-up?aff=BpDr",
        "note": "注册 $75 + 每日签到 $25;newapi 型,Turnstile 开启",
        "accounts": [],
    },
]


def setup_builtin() -> dict[str, Any]:
    """初始化:装入内置四站。

    已存在的 key 跳过;用户主动删除过的记入 cfg['removedBuiltin'] 块名单,
    再次 setup 不复活(与原版「内置站与自定义站完全平权」语义一致)。
    """
    cfg = load()
    cfg.setdefault("removedBuiltin", [])
    keys = {s.get("key") for s in cfg.get("sites", [])}
    removed = set(cfg["removedBuiltin"])
    for b in BUILTIN_SITES:
        if b["key"] in keys or b["key"] in removed:
            continue
        cfg["sites"].append(dict(b))
    save(cfg)
    return cfg


def mark_builtin_removed(cfg: dict[str, Any], site_key: str) -> None:
    """删除站点时调用:内置站记入块名单,防止下次 setup 复活。"""
    if any(b["key"] == site_key for b in BUILTIN_SITES):
        removed = cfg.setdefault("removedBuiltin", [])
        if site_key not in removed:
            removed.append(site_key)

_lock = RLock()


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _merge_valid(raw: dict) -> dict:
    merged = _deep_merge(DEFAULTS, raw)
    if not isinstance(merged.get("sites"), list):
        merged["sites"] = []
    return merged


def _read_cfg() -> dict | None:
    """读配置文件;读失败(JSONDecodeError/OSError)时先把原文件改名为
    <config>.bad 保留现场(可人工恢复),再返回 None 由调用方回退默认值——
    绝不静默把"瞬时读取失败"变成对原数据的覆盖。"""
    if not CFG_PATH.exists():
        return None
    try:
        return _merge_valid(json.loads(CFG_PATH.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError):
        try:
            os.replace(str(CFG_PATH), str(CFG_PATH) + ".bad")
        except OSError:
            pass        # 改名失败(文件被占用等)则原文件保留,下次读再试
        return None


def _atomic_write(cfg: dict[str, Any]) -> None:
    """临时文件 + os.replace 原子落盘(与 db.save 同法):进程中断/并发写
    不会留下半个 config.json。"""
    tmp = Path(str(CFG_PATH) + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(str(tmp), str(CFG_PATH))


def load() -> dict[str, Any]:
    with _lock:
        cfg = _read_cfg()
        return deepcopy(cfg) if cfg is not None else deepcopy(DEFAULTS)


def save(cfg: dict[str, Any]) -> None:
    with _lock:
        _atomic_write(cfg)


def update(mutator) -> dict[str, Any]:
    """原子读-改-写事务:整个 load→mutator→save 在锁内完成。

    并发签到/刷新/授权会各自 load→改→save,非原子时后写覆盖先写,
    实测并发新增 90 条只落盘 34 条(账号被吞 → 前端拿旧 key 报"账号不存在")。
    mutator(cfg) 就地修改 cfg;返回修改后的 cfg。
    读失败时原文件保留为 <config>.bad,基于默认值继续(用户主动写操作)。
    """
    with _lock:
        cfg = _read_cfg() or deepcopy(DEFAULTS)
        result = mutator(cfg)
        _atomic_write(cfg)
        return result if isinstance(result, dict) else cfg


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
