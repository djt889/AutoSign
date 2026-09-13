"""test_bravo_fixes.py — BRAVO 修复清单回归(B-1/B-5/B-6/B-9/B-11~B-14/B-23)。

- B-1  HOST 默认 127.0.0.1(显式 JUSTSIGN_HOST 才对外)
- B-5  db.seq 进程内单调 + SSE 按 seq 增量(首连回放 20 条,之后只推新条目)
- B-6  config 原子写(临时文件 + os.replace)+ 读失败改存 .bad 回退默认
- B-9  _mask 只显示尾部 4 字符
- B-11 任务/账号 ID 用 uuid 后 8 位(消灭同毫秒碰撞)
- B-12 同账号授权去重(running/waiting_* 复用 task_id,不并发双 Chrome)
- B-13 任务清理(TTL/容量)保护活任务
- B-14 run-all worker 异常兜底写 err 日志
- B-23 settings port 校验(400)+ account_logs urlencode/钳制

不发真实网络与浏览器:monkeypatch main.authorize / silent_auth。
复用 test_api_auth 的环境隔离与 AuthResult 替身。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pc.main as main  # noqa: E402
from pc.tests.test_api_auth import (  # noqa: E402
    _patch_env, _res, _seed_config, _wait_for,
)


@pytest.fixture
def client():
    """TestClient(与 test_api_auth.client 等价;fixture 不跨测试文件共享,须本地定义)。"""
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c


# ---------- B-1 HOST 默认 ----------

@pytest.mark.skipif(bool(os.environ.get("JUSTSIGN_HOST")),
                    reason="环境显式设置了 JUSTSIGN_HOST")
def test_host_defaults_to_loopback():
    """B-1:默认只绑回环,显式设 0.0.0.0 才对外(服务无鉴权)。"""
    assert main.HOST == "127.0.0.1"


# ---------- B-9 _mask 尾部 ----------

def test_mask_shows_tail_only():
    """B-9:只显示尾部 4 字符,不泄露明文前缀。"""
    assert main._mask("ghp_1234567890abcd") == "…abcd"
    assert main._mask("ab") == "…ab"
    assert main._mask("") is None
    assert main._mask(None) is None


# ---------- B-11 ID 碰撞 ----------

def test_ids_use_uuid_suffix(monkeypatch, tmp_path, client):
    """B-11:账号/授权任务 ID 为 <前缀>_<uuid8>,不再是毫秒时间戳。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _seed_config(config, with_credential=False)
    cfg = config.load()
    cfg["sites"][0]["accounts"] = [{"key": "a1", "alias": "主号"}]
    config.save(cfg)

    r = client.post("/api/accounts/save", json={"siteKey": "s1"}).json()
    assert re.fullmatch(r"acc_[0-9a-f]{8}", r["key"])

    monkeypatch.setattr(main, "authorize", lambda *a, **k: _res("ok", "好"))
    r2 = client.post("/api/oauth/start", json={"accountKey": "a1"}).json()
    assert re.fullmatch(r"oauth_[0-9a-f]{8}", r2["task"])


def test_accounts_save_keys_unique_across_calls(monkeypatch, tmp_path, client):
    """B-11:连发 50 个建号请求 key 全唯一(时间戳方案同毫秒必撞)。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _seed_config(config, with_credential=False)
    keys = [client.post("/api/accounts/save", json={"siteKey": "s1"}).json()["key"]
            for _ in range(50)]
    assert len(set(keys)) == 50


# ---------- B-12 同账号授权去重 ----------

def test_oauth_start_reuses_active_task_for_same_account(monkeypatch, tmp_path, client):
    """B-12:同账号已有 running 任务时再发起 → 返回原 task_id + reused=true,
    不起新线程;不同账号不受影响;任务结束后可重新发起。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _seed_config(config, with_credential=False)
    cfg = config.load()
    cfg["sites"][0]["accounts"] = [{"key": "a1"}, {"key": "a2"}]
    config.save(cfg)

    release = threading.Event()
    entered = threading.Event()

    def fake_authorize(site, account, cfg, credential=None, headful=False,
                       task_id="", on_state=None):
        entered.set()
        release.wait(5)
        return _res("ok", "好")

    monkeypatch.setattr(main, "authorize", fake_authorize)

    r1 = client.post("/api/oauth/start", json={"accountKey": "a1"}).json()
    assert r1["reused"] is False
    assert entered.wait(5)                       # worker 已进入 authorize
    assert main._oauth_tasks[r1["task"]]["state"] == "running"

    # 同账号再发起 → 复用
    r2 = client.post("/api/oauth/start", json={"accountKey": "a1"}).json()
    assert r2["reused"] is True and r2["task"] == r1["task"]

    # 有头入口同样复用(headless/headful 共用去重池,防双 Chrome)
    r2h = client.post("/api/oauth/manual", json={"accountKey": "a1"}).json()
    assert r2h["reused"] is True and r2h["task"] == r1["task"]

    # 不同账号 → 新任务
    r3 = client.post("/api/oauth/start", json={"accountKey": "a2"}).json()
    assert r3["reused"] is False and r3["task"] != r1["task"]

    # 放行,任务结束(终态)→ 可重新发起
    release.set()
    assert _wait_for(lambda: (main._oauth_tasks.get(r1["task"]) or {}).get("state") == "ok")
    r4 = client.post("/api/oauth/start", json={"accountKey": "a1"}).json()
    assert r4["reused"] is False and r4["task"] != r1["task"]


# ---------- B-13 清理保护活任务 ----------

def test_cleanup_ttl_preserves_live_tasks(monkeypatch, tmp_path):
    """B-13:超 1h 的活任务(running)不被 TTL 清理;终态任务照常清。"""
    _patch_env(monkeypatch, tmp_path)
    main._put_task(main._oauth_tasks, "old_live", {"state": "running"})
    main._put_task(main._oauth_tasks, "old_done", {"state": "ok"})
    stale = time.time() - (main._TASK_TTL_S + 10)
    main._task_ts["old_live"] = stale
    main._task_ts["old_done"] = stale
    main._put_task(main._oauth_tasks, "new", {"state": "running"})   # 触发清理
    assert "old_live" in main._oauth_tasks and "old_live" in main._task_ts
    assert "old_done" not in main._oauth_tasks and "old_done" not in main._task_ts
    assert "new" in main._oauth_tasks


def test_cleanup_capacity_preserves_live_tasks(monkeypatch, tmp_path):
    """B-13:容量淘汰最旧时跳过活任务(waiting_* 也不得删)。"""
    _patch_env(monkeypatch, tmp_path)
    main._put_task(main._oauth_tasks, "live", {"state": "waiting_code"})
    for i in range(main._TASK_MAX):
        main._put_task(main._oauth_tasks, f"t{i}", {"state": "ok"})
    main._put_task(main._oauth_tasks, "extra", {"state": "ok"})
    assert "live" in main._oauth_tasks and "live" in main._task_ts
    assert "t0" not in main._oauth_tasks         # 最旧终态任务被淘汰
    assert "extra" in main._oauth_tasks


def test_cleanup_ttl_preserves_waiting_manual(monkeypatch, tmp_path):
    """B-13:waiting_manual(等人工输入)超 TTL 同样保护。"""
    _patch_env(monkeypatch, tmp_path)
    main._put_task(main._verify_tasks, "wm", {"state": "waiting_manual"})
    main._task_ts["wm"] = time.time() - (main._TASK_TTL_S + 10)
    main._put_task(main._verify_tasks, "x", {"state": "ok"})
    assert "wm" in main._verify_tasks


# ---------- B-14 run-all worker 容错 ----------

def test_run_all_worker_catches_exception(monkeypatch, tmp_path, client):
    """B-14:run_all_once 抛异常时 worker 兜底,写 err 日志,HTTP 仍 200。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)

    def boom(trigger="manual"):
        raise RuntimeError("boom-runall")

    monkeypatch.setattr(main, "run_all_once", boom)
    assert client.post("/api/run-all").status_code == 200
    assert _wait_for(lambda: any(
        l.get("event") == "run-all" and l.get("level") == "err"
        and "boom-runall" in str((l.get("detail") or {}).get("error", ""))
        for l in db.recent_logs(50)))


# ---------- B-23 port 校验 + account_logs 钳制 ----------

def test_settings_save_port_validation(monkeypatch, tmp_path, client):
    """B-23:proxy.port 非整数/越界 → 400 且不落盘;合法值正常保存。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    config.save(config.load())
    bad_bodies = [{"proxy": {"port": "abc"}}, {"proxy": {"port": 70000}},
                  {"proxy": {"port": 0}}, {"proxy": {"port": -1}}]
    for body in bad_bodies:
        assert client.post("/api/settings/save", json=body).status_code == 400, body
    assert (config.load()["proxy"] or {}).get("port") != "abc"   # 非法值未落盘
    ok = client.post("/api/settings/save",
                     json={"proxy": {"enabled": True, "host": "127.0.0.1", "port": 8118}})
    assert ok.status_code == 200
    assert config.load()["proxy"]["port"] == 8118


def test_account_logs_urlencode_and_clamp(monkeypatch, tmp_path, client):
    """B-23:category 经 urlencode(含中文/& 不会拆坏 query);limit/page 钳制 1-200。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    _seed_config(config, with_credential=False)
    cfg = config.load()
    cfg["sites"][0]["accounts"] = [{"key": "a1"}]
    config.save(cfg)

    from pc.engine import silent_auth as sa
    captured = {}

    class _R:
        status = 200
        data = {"data": {"list": []}}
        blocked_by_waf = False
        error = ""

    def fake_call(site, acc, c, method, path, **kw):
        captured["path"] = path
        return _R()

    monkeypatch.setattr(sa, "call_with_auto_reauth", fake_call)

    r = client.get("/api/logs/a1",
                   params={"category": "系统&x=1", "limit": 9999, "page": -5})
    assert r.status_code == 200
    assert "category=%E7%B3%BB%E7%BB%9F%26x%3D1" in captured["path"]
    assert "limit=200" in captured["path"] and "page=1" in captured["path"]

    captured.clear()
    client.get("/api/logs/a1", params={"limit": 0, "page": 0})
    assert "limit=1" in captured["path"] and "page=1" in captured["path"]


# ---------- B-5 db.seq + SSE 增量 ----------

def test_db_seq_monotonic_and_max_seq(monkeypatch, tmp_path):
    """B-5:append_log 写入进程内单调 seq;max_seq 返回当前值;
    _restore_seq 从文件恢复基线(重启不回退)。"""
    from pc.service import db
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "_p", lambda name: tmp_path / name)
    db.append_log("s1", "a1", "e1")
    db.append_log("s1", "a1", "e2", level="err")
    logs = db.recent_logs(10)                    # 最新在前
    assert logs[0]["seq"] == logs[1]["seq"] + 1
    assert db.max_seq() == logs[0]["seq"]
    assert db._restore_seq() == logs[0]["seq"]   # 重启后基线恢复


def test_events_stream_seq_increment(monkeypatch, tmp_path):
    """B-5:SSE 首连回放最近 20 条,之后按 seq 增量只推新条目(不再按条数差)。"""
    from pc.service import db
    _patch_env(monkeypatch, tmp_path)
    for i in range(25):
        db.append_log("s1", "a1", f"e{i}", None)

    async def _run():
        resp = await main.events()
        gen = resp.body_iterator
        got = []
        async for chunk in gen:                  # 首屏 20 条
            got.append(json.loads(chunk.removeprefix("data: ").strip()))
            if len(got) >= 20:
                break
        db.append_log("s1", "a1", "e-new", None)
        got.append(json.loads(                   # 增量:只推新的一条
            (await gen.__anext__()).removeprefix("data: ").strip()))
        await gen.aclose()
        return got

    got = asyncio.run(_run())
    seqs = [g["seq"] for g in got]
    assert len(seqs) == 21
    assert seqs[:20] == list(range(seqs[0], seqs[0] + 20))   # 首屏 20 条连续
    assert seqs[20] == seqs[19] + 1                          # 增量恰好是下一条
    assert got[20]["event"] == "e-new"


# ---------- B-6 config 原子写 + .bad 保护 ----------

def test_config_atomic_write_roundtrip(monkeypatch, tmp_path):
    """B-6:save 经临时文件 + os.replace,读回一致且无 .tmp 残留。"""
    from pc.service import config
    monkeypatch.setattr(config, "CFG_PATH", tmp_path / "config.json")
    cfg = config.load()
    cfg["sites"].append({"key": "s1", "baseUrl": "https://x.com", "accounts": []})
    config.save(cfg)
    raw = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert any(s["key"] == "s1" for s in raw["sites"])
    assert not list(tmp_path.glob("config.json.*.tmp"))


def test_config_corrupt_file_renamed_bad(monkeypatch, tmp_path):
    """B-6:load 读到坏 JSON → 回退默认,且原文件改名 .bad 保留现场。"""
    from pc.service import config
    cfg_path = tmp_path / "config.json"
    monkeypatch.setattr(config, "CFG_PATH", cfg_path)
    cfg_path.write_text("{not-json", encoding="utf-8")
    assert config.load() == config.DEFAULTS
    bad = tmp_path / "config.json.bad"
    assert bad.exists() and bad.read_text(encoding="utf-8") == "{not-json"
    assert not cfg_path.exists()


def test_config_update_after_corrupt_keeps_bad_backup(monkeypatch, tmp_path):
    """B-6:坏文件 + 用户主动写(update)→ 基于默认值继续,.bad 保留可恢复。"""
    from pc.service import config
    cfg_path = tmp_path / "config.json"
    monkeypatch.setattr(config, "CFG_PATH", cfg_path)
    cfg_path.write_text("{corrupt", encoding="utf-8")

    def _mut(c):
        c["sites"].append({"key": "s1", "accounts": []})

    config.update(_mut)
    assert (tmp_path / "config.json.bad").read_text(encoding="utf-8") == "{corrupt"
    assert config.load()["sites"][0]["key"] == "s1"


def test_settings_save_recovers_from_corrupt_config(monkeypatch, tmp_path, client):
    """B-6 端到端:手写坏 config.json 后调写端点 → 200,.bad 保留,配置恢复可读。"""
    config, db, crypto = _patch_env(monkeypatch, tmp_path)
    (config.CFG_PATH).write_text("{broken-json", encoding="utf-8")
    r = client.post("/api/settings/save",
                    json={"proxy": {"enabled": False, "host": "127.0.0.1", "port": 10808}})
    assert r.status_code == 200
    assert config.CFG_PATH.with_name("config.json.bad").exists()
    loaded = config.load()
    assert loaded["proxy"]["port"] == 10808      # 基于回退默认 + 本次修改
