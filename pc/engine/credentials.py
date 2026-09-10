"""credentials.py — 全局账号凭据库(对齐原版 v0.2.0 模型)。

config.json 顶层 credentials[] = { id, alias, githubUser, siteAccount,
                                   password(enc), twofa(enc), note }
- 与站点解耦:同一 GitHub 账号只存一条(githubUser 去重)
- 站点下账号只存 credentialId 引用;密码/2FA 加密(AES-256-GCM)
- TOTP 码 pyotp 现场生成

读取兼容:账号有 credentialId 用凭据库;否则回退旧版 encCredential 内嵌格式。
"""
from __future__ import annotations

import json
from typing import Any

from ..service import config as config_svc
from ..service import crypto


def _load_creds(cfg: dict) -> list[dict]:
    return cfg.get("credentials") or []


def _find(cfg: dict, cid: str) -> dict | None:
    return next((c for c in _load_creds(cfg) if c.get("id") == cid), None)


def list_credentials(secrets: bool = False) -> list[dict]:
    """凭据列表(默认隐藏 password/twofa 密文细节,仅返回是否配置)。

    附带 verified 状态(见 verify 流程):
    - unverified: 从未验证过
    - ok: 上次验证通过(含验证时间 verified_at)
    - stale: 7 天前的验证已过期,建议重验
    - failed: 上次验证失败(含失败原因 verify_error)
    """
    import time as _time
    cfg = config_svc.load()
    out = []
    for c in _load_creds(cfg):
        item = {
            "id": c.get("id"), "alias": c.get("alias") or c.get("githubUser") or c.get("id"),
            "githubUser": c.get("githubUser") or "", "siteAccount": c.get("siteAccount") or "",
            "note": c.get("note") or "",
            "hasPassword": bool(c.get("password")),
            "hasTwofa": bool(c.get("twofa")),
            "verified": c.get("verified") or "unverified",
            "verifiedAt": c.get("verifiedAt") or "",
            "verifyError": c.get("verifyError") or "",
        }
        if item["verified"] == "ok" and item["verifiedAt"]:
            try:
                age_days = (_time.time() - float(item["verifiedAt"])) / 86400
                if age_days > 7:
                    item["verified"] = "stale"
            except (TypeError, ValueError):
                pass
        out.append(item)
    return out


def mark_verified(credential_id: str, ok: bool, error: str = "") -> bool:
    """写验证结果:ok ⇒ verified=ok + verifiedAt=now;失败 ⇒ verified=failed + 原因。"""
    import time as _time
    cfg = config_svc.load()
    c = _find(cfg, credential_id)
    if not c:
        return False
    if ok:
        c["verified"] = "ok"
        c["verifiedAt"] = str(_time.time())
        c.pop("verifyError", None)
    else:
        c["verified"] = "failed"
        c["verifyError"] = error[:200]
    config_svc.save(cfg)
    return True


def upsert_credential(alias: str = "", github_user: str = "", site_account: str = "",
                      password: str | None = None, twofa: str | None = None,
                      note: str = "", credential_id: str = "") -> dict:
    """新增/更新凭据。password/twofa 传明文;传 None = 不修改,传 '' = 清除。

    同 githubUser 已存在 ⇒ 返回已有条目(不重复建);显式传 credential_id 则更新它。
    返回 {id, created: bool, duplicated: bool}。
    """
    cfg = config_svc.load()
    creds = _load_creds(cfg)

    target = None
    created = duplicated = False
    if credential_id:
        target = _find(cfg, credential_id)
        if not target:
            raise ValueError("凭据不存在: " + credential_id)
    elif github_user:
        target = next((c for c in creds
                       if (c.get("githubUser") or "").lower() == github_user.lower()), None)
        duplicated = target is not None
    if not target:
        target = {"id": "cred_" + str(__import__("time").time() * 1000).split(".")[0]}
        creds.append(target)
        created = True

    if alias:
        target["alias"] = alias
    if github_user:
        target["githubUser"] = github_user
    if site_account:
        target["siteAccount"] = site_account
    if password is not None:
        target["password"] = crypto.encrypt(password) if password else ""
    if twofa is not None:
        target["twofa"] = crypto.encrypt(twofa) if twofa else ""
    if note:
        target["note"] = note

    cfg["credentials"] = creds
    config_svc.save(cfg)
    return {"id": target["id"], "created": created, "duplicated": duplicated}


def delete_credential(cid: str) -> bool:
    cfg = config_svc.load()
    creds = _load_creds(cfg)
    before = len(creds)
    cfg["credentials"] = [c for c in creds if c.get("id") != cid]
    if len(cfg["credentials"]) == before:
        return False
    config_svc.save(cfg)
    return True


def credential_of(account: dict) -> dict[str, str]:
    """账号的凭据(明文):优先 credentialId 引用;回退旧 encCredential。"""
    cfg = config_svc.load()
    cid = account.get("credentialId") or ""
    if cid:
        c = _find(cfg, cid)
        if c:
            cred = {"username": c.get("githubUser") or c.get("siteAccount") or "",
                    "password": "", "totpSecret": ""}
            if c.get("password"):
                try:
                    cred["password"] = crypto.decrypt(c["password"])
                except crypto.CryptoError:
                    pass
            if c.get("twofa"):
                try:
                    cred["totpSecret"] = crypto.decrypt(c["twofa"])
                except crypto.CryptoError:
                    pass
            return cred
    # 回退旧版:encCredential 内嵌
    enc = account.get("encCredential") or ""
    if not enc:
        return {}
    try:
        d = json.loads(crypto.decrypt(enc))
        return {
            "username": d.get("username", ""), "password": d.get("password", ""),
            "totpSecret": d.get("totpSecret", ""),
        }
    except (crypto.CryptoError, json.JSONDecodeError):
        return {}


def get_credential(account_key: str) -> dict[str, str]:
    """按账号 key 取凭据(向后兼容旧调用点)。"""
    cfg = config_svc.load()
    found = config_svc.find_account(cfg, account_key)
    if not found:
        return {}
    return credential_of(found[1])


def save_credential(account_key: str, username: str = "", password: str = "",
                    totp_secret: str = "") -> bool:
    """旧调用兼容:往账号对应凭据写(若账号无 credentialId 则按 githubUser 建全局凭据并绑定)。"""
    cfg = config_svc.load()
    found = config_svc.find_account(cfg, account_key)
    if not found:
        return False
    _, acc = found
    gh = username or acc.get("githubAccount") or ""
    if acc.get("credentialId"):
        cid = acc["credentialId"]
    elif gh:
        r = upsert_credential(github_user=gh, alias=acc.get("alias") or gh,
                              password=password or None, twofa=totp_secret or None)
        cid = r["id"]
        acc["credentialId"] = cid
        config_svc.save(cfg)
    else:
        return False
    # 有 cid 后走全局库 upsert
    try:
        upsert_credential(credential_id=cid, password=password or None,
                          twofa=totp_secret or None)
    except ValueError:
        return False
    return True


def totp_now(credential: dict[str, str]) -> str:
    secret = credential.get("totpSecret", "")
    if not secret:
        return ""
    try:
        import pyotp
        return pyotp.TOTP(secret).now()
    except Exception:
        return ""


def migrate_legacy_enc() -> int:
    """迁移:旧 encCredential(账号内嵌) → 全局凭据库(同 githubUser 去重)。"""
    cfg = config_svc.load()
    n = 0
    for s in cfg.get("sites", []):
        for a in s.get("accounts") or []:
            enc = a.get("encCredential") or ""
            if not enc or a.get("credentialId"):
                continue
            try:
                d = json.loads(crypto.decrypt(enc))
            except crypto.CryptoError:
                continue
            gh = d.get("username") or a.get("githubAccount") or ""
            if not gh:
                continue
            try:
                r = upsert_credential(
                    github_user=gh, alias=a.get("alias") or gh,
                    password=d.get("password") or None,
                    twofa=d.get("totpSecret") or None)
            except Exception:
                continue
            a["credentialId"] = r["id"]
            a.pop("encCredential", None)
            n += 1
    config_svc.save(cfg)
    return n
