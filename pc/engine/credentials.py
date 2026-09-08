"""credentials.py — 凭据库(P2):站点账号/密码/TOTP 密钥,AES-256-GCM 加密落盘。

存储:config.json 账号条目的 encCredential 字段(整个凭据 JSON 加密),
读不回显明文;TOTP 码用 pyotp 现场生成。
"""
from __future__ import annotations

import json
from typing import Any

from ..service import config as config_svc
from ..service import crypto


def save_credential(account_key: str, username: str = "", password: str = "",
                    totp_secret: str = "") -> bool:
    """写入/更新凭据(字段空串 = 保留原值);返回是否成功。"""
    cfg = config_svc.load()
    found = config_svc.find_account(cfg, account_key)
    if not found:
        return False
    _, acc = found

    cred: dict[str, Any] = {}
    if acc.get("encCredential"):
        try:
            cred = json.loads(crypto.decrypt(acc["encCredential"]))
        except crypto.CryptoError:
            cred = {}
    if username:
        cred["username"] = username
    if password:
        cred["password"] = password
    if totp_secret:
        cred["totpSecret"] = totp_secret
    if not cred:
        return False

    acc["encCredential"] = crypto.encrypt(json.dumps(cred, ensure_ascii=False))
    config_svc.save(cfg)
    return True


def get_credential(account_key: str) -> dict[str, str]:
    """解密取凭据(内部使用:自动填充);无/解密失败返回空 dict。"""
    cfg = config_svc.load()
    found = config_svc.find_account(cfg, account_key)
    if not found:
        return {}
    _, acc = found
    enc = acc.get("encCredential")
    if not enc:
        return {}
    try:
        return json.loads(crypto.decrypt(enc))
    except (crypto.CryptoError, json.JSONDecodeError):
        return {}


def totp_now(credential: dict[str, str]) -> str:
    secret = credential.get("totpSecret", "")
    if not secret:
        return ""
    try:
        import pyotp
        return pyotp.TOTP(secret).now()
    except Exception:
        return ""


