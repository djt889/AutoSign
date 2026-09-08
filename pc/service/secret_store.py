"""secret_store.py — 站点凭据(token/siteCookie)透明加密存取。

设计(文档 §7 凭据安全):
- config.json 里 token/siteCookie 字段存 "enc:<base64>" 密文(AES-256-GCM,
  密钥 data/secret.key,与 GitHub 凭据库同钥)
- 读时自动解密,写时自动加密——调用方(SiteClient/授权落库)无感知
- 兼容明文:读到无 enc: 前缀的旧值按明文处理(平滑迁移),首次写入时加密
"""
from __future__ import annotations

from ..service import crypto

PREFIX = "enc:"


def seal(value: str | None) -> str | None:
    """明文 → enc: 密文(已是密文则原样)。None/空串透传。"""
    if not value:
        return value
    return crypto.encrypt(str(value))


def open_(value: str | None) -> str:
    """enc: 密文 → 明文;明文/None/解密失败(密钥更换)返回空串(视为无凭据)。"""
    if not value:
        return ""
    s = str(value)
    if not s.startswith(PREFIX):
        return s          # 旧明文格式,平滑兼容
    try:
        return crypto.decrypt(s)
    except crypto.CryptoError:
        return ""         # 密钥不匹配 ⇒ 视为无凭据,触发重新授权


def seal_account(account: dict) -> dict:
    """落库前:token/siteCookie 加密(就地)。"""
    for f in ("token", "siteCookie"):
        if account.get(f):
            account[f] = seal(account[f])
    return account


def unseal_account(account: dict) -> dict:
    """使用前:token/siteCookie 解密(返回新 dict,不动原配置)。"""
    out = dict(account)
    for f in ("token", "siteCookie"):
        if out.get(f):
            out[f] = open_(out[f])
    return out
