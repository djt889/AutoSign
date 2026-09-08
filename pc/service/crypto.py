"""crypto.py — 凭据 AES-256-GCM 加密/解密(对齐原 Android Keystore 强度)。

主密钥 data/secret.key:首次运行生成 32 字节随机密钥;凭据库中
password/totpSecret 字段一律存 "enc:<base64(nonce|ct|tag)>" 格式,
解密失败抛 CryptoError,绝不静默返回明文。
"""
from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import ROOT

KEY_PATH = Path(os.environ.get("JUSTSIGN_SECRET", ROOT / "data" / "secret.key"))

_ENC_PREFIX = "enc:"


class CryptoError(Exception):
    pass


def _load_key() -> bytes:
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        key = KEY_PATH.read_bytes()
        if len(key) == 32:
            return key
        raise CryptoError(f"主密钥长度异常({len(key)} 字节,应为 32),拒绝使用")
    key = os.urandom(32)
    KEY_PATH.write_bytes(key)
    try:  # Windows 上 chmod 作用有限,尽力收紧
        KEY_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    if plaintext.startswith(_ENC_PREFIX):
        return plaintext  # 已加密,幂等
    key = _load_key()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _ENC_PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt(token: str) -> str:
    if not token:
        return ""
    if not token.startswith(_ENC_PREFIX):
        raise CryptoError("凭据不是加密格式(应为 enc: 前缀)")
    key = _load_key()
    raw = base64.b64decode(token[len(_ENC_PREFIX):])
    nonce, ct = raw[:12], raw[12:]
    try:
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except Exception as e:
        raise CryptoError(f"解密失败(密钥不匹配或数据损坏): {e}") from e


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(_ENC_PREFIX)
