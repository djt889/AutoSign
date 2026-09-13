# pc/ — Python WebUI 服务端

AutoSign 魔改版核心：FastAPI + Scrapling（替代上游已移除的 `src/` Node 引擎与 `electron/` 桌面端）。
设计文档见 `docs/设计文档-justsign魔改.md`（接口契约是唯一真源）。

## 运行

```bash
pip install -r pc/requirements.txt
scrapling install          # 浏览器内核（OAuth 授权 / 签到验证码需要）
python -m pc.main          # http://127.0.0.1:37421（API 文档 /docs）
```

## 结构

- `main.py` — FastAPI 入口（全部 API 端点 + 静态 WebUI 托管）
- `engine/site_client.py` — 站点 API 客户端（请求头叠加 / 429 退避 / WAF 识别 / 签到前置判定）
- `engine/oauth_flow.py` — GitHub OAuth 授权（无头自动 + 有头浏览器兜底）
- `engine/silent_auth.py` — 凭据静默换新（防风暴：同账号串行 + 8s 复用 + 90s 冷却）
- `engine/checkin.py` — 签到闭环（两级自动处理）
- `engine/credentials.py` — 全局凭据库
- `service/config.py` — 配置读写（`config.update` 原子事务）
- `service/crypto.py` — 凭据 AES-256-GCM（`data/secret.key`）
- `service/secret_store.py` — token/cookie 透明加解密
- `service/db.py` — 运行日志（兼容原 `logs.json` 格式）
- `service/scheduler.py` — 定时调度（APScheduler，Asia/Shanghai）
- `web/static/index.html` — 单文件响应式 WebUI
- `tests/` — 测试套件（零真实网络）

## 测试

```bash
python -m pytest pc/tests/ -q
```
