# pc/ — Python 引擎(P0)

AutoSign 魔改版核心:FastAPI + Scrapling,替换原 `src/` Node 引擎。
设计文档见 `docs/设计文档-justsign魔改.md`(契约 §3.0 是接口唯一真源)。

## 运行

```bash
pip install -r pc/requirements.txt
scrapling install          # 浏览器内核(P2 OAuth 阶段才需要)
python -m pc.main          # http://0.0.0.0:37421 (API 文档 /docs)
```

## 结构

- `engine/site_client.py` — 站点 API 客户端(契约 3.0:请求头叠加/429 退避/WAF 假 200/签到前置判定)
- `service/config.py` — config.json(兼容原两级结构)
- `service/crypto.py` — 凭据 AES-256-GCM(data/secret.key)
- `service/db.py` — 日志(兼容原 logs.json 格式)
- `main.py` — FastAPI 入口(P0:health/sites/accounts/status/history)
- `tests/` — 契约测试(24 项,零真实网络)

## 阶段

P0 引擎骨架(本目录)→ P1 签到闭环 → P2 OAuth(Scrapling 浏览器)→ P3 WebUI → P4 调度 → P5 Android 瘦壳。
