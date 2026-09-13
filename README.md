# AutoSign — 公益 AI 中转站自动签到

多站点 × 多 GitHub 账号的每日自动签到与额度看板。凭据本地加密存储，
签到与授权都走站点官方接口。

本仓库提供两种使用形态，同一套业务逻辑：

| 形态 | 目录 | 说明 |
| :--- | :--- | :--- |
| **WebUI 服务端**（推荐） | `pc/` | Python + FastAPI 服务，浏览器访问，手机/桌面自适应；可常驻后台按定时自动跑 |
| **Android App** | `android/` | 原生安卓端（来自上游，保留） |

> Android 包名 `icu.justwoker.justsign`（历史沿用，与仓库名无关）。

## 快速开始（WebUI）

需要 Python 3.10 及以上（开发与测试环境为 3.13）。

### 方式一：双击启动脚本（推荐）

脚本会自动检测 Python、创建虚拟环境、安装依赖，然后启动服务：

| 系统 | 脚本 |
| :--- | :--- |
| Windows | 双击 `start-server.cmd` |
| Linux / macOS | 终端执行 `./start-server.sh`（首次需 `chmod +x start-server.sh`） |

启动后浏览器打开 **http://127.0.0.1:37421** 即可。首次运行需要几分钟装依赖，之后启动是秒级。

### 方式二：手动安装

```bash
pip install -r pc/requirements.txt
python -m pc.main                 # 默认 http://127.0.0.1:37421
```

API 文档在 `/docs`。

### 可选：浏览器内核

授权/签到的验证码环节需要浏览器内核。装了就能用「全自动授权」：

```bash
python -m scrapling install
```

不装也能用，授权时改选「手动浏览器」方式即可。

### 后台常驻（Windows）

- `deploy/run-server-bg.cmd` —— 无窗口后台启动（供计划任务调用）
- `deploy/AutoSign.xml` —— 计划任务定义，登录即启动、异常自动拉起

先双击一次 `start-server.cmd` 完成初始化，再把 `deploy/AutoSign.xml` 导入任务计划程序即可。

## WebUI 功能

手机端底部四个标签（看板 / 签到 / 刷新 / 设置），桌面端为侧边栏，同一套数据与交互：

- **看板** —— 按站点分组展示每个账号的可用余额、累计已用、今日消耗、今日签到奖励，
  以及各站点的额度合计与总资产。
- **凭据库** —— 全局凭据库，同一 GitHub 账号只存一条，可绑定到任意多个站点复用。
  支持每账号单独设定授权方式。
- **签到** —— 一键对全部未签账号签到；也可单账号操作。
- **刷新** —— 按需拉取额度（打开页面自动取一次，其余靠刷新按钮；服务端 10 分钟缓存，
  避免多端重复打站点）。
- **设置** —— 站点增删改、定时调度、SOCKS5 代理、凭据库管理、运行日志。

## 授权方式

每个账号可选两种方式，默认按凭据能力推导（有密码 → 全自动）：

| 方式 | 适用 | 行为 |
| :--- | :--- | :--- |
| **全自动**（headless） | 已录入 GitHub 密码/TOTP | 后台静默完成授权，无需人工 |
| **手动浏览器** | 不愿交密码，或需要现场过验证 | 弹出浏览器窗口自行登录，只保存登录会话，不保存密码 |

授权采用 GitHub OAuth。全自动模式下用已存账密/TOTP 自动填充；若 GitHub 要求
邮箱设备验证码，前端会在确实需要时才显示 6 位验证码输入框（不需要填时不会出现）。
卡住时会给出「打开手动授权」入口兜底。授权结果记录验证状态，可随时在凭据库复查。

## 站点形态

| 形态 | 判据 | 行为 |
| :--- | :--- | :--- |
| `newapi` | 有 `GET/POST /api/user/checkin` | 完整签到流程，可拿到确切奖励金额 |
| `login` | 登录即发额度（无签到接口） | 每日重新登录触发发放，按今日奖励记录判定 |

内置四站（注册与签到奖励以站点当前实际为准）：

| 站点 | 注册奖励 | 每日签到 |
| :--- | :--- | :--- |
| [AgentRouter](https://agentrouter.org/register?aff=nc7C) | $175 | $25 |
| [JustDoWork](https://api.justwoker.icu/sign-up?aff=wFQu) | $90 | $20 |
| [GoRouter](https://gorouter.app/sign-up?aff=Dr35) | $70 | $10 |
| [KKtoken AI](https://kktoken.cc/sign-up?aff=BpDr) | $75 | $25 |

内置站与自定义站完全平权，都可增删改。

## 凭据与安全

- **凭据库**存 GitHub 用户名、密码、TOTP 密钥、站点会话（token / siteCookie）。
- 密码、TOTP、会话凭据一律经 **AES-256-GCM** 加密后落盘（密钥 `data/secret.key`，
  首次运行自动生成），接口只返回「是否已配置」，**读不回显明文**。
- `config.json`、`data/`（含密钥与 profile）已在 `.gitignore` 中，**不会被提交或上传**。
- 授权使用站点×账号独立的浏览器 profile，授权会话互不串号。

## 定时调度与代理

- 定时调度：APScheduler，时区 `Asia/Shanghai`，每日指定时刻自动对全部已授权账号跑一轮；
  单账号失败不阻断其余。可在设置页开关与改时间，保存即时生效。
- SOCKS5 代理：可在设置页配置，用于访问受限网络下的站点。

## 目录结构

```
pc/                       Python WebUI 服务端（本仓库主实现）
  main.py                 FastAPI 入口（全部 API 端点）
  engine/
    site_client.py        站点 API 客户端（请求头叠加 / 429 退避 / WAF 识别 / 签到前置判定）
    oauth_flow.py         GitHub OAuth 授权流程（Scrapling 无头 / 有头兜底）
    silent_auth.py        凭据静默换新（防风暴：串行 + 复用 + 冷却）
    checkin.py            签到闭环
    credentials.py        全局凭据库
  service/
    config.py             配置读写（原子事务）
    crypto.py             AES-256-GCM 加解密
    secret_store.py       凭据透明加解密
    db.py                 运行日志
    scheduler.py          定时调度
  web/static/index.html   单文件响应式 WebUI
  tests/                  测试套件
android/                  安卓端（保留自上游）
tools/                    构建与校验脚本
docs/                     设计文档
deploy/                   后台常驻部署脚本（Windows 计划任务）
```

## 开发与测试

```bash
python -m pytest pc/tests/ -q          # 全量测试
```

测试覆盖站点客户端契约、签到判定、OAuth 授权（含验证码隔离/过期/一次性消费）、
凭据库、配置原子事务与前后端接口契约。

## Android 构建

```bash
cd android
gradle assembleDebug                   # 需要 JDK17 + Gradle 8.7 + Android SDK 34
```

推 `v*` 标签会触发 CI 产出 APK（`.github/workflows/android-apk.yml`）。

## 声明

本项目用于管理**使用者本人**在相关站点注册的账号，仅按其官方接口完成每日签到与额度查询，
凭据全部保存在使用者本机。请遵守各站点的服务条款，风险自负。
