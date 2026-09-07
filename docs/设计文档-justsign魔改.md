# justsign 魔改设计文档

**项目名**:AutoSign(仓库 justsign)
**目标**:改造为「WebUI 本地服务器部署 + Python(Scrapling)引擎」的自动签到系统,保留 Android 端但同步换成同一套 Python 引擎
**fork**:`djt889/justsign`(源自 `AI-modelsAPI/justsign`)
**文档版本**:v1.0
**日期**:2026-09-08

---

## 0. 一句话概括

把原来「Node 引擎 + 各端原生壳(Android Java WebView / Electron)+ puppeteer」的架构,整体重写为「**单一 Python 服务端引擎(FastAPI + Scrapling)+ 浏览器 WebUI + 可选 Android 壳/桌面壳纯远程控制端**」。一个 Python 进程同时承担:站点 API 调用、GitHub OAuth 授权(浏览器自动化)、签到调度、凭据存储、WebUI 与 REST API。Android 端保留,但不再内置业务逻辑,只作为 WebUI 的远程访问入口(或瘦客户端直接调后端 REST API)。

> **人机验证声明已去除**:原 README「声明」段中「不绕过人机验证、不伪造凭据、不做批量注册」的立场性声明将从所有文档/UI 文案中移除。技术实现上通过 Scrapling 的 StealthyFetcher 处理 Cloudflare/Turnstile 挑战。

---

## 1. 现状分析(原仓库)

### 1.1 原架构

```
┌────────────────────────────────────────────────────────┐
│  Android 端 (Java, 纯手写 View)                        │
│    MainActivity / AuthActivity / CheckinActivity       │
│    ├─ Engine.java     纯 HTTP 调度(OkHttp)             │
│    ├─ SilentAuth.java 离屏 WebView 静默换凭据          │
│    ├─ OffscreenCheckin.java 离屏 WebView 签到+Turnstile│
│    ├─ AuthFillJs.java 自动填充账号密码/2FA            │
│    └─ Store.java      配置(Keystore 加密)              │
│    └─ WorkManager     每日定时签到                     │
├────────────────────────────────────────────────────────┤
│  src/ (Node 引擎, 跨平台)                              │
│    ├─ server.js  HTTP 服务(静态 UI + REST API + cron)  │
│    ├─ client.js  SiteClient: 站点 API 调用(axios)      │
│    ├─ auth.js    GitHub OAuth 自动化(puppeteer-core)   │
│    ├─ config.js  config.json 读写                     │
│    └─ db.js       logs.json 日志存储                  │
├────────────────────────────────────────────────────────┤
│  electron/ (macOS 桌面端, 复用 src/ 引擎)            │
└────────────────────────────────────────────────────────┘
```

### 1.2 关键业务逻辑(必须完整迁移)

| 逻辑 | 原实现 | 说明 |
|---|---|---|
| **站点 API 调用** | `client.js` / `Engine.java` (axios/OkHttp) | `self / status / log/self / checkin`,Bearer token + 可选 Cookie,支持 SOCKS5 代理 |
| **签到前置判定** | 先 `GET /api/user/checkin?month=YYYY-MM` 查已签,确认未签才 `POST` | 减少无效 POST,且只读接口不触发人机验证 |
| **Turnstile 处理** | `CheckinJs.java` 注入官方挂件,`appearance: interaction-only` 静默通过 | POST 被拦时才挂 |
| **OAuth 授权** | `auth.js` / `SilentAuth.java`/`AuthActivity.java`:拿 flow_token → 开浏览器 → GitHub 授权 → 回调页 fetch 交换 → 存 token+cookie | 全程浏览器,自动填充、2FA、SPA 回调 |
| **静默换凭据** | `SilentAuth`:JWT exp <60s 或 401 时重走 OAuth,8s 复用 / 90s 冷却,同账号串行 | 保证 token 长期有效 |
| **调度** | WorkManager(安卓)/ node-cron(服务端) | 每天/工作日/自定义 |
| **多 Profile 会话隔离** | WebView Profile 分区 | 站点×账号 cookie 隔离 |
| **429/WAF 防御** | 识别假 200 拦截页、自动切备用代理端口、60s 冷却 | |
| **奖励三态** | 有记录且 quota_awarded>0 金额;==0 无奖励;查不到只显示已签 | |

### 1.3 三种站点形态

- **newapi**:有 `GET/POST /api/user/checkin` → 全自动签到,可拿到确切奖励金额
- **login**:登录即发额度(无签到接口)→ 刷新即取奖励并置已签
- **web**:非 New API 或接口被拦截 → 点「去网页」人工处理

---

## 2. 目标架构

```
                        ┌─────────────────────────────┐
                        │   浏览器 WebUI (PC/手机)     │
                        │   Vue/React 单页 or 静态页   │
                        └──────────────┬──────────────┘
                                       │ HTTP / REST (JWT 可选)
┌──────────────────────────────────────▼──────────────────────────────┐
│  Python 服务端 (单进程, 本地服务器)                                  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  FastAPI 应用                                                 │  │
│  │  ├─ /api/*  REST 接口(站点/账号/签到/日志/设置)              │  │
│  │  ├─ /         静态 WebUI 托管                                 │  │
│  │  ├─ /oauth/   授权回调拦截(192.168.x.x 内网可达)             │  │
│  │  ├─ 定时调度 (APScheduler / 内置 asyncio 任务)               │  │
│  │  └─ WebUI 实时日志 (WebSocket 或 SSE)                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Scrapling 引擎(scrapling_engine 包)                          │  │
│  │  ├─ SiteClient    站点 API 调用(httpx, 可挂代理)             │  │
│  │  ├─ OAuthFlow     GitHub OAuth 自动化                        │  │
│  │  │   ├─ StealthyFetcher: Cloudflare/Turnstile 自动过         │  │
│  │  │   └─ DynamicFetcher: 表单填写/点击/2FA/SPA 回调           │  │
│  │  ├─ CredentialManager 凭据管理(AES-GCM 加密)                 │  │
│  │  └─ SessionIsolation 站点×账号 cookie 隔离                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────┐   ┌───────────────┐   ┌─────────────────────┐  │
│  │ config.json   │   │ data/*.json   │   │ .env / 密钥文件      │  │
│  │ 站点/账号/调度 │   │ 日志/快照      │   │ 凭据主密钥(可选)    │  │
│  └───────────────┘   └───────────────┘   └─────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                                       ▲
              ┌────────────────────────┴────────────────────────┐
              │                                                 │
┌─────────────▼───────────────┐              ┌────────────────▼───────────────┐
│  Android 端 (改造后)         │              │  (可选) Electron 桌面端        │
│  = WebView 全屏加载 WebUI    │              │  = BrowserWindow 加载 WebUI   │
│  = 仅保留原生存凭据能力(可选)│              │  = 或直接用系统浏览器         │
│  = 无业务逻辑, 纯遥控端       │              │    (放弃, 原 electron/ 可删)  │
└─────────────────────────────┘              └────────────────────────────────┘
```

### 2.1 核心决策

| 决策 | 选择 | 理由 |
|---|---|---|
| 服务端框架 | **FastAPI** | 异步、自带 OpenAPI 文档、静态托管、轻量,适合单机签到服务 |
| 抓取/自动化 | **Scrapling** | 一个库覆盖四档能力:HTTP(TLS 指纹伪装)→ Stealthy(过 CF/Turnstile)→ Dynamic/Playwright(全浏览器操作)→ Spider(批量爬);且内置 ProxyRotator、CDP 接管、executable_path |
| 浏览器内核 | **DynamicFetcher → Playwright Chromium**(服务端安装),授权/签到复用同一浏览器上下文 | 与 puppeteer 等价操作能力,由 scrapling 封装 |
| 凭据加密 | 服务端 `cryptography` (Fernet / AES-256-GCM),主密钥存 `data/secret.key` 或环境变量 | 对齐原 Android Keystore 强度(AES-256-GCM),去掉手机硬件依赖 |
| 配置格式 | 兼容原 `config.json` 结构(站→账号两级),Python 侧新增字段不破坏原数据结构 | 平滑迁移既有配置 |
| 静态 UI | 直接复用原 `src/index.html` 单文件暗色 UI,稍作打磨 | 已有页面,避免重造;后续可换 Vue |
| 调度 | APScheduler(`cron` 触发器,`Asia/Shanghai`) | 服务内置,不依赖系统 crontab |
| 代理 | Scrapling 内置 ProxyRotator + 手动 socks5 配置 | 429/WAF 换节点能力保留 |

---

## 3. Python 引擎设计(替换 src/)

### 3.1 项目结构

```
pc/  (Python Core, 新目录, 替换 src/)
├── main.py              # FastAPI 入口: 挂 API 路由 + 静态 WebUI + 调度启动
├── engine/
│   ├── __init__.py
│   ├── site_client.py   # SiteClient: 站点 API 调用(AppError 封装, httpx)
│   ├── oauth_flow.py    # GitHub OAuth 自动化(DynamicFetcher + StealthyFetcher)
│   ├── silent_auth.py   # 凭据交换: JWT exp 判定 / 401 重换 / 8s 复用 / 90s 冷却
│   ├── checkin.py       # 签到: 前置判定 → POST → Turnstile 兜底
│   ├── authfill.py      # 自动填充: 账号密码 / 2FA / "Use authenticator app" 切换
│   ├── proxy.py         # 代理管理: socks5 配置 / 429 换节点 / 探测
│   └── session.py       # 站点×账号 cookie 隔离(独立 Chromium 上下文目录)
├── service/
│   ├── config.py        # config.json 读写(兼容旧结构, deep-merge 默认值)
│   ├── crypto.py        # AES-256-GCM 凭据加密/解密
│   ├── db.py            # 日志/快照读写(JSON)
│   └── scheduler.py     # APScheduler 定时签到
├── web/
│   └── static/          # index.html 等前端静态资源(直接迁自 src/index.html)
├── requirements.txt
├── pyproject.toml
└── README-魔改.md
```

### 3.2 模块职责与 API 对照

| 原 Node/Java | 新 Python 模块 | 关键差异 |
|---|---|---|
| `client.js` SiteClient | `engine/site_client.py` | axios → httpx(AsyncClient);SOCKS 代理走 `socksio`/`httpx[socks]`;同签名 `status() self() usage_log() checkin()` |
| `auth.js` / `SilentAuth.java` | `engine/oauth_flow.py` + `engine/silent_auth.py` | puppeteer → scrapling `DynamicFetcher`;手动 chromiumPath → 服务端 Config 指定浏览器路径;逻辑(flow_token → 授权 → 回调 fetch 交换 → 落盘)逐行照搬 |
| `AuthFillJs.java` | `engine/authfill.py` | JS DOM 操作 → Playwright locator 语法;选择器一一对应(`#login_field`/`#password`/`#app_totp`/`Use authenticator app` 链接等) |
| `CheckinJs.java` | `engine/checkin.py` | 前置判定、`interaction-only` Turnstile、奖励解析逻辑全部保留;Turnstile 挂载由 Python 注入同款 JS / 或 StealthyFetcher 自动处理 |
| `Engine.java` 401 重试 | `silent_auth.py` 装饰器 | `@ensure_credential(account)` 包裹业务请求,401/exp→静默换凭据→重试 |
| WebView Profile | `engine/session.py` | 每「站点×账号」一个独立浏览器上下文目录(等价 WebView Profile 分区),cookie 隔离 |
| WorkManager / node-cron | `service/scheduler.py` | APScheduler CronTrigger |
| `Store.java` Keystore | `service/crypto.py` | 主密钥 `data/secret.key`,本地生成并 chmod 600 |

### 3.3 Scrapling 能力映射(验证过)

| 需求 | Scrapling 用法 | 说明 |
|---|---|---|
| 普通 API 调用 | `Fetcher.get()/post()` | TLS 指纹伪装,HTTP/3 |
| Cloudflare / Turnstile 自动过 | `StealthyFetcher.adaptive = True`;`StealthyFetcher.get(url, solve_cloudflare=True)` | 覆盖「POST 被拦时挂 Turnstile」场景 |
| 表单填写 / 点击 / 2FA | `DynamicFetcher`(Playwright Chromium):`page.type` / `page.click` / 等待选择器 | 对应 AuthFillJs 全部逻辑 |
| SPA 回调交换 | DynamicFetcher 监听页面跳转 + 页面内 `fetch` 交换 code | 对应 auth.js 回调拦截 |
| 代理 | 全局 `ProxyRotator` + `page.proxy` 参数 | 429 换节点 |
| 自定义浏览器 | `executable_path=...` 或 `cdp_url` 接管已开浏览器 | 对应原 chromiumPath |
| JS 渲染 | DynamicFetcher `network_idle=True` | |

---

## 4. WebUI 化设计(核心改造)

### 4.1 形态

- **服务端**:FastAPI 同时托管 `web/static/` 与 `/api/*`。默认监听 `0.0.0.0:7300`,局域网可达(`http://<服务器IP>:7300`)。
- **前端**:直接采用原 `src/index.html` 单一暗色页面(首页总览 / 账号 / 站点 / 日志&设置 / 引擎设置 五个 tab),替换 API 调用基地址为同源 `/api/*`(原生就是同源相对路径,几乎零改动);新增一处「授权回调入口」逻辑。
- **登录态/鉴权**:默认内网可信无鉴权(与原 Node server 一致);可选开启「简易令牌」——访问 WebUI 需填 `AUTHSIGN_TOKEN`(前端 localStorage 持久化,请求带 `Authorization` 头)。

### 4.2 新增/改动页面交互

| 交互 | 原实现 | WebUI 版 |
|---|---|---|
| GitHub OAuth 授权 | 安卓内嵌 WebView 引导 / Electron 窗口 / Node 脚本 | 页面点「授权」→ 后端起一次 OAuth 流程(可 headless 或弹新窗口),回调由后端接管。headless 失败需人工时,后端返回一个"去浏览器手动授权"链接 |
| 签到 | 点按钮触发原生流程 | 点按钮 → `POST /api/checkin/{account}` → 结果 + 日志即时回显(WebSocket/SSE 推送) |
| 定时任务 | WorkManager / node-cron | `POST /api/settings` 保存 cron 表达式,APScheduler 生效 |
| 日志 | 页面轮询 `/api/history` | 保留轮询 + 新增 SSE/WS 实时流 |
| 代理设置 | 设置页表单 | 同保留,字段一致(socks5 host/port/enabled) |

### 4.3 REST API 清单(与原 server.js 对齐)

```
GET    /api/health
GET    /api/sites                         # 站点列表(账号 token 打码)
POST   /api/sites/save                    # 新增/修改站点
DELETE /api/sites/{key}
POST   /api/accounts/save                 # 新增/修改账号(token/cookie 写入)
DELETE /api/accounts/{key}
GET    /api/accounts                      # 扁平账号列表(兼容)
GET    /api/status/{account}              # 额度 / 用户 / 授权状态
POST   /api/checkin/{account}             # 手动签到
GET    /api/logs/{account}                # 使用日志 + lastBonus
GET    /api/history                       # 引擎日志
POST   /api/settings/save                 # 调度 + 代理
POST   /api/oauth/start                   # 发起授权流程(返回 state/token)
POST   /api/oauth/callback                # 授权回调落点
GET    /api/proxy-test
GET    /api/events                        # SSE 实时日志流
```

> 新增:OAuth 相关两个端点是 Node 版没有的(原版靠 App 内嵌 WebView 完成授权,WebUI 必须暴露给服务端)。

---

## 5. OAuth 授权改造(重点)

### 5.1 原流程(保留行为)

```
1. POST /api/oauth/state  → 拿 flow_token(state)
2. GET  /api/status       → 动态取 github_client_id
3. 浏览器打开 https://github.com/login/oauth/authorize?client_id&state&scope=user:email
4. (自动填充账号密码 / 2FA / 切 authenticator)
5. 等回调页(站点同域 /oauth/*?code&state)→ 页面内 fetch /api/oauth/{provider} 换 access_token
6. 落盘 token + cookie,绑定「站点×账号」
```

### 5.2 WebUI 方式三选一

**推荐 A(全自动,后端 headless)**
用户点「授权」→ 服务端用 `DynamicFetcher` 起 headless 浏览器走完整流程 → 自动填充凭据(来自凭据库)→ 完成交换 → 落盘 → 页面显示成功。与安卓 SilentAuth 语义一致。

**方式 B(有头浏览器 + 服务端接管回调)**
授权时在服务器上弹出可见浏览器(Cron 环境无桌面时不可用),完成后回调由 `POST /api/oauth/callback` 收尾。适合服务器带桌面或利用 VNC。

**方式 C(手动,浏览器零自动化)**
后端只生成授权 URL → 用户在任何浏览器(自己电脑)打开 → 完成 GitHub 授权回到站点 → 站点页面显示 token,用户复制回 WebUI 粘贴(对应原 auth.js 的「手动授权指引」路径)。作为 A/B 失败时的兜底,必须保留。

### 5.3 静默换凭据(SilentAuth 平移)

在 Python 侧实现等价的 `silent_auth.py`:

- 解析 JWT `exp`,剩余 < 60s → 提前换新
- 业务请求遇 401 → 换新 → 重试一次
- 同账号串行(asyncio lock)+ 成功后 8s 内复用(`LAST_OK`)
- 失败后 90s 冷却(`FAIL_UNTIL`),手动授权可清冷却
- 换新全程 headless,复用站点×账号 session 上下文(保留 GitHub cookie)

---

## 6. Android 端改造

### 6.1 原则

- **保留 Android 工程与 APK 产物**(用户明确要求「保留安卓版本」),但删除全部内嵌业务逻辑(Engine/SilentAuth/CheckinJs/AuthFillJs/OffscreenCheckin 等)。
- 改造后 App = **WebUI 的移动端入口**:全屏 WebView 加载配置的后端地址(首个启动页填服务器 IP/端口,存 SharePreferences),其余全部交给远程 WebUI。
- 原「纯 Java 手写 View」的本地 UI 层(Ui.java/MainActivity 主界面)删除,只在 Settings 里留「服务器地址 / 口令」两项原生设置 + 一个 WebView 容器。

### 6.2 改造结果

```
android/ (改造后)
├── app/src/main/java/icu/justwoker/justsign/
│   ├── MainActivity.java      # 全屏 WebView + 首启配置页
│   └── ServerConfig.java      # 服务器地址/口令持久化(加密)
├── (删除) Engine / SilentAuth / OffscreenCheckin / AuthFillJs /
│          CheckinJs / OAuthCallback / WebViewProfileUtil / SettingsView 等
├── res/                       # 图标/字符串保留
└── AndroidManifest.xml        # 加 INTERNET;删除不用的 Activity
```

> **能力取舍说明**:手机上局域网访问 WebUI,签到定时改由「服务器调度 + 服务器常开」承担,不再依赖 App 后台保活(这是换 WebUI 的核心收益——原版根依赖 WorkManager 存活率,改成服务器后签到更可靠)。

### 6.3 可选:Android 直连后端(瘦客户端模式)

如果不想让 Android 依赖 WebUI(服务器挂了 App 也全废),可保留一层「直连模式的轻业务」:App 里用 OkHttp + 手写的 Java 版 SiteClient 调后端 REST API 展示额度(只读),签到/授权仍走服务器。**本版默认不做**,文档记为一期可选项。

---

## 7. 去除「人机验证声明」的具体改动清单

| 位置 | 原内容 | 改法 |
|---|---|---|
| `README.md` 开头 | 「…不伪造任何验证」 | 删除/改写成中性描述 |
| `README.md` 声明段 | 「不绕过人机验证、不伪造凭据、不做批量注册。人机验证由真实浏览器环境完成…」整段 | **删除整段** |
| `CheckinJs.java`/相关注释 | 「不绕过人机验证」相关注释 | 删除(文件本身将随 Android 改造移除) |
| `src/auth.js` / `src/server.js` | 「不伪造」「不批量」注释 | 删除相关注释 |
| 前端 UI 文案 | 任何「不绕过人机验证」字样 | 删除 |

同时,**行为层放开**:将 Turnstile 处理从「仅 interaction-only 静默」升级为「POST 被拦时用 StealthyFetcher 的 Cloudflare 求解能力自动过」(这就是 scrapling 相对原方案的核心增强点)。签到 POST 不再因为「过不了验证」直接判失败,而是尝试破解验证(interaction-only + 若要求交互则触发完整求解)。

---

## 8. 部署与运行

### 8.1 服务器(本地 Linux/Windows 均可)

```bash
# 环境: Python 3.11+
pip install "scrapling[fetchers]" fastapi uvicorn apscheduler httpx[socks] cryptography
scrapling install                                  # 下载 Chromium/Playwright 内核

git clone https://github.com/djt889/justsign.git
cd justsign
cp .env.example .env                              # 配置端口/令牌/浏览器路径
python -m pc.main                                  # 或 uvicorn pc.main:app
# 打开 http://<服务器IP>:7300
```

systemd 示例(常驻):

```ini
[Unit]
Description=AutoSign WebUI Server
After=network.target
[Service]
ExecStart=/usr/bin/python3 -m pc.main
WorkingDirectory=/opt/justsign
Restart=always
[Install]
WantedBy=multi-user.target
```

### 8.2 Docker(可选)

Scrapling 官方有 `pyd4vinci/scrapling` 镜像(预装全部浏览器),Dockerfile 可以直接基于它 + 项目代码,`docker-compose up -d` 一把起。**本期文档建议等实现阶段提供 compose 文件**。

### 8.3 Android

装改造后的 APK → 填服务器地址 → 之后的日常全部在 WebUI 里操作。

---

## 9. 迁移与兼容

| 项 | 处理 |
|---|---|
| 旧 `config.json` | Python 侧 deep-merge 默认值,站点→账号两级结构完全兼容;token 明文字段若已加密,迁移时先用旧密钥解密再落新库(或直接重新授权) |
| 旧 `data/logs.json` | 直接读取,格式不变 |
| 内置站点(4 个) | 保留在 `data/` 快照与 WebUI,注册邀请码链接保留 |
| 三种站点形态 | 保留,`web` 形态在 WebUI 里变成「跳转到站点」按钮 |

---

## 10. 风险与对策

| 风险 | 对策 |
|---|---|
| GitHub OAuth 全部依赖浏览器自动化,故障面大 | 三选一授权方式(A/B/C)并行,手动兜底必须可用;凭据库自动填充可关 |
| Scrapling StealthyFetcher 对某些站 Cloudflare 求解失败 | 降级到 DynamicFetcher 全浏览器交互;再不行走 `web` 形态人工 |
| 服务器在公网暴露 → 凭据泄露 | 默认只绑内网 IP;可选令牌鉴权;凭据 AES-256-GCM 静态加密;不部署到公网(文档明确本地服务器定位) |
| 多账号并发点签到 → 429 | 保留同账号串行 + 成功后 8s 复用 + 失败 90s 冷却;ProxyRotator 换节点 |
| 原 Android 用户升级丢数据 | 新 App 定位是 WebUI 入口,数据都上服务器;旧本地数据(Keystore 加密字段)不迁移,由用户登录各站重新授权 |
| Chromium 资源占用 | DynamicFetcher 只在授权/静默换凭据时短暂拉起;日常签到走 Fetcher HTTP,几乎零开销 |

---

## 11. 分期实施计划

| 阶段 | 内容 | 验证 |
|---|---|---|
| **P0 引擎替换** | `pc/` Python 骨架 + SiteClient + 配置/加密/日志 | `pytest` 对 4 个真实站点跑 `status/self/log` 成功 |
| **P1 签到闭环** | checkin.py 前置判定 + POST + Turnstile 兜底;手动 API 可触发 | 真实账号连签 3 天无重复 POST |
| **P2 OAuth** | oauth_flow + silent_auth 三选一授权 | 一次人工授权后 7 天全自动静默换凭据 |
| **P3 WebUI** | FastAPI 托管静态页 + 全部 REST API + SSE 日志 + 可选令牌 | 浏览器完成添加站点/账号/签到/看额度全流程 |
| **P4 调度** | APScheduler cron | 定时触发日志有记录,跨日不重复 |
| **P5 Android 瘦身** | 删业务逻辑,改 WebView 远程入口 | 安装 APK 填地址即可用 |
| **P6 文档收尾** | README 重写(去除人机验证声明)、删 electron/ | repo 干净可读 |

---

## 12. 待确认问题(实现前需用户拍板)

1. **WebUI 鉴权**:默认不鉴权(仅内网)?还是一定要开令牌?——文档默认「内网无鉴权 + 可选令牌」。
2. **Electron 桌面端去留**:默认删除(WebUI 已覆盖),是否保留为「本地浏览器壳」?
3. **Android 是否保留直连后端模式**(见 6.3):默认不做,只做 WebView 入口。
4. **前端是否重做**:默认直接迁移现有暗色单页,后续再美化。