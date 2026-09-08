# justsign 魔改设计文档

**项目名**:AutoSign(仓库 justsign)
**目标**:改造为「WebUI 本地服务器部署 + Python(Scrapling)引擎」的自动签到系统,保留 Android 端但同步换成同一套 Python 引擎
**fork**:`djt889/justsign`(源自 `AI-modelsAPI/justsign`)
**文档版本**:v1.2
**日期**:2026-09-08
**v1.1 修订**:明确「接口复用 vs Scrapling 抓取」分工;澄清自动限速(AutoThrottle)仅属 Spider 框架、普通 fetch 不自动限速;授权流程改为「纯后台 headless 为主,弹出浏览器仅兜底」;新增 `capture_xhr` 背景接口监听辅助手段。
**v1.2 修订**:3.0 契约清单补全 OAuth 交换凭据通用规则(Set-Cookie 抓取、token/cookie 任一变化即成功、`login=` 防串号、GitHub 过期 URL 转人工清单、「免退出重登」=静默重放 OAuth,全站通用不按站点特判);3.2 功能选型表全面扩充(标签页池/wait_selector/page_setup/init_script/多指纹轮换/locale+timezone 一致性等);0.1.1 `capture_xhr` 升级为授权交换首选手段。

---

## 0. 一句话概括

把原来「Node 引擎 + 各端原生壳(Android Java WebView / Electron)+ puppeteer」的架构,整体重写为「**单一 Python 服务端引擎(FastAPI + Scrapling)+ 浏览器 WebUI + 可选 Android 壳/桌面壳纯远程控制端**」。一个 Python 进程同时承担:站点 API 调用、GitHub OAuth 授权(浏览器自动化)、签到调度、凭据存储、WebUI 与 REST API。Android 端保留,但不再内置业务逻辑,只作为 WebUI 的远程访问入口(或瘦客户端直接调后端 REST API)。

> **人机验证声明已去除**:原 README「声明」段中「不绕过人机验证、不伪造凭据、不做批量注册」的立场性声明将从所有文档/UI 文案中移除。技术实现上通过 Scrapling 的 StealthyFetcher 处理 Cloudflare/Turnstile 挑战。

---

## 0.1 接口复用策略(重要)

**「复用原仓库已确认的接口」不等于「复用原 Node/Puppeteer 实现」,全部接口调用都改用 Python + Scrapling 完成。**

- **复用的是「接口清单与调用形状」**:原仓库已经探明并验证过每个站点有哪些接口(`/api/status`、`/api/user/self`、`/api/user/checkin?month=`、`/api/log/self`、`/api/oauth/state`、`/api/oauth/github`、`/api/user/auth/refresh` 等)、各接口的请求方法/参数/响应字段(如 `quota_per_unit`、`stats.checked_in_today`、`records[].quota_awarded`、`data.flow_token`、`data.access_token` 等)。这些**契约直接作为 Python 实现的依据**,避免重新逆向或盲猜 URL/参数。
- **实现全部落在 Scrapling**:即使是最普通的 GET/POST,也统一走 Scrapling 触发网络访问(`Fetcher`/`FetcherSession`/浏览器 fetcher),以获得 TLS 指纹伪装、Session 管理、代理轮换、拒绝检测等能力;不使用手写 `requests`/`httpx` 裸调用。
- **「复用接口」的边界**:只复用接口契约,不复用 Node 代码、不复用 axios 客户端、不复用 puppeteer 自动化流程。Python 引擎按同等契约重写全部调用。

> 结论一句话:**接口清单白嫖原仓库,代码全部用 Python + Scrapling 自研。**

### 0.1.1 可选增强:背景接口监听(capture_xhr)

原仓库的 WebView 方案是通过「注入 JS + 拦截回调页 fetch」拿到 token 的。Scrapling 提供 **`capture_xhr`** 能力:`DynamicFetcher`/`StealthyFetcher` 抓取页面时,传入 URL 模式,页面加载过程中所有匹配的 XHR/fetch 响应会被自动收集成 `Response` 对象(`response.captured_xhr`)。

- **用途一(摸底)**:某站点接口文档缺失或前端调用了未记载的内部 API 时,用浏览器抓一次,从 `captured_xhr` 里直接捞出真实接口与响应结构,反过来补全接口清单(**只用于摸底,不用于运行时**)。
- **用途二(运行时,授权交换)**:OAuth 回调页加载时,前端自己会 GET `/api/oauth/{provider}?code&state` 完成交换——`capture_xhr` 直接捕获这个响应,拿到 `access_token`,**不需要再注入 JS 主动 fetch**,比原版「页面上下文 evaluate fetch」更稳(不依赖页面脚本时序)。这是授权流程方式 A 的首选交换手段,主动 evaluate 作为备用。

> 运行时除授权交换外,仍以「已确认接口直调」为主,浏览器只做授权与兜底。

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
| **站内用户 ID 透传** | `Engine.java`:`New-Api-User: <siteUserId>` 请求头 | 账号授权响应 `data.id` 落库后随每个请求透传(AgentRouter 等变体必需) |
| **凭据字段化(全站通用)** | `SilentAuth.java`(审计 B-02/B-03):OAuth 交换抓 `Set-Cookie` session + `access_token`(可为 null),按账号实际持有字段组装请求头,不按站点名特判 | AgentRouter 首个实例;「退出重登」由静默重放 OAuth 隐式完成,全站统一,无 logout 接口(详见 3.0) |
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
- **web**:非 New API 或接口被拦截 → 标记「不支持自动签到」,不提供人工签到入口(本版定位:签到全自动,失败即报错,见 §7)

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
│  │  Scrapling 引擎(pc/engine 包)                                 │  │
│  │  ├─ SiteClient    站点 API 调用(FetcherSession, 可挂代理)    │  │
│  │  ├─ OAuthFlow     GitHub OAuth 自动化(全 headless 优先)      │  │
│  │  │   ├─ StealthyFetcher: Cloudflare/Turnstile 自动过         │  │
│  │  │   └─ 标签页池 + capture_xhr 交换 + user_data_dir 隔离    │  │
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

### 3.0 接口复用契约清单(核心资产,直接照搬不推测)

> 本节从原仓库源码逐文件提取,是**已实测验证的接口契约**。Python 实现以本表为唯一真源,与源码逐条对照,禁止重新推测接口行为。

**站点业务接口(New API 系,来自 `client.js` + `Engine.java` + `CheckinJs.java`)**

| 接口 | 方法 | 请求头 | 响应关键结构 | 备注 |
|---|---|---|---|---|
| `/api/status` | GET | `Accept: application/json` | `data.quota_per_unit`(默认 500000)、`data.turnstile_check`、`data.turnstile_site_key`、`data.github_client_id`、`data.checkin_enabled`、`data.price` | 站点级元信息;quota 换算单位、Turnstile 开关、OAuth clientId 全从这里取 |
| `/api/user/self` | GET | `Authorization: Bearer <token>` + `New-Api-User: <siteUserId>`(有 siteUserId 时) | `data.data.display_name / username / github_id / quota / used_quota / today_used_quota` | 余额/已用/今日消耗;401 = token 失效需静默换新 |
| `/api/user/status` | GET | 同上 | 同 self | 备用 |
| `/api/log/self?category=&page=&limit=` | GET | 同上 | `data.data.list[]`:`created_at / category / description / content / remark / quota` | 找「签到」记录作为 lastBonus;日志可能倒序,取**最新**签到记录(v0.4.5 教训) |
| `/api/user/checkin?month=YYYY-MM` | GET | 同上 | `stats.checked_in_today`、`records[]`(`checkin_date/date`、`quota_awarded`) | **只读前置判定**,不触发人机验证;先查它,未签才 POST |
| `/api/user/checkin` | POST | 同上 | 成功响应含奖励信息 | 真正签到动作 |
| `/api/user/checkin?turnstile=<token>` | POST | 同上 + turnstile token | 同上 | POST 被拦(响应匹配 `/turnstile\|captcha\|验证\|校验\|人机\|challenge\|robot/i`)时才走此变体 |
| `/api/oauth/state` | POST(默认)或 GET | body `{"provider":"github","intent":"login"}` / GET `?mode=login` | `data` 为 String 直接是 state,或 `data.flow_token` | **两种形态**:多数站走 POST;AgentRouter 一类只认 GET(POST 直接 404)。先 POST,404 则改 GET,`stateMethod=get` 记入站点 meta |
| `/api/oauth/{provider}?code=&state=` | GET(服务端直调) | `Accept: application/json` + UA | `{success:true, data:{access_token?, user?, id, github_id?}}` + **响应头 `Set-Cookie`** | 见下方「OAuth 交换凭据规则」 |
| `/api/user/auth/refresh` | ~~POST~~ | — | — | **已废弃,不要实现**(原 v0.2.3 已删除:httpOnly Cookie 在 App 侧无法稳定维持,实测 401) |

**OAuth 交换凭据规则(全站通用,数据驱动,AgentRouter 只是首个实例)**

New API 系登录凭据是 OAuth 交换响应的 **`Set-Cookie` session**(gin 框架),`access_token` 是可选系统令牌,**可能为 JSON null**。以下规则对**所有站点无条件执行**,不按站点名特判——"token 型 / cookie 型"不是站点属性,而是**每个账号实际持有哪些凭据字段**决定的:

1. 交换 `/api/oauth/{provider}` 时**总是**抓取响应头 `Set-Cookie`,逐条解析只保留有值的(跳过 `Max-Age=0`/空值/`deleted` 删除态),拼成 `k1=v1; k2=v2` 落库为 `siteCookie`(token 型站响应里通常没有有效 Set-Cookie,自然存空,零副作用)。
2. token 兼容三字段名:`access_token` / `accessToken` / `token`,空串、`null`、缺失一律视为无 token。
3. 身份字段:`data` 直接是用户对象(AgentRouter 型,`data.username`/`data.id`/`data.github_id`),旧版在 `data.user` 里(`username`/`login`)——**两层都试**;`data.id` = 站内用户 ID(siteUserId)。
4. **换新成功判据:token 或 siteCookie 任一变化即算成功**(同一套判定适用于所有站)。
5. 后续业务请求头按账号字段**叠加组装**(三者互斥性为零,有哪个带哪个):有 token ⇒ `Authorization: Bearer`;有 siteCookie ⇒ `Cookie`;有 siteUserId ⇒ `New-Api-User`。
6. 交换响应若 `github_id`/`github_user_id` 与账号缓存不一致 ⇒ **拒绝**(B1 身份校验,锚点分层:强判据 = 响应有 `github_id` 且账号已缓存 `githubId`,不等即拒;弱判据 = 无 `github_id` 数据时回退 `username` 比对;两者都拿不到 ⇒ 跳过校验不误拒。注意站内名 `github_<站内id>` 与 GitHub 用户名无关,不可比)。

**「重新登录」语义(重要,全站统一路径,免退出实现)**

**不实现任何 logout 接口,所有站点统一用"静默重放一遍 GitHub OAuth"换新凭据。** 每次重放对每个站点都是同一套流程,收益对 cookie 型站是"旧 session 作废+新登录",对 token 型站是"新 access_token":

- 触发:JWT `exp` 剩余 < 60s 预判换新,或业务请求 401 兜底换新(换完重试一次,标记 `reauthed:true`)
- 授权 URL 强制带 **`login=<期望GitHub账号>`** 参数:强制 GitHub 以指定账号授权,防 WebView/浏览器里登录了别的 GitHub 账号导致串号
- 重放全程 headless:GitHub 会话 cookie 在持久化分区(`user_data_dir`)里,正常情况直接 302 跳回回调页,秒级完成
- **转人工判定**:重放途中浏览器导航到 `github.com/login`、`/session`、`two-factor`、`verified-device`、`sudo` 任一 URL ⇒ GitHub 会话本身过期,转方式 B/C(自动填充账密/2FA)
- 快速失败:会话已登录且期望账号明确却卡在授权确认页(8s 无人点)⇒ 立即转人工,不空等 30s
- 防风暴三重保护:同账号串行(asyncio.Lock)+ 成功 8s 复用 + 失败 90s 冷却

**调用通用规则(来自 `Engine.java` / `AuthActivity.java`)**

1. **请求头组装(按账号字段叠加,有哪个带哪个)**:`User-Agent` + `Accept: application/json` + `Authorization: Bearer`(有 token 时)+ `Cookie`(有 siteCookie 时)+ `New-Api-User`(有 siteUserId 时)。
2. **429 处理**:读 `Retry-After` 头,提示等待 N 秒;退避 `4s × (attempt+1)`(共 3 次机会);仍失败触发换代理逻辑。
3. **WAF 假 200 识别**:HTTP 200 但响应体不是合法 JSON ⇒ WAF 拦截,提示换代理,**不清空已有额度数据**。
4. **代理**:socks5(默认 `127.0.0.1:10808`);429 时自动探测本机其它存活 socks 端口切换,60s 冷却防横跳;代理失败自动回落直连。
5. **超时**:连接 15s / 读取 20s。
6. **兜底**:代理与直连均不可达 ⇒ 明确报错,不静默吞。

**OAuth 回调安全规则(平移 `OAuthCallback.java`)**

| 判定 | 条件 | 动作 |
|---|---|---|
| `shouldExchange` | 同域 && hasCode && hasState && stateMatches | 执行交换 |
| `missingCode` | 同域 && !hasCode | 明确失败报错 |
| `badState` | 同域 && hasCode && (callbackPath \|\| hasState) && !stateMatches | 拒绝,防串流/CSRF |

回调路径不限定 `/oauth/*`(v0.5.1 起,兼容根路径/hash 路由);日志只记 host/path/参数名,**绝不记 code/state 值**。

**自动填充选择器契约(来自 `AuthFillJs.java`,逐一平移到 Playwright locator)**

| 场景 | 选择器(原文照搬) | 动作 |
|---|---|---|
| GitHub 登录框 | `#login_field` | 填账号 |
| GitHub 密码框 | `#password` | 填密码 |
| 登录按钮 | 含 sign in / 登录 的按钮/链接 | 自动点(可关) |
| 2FA 非 TOTP 默认页 | "Use authenticator app" / "使用验证器应用" 链接(text 匹配) | 先点切换,再填码 |
| 2FA TOTP 框 | `#app_totp` \| `#otp` \| `input[name*=totp]` \| `input[name*=two]` \| `input[autocomplete=one-time-code]` | 填 6 位码(满 6 位才提交) |
| 人机验证挂件 | `.cf-turnstile, #cf-turnstile, [data-sitekey], .g-recaptcha, .h-captcha` 且未产出 token | **只填不点** |
| token 已产出检测 | `[name=cf-turnstile-response], [name=g-recaptcha-response], [name=h-captcha-response]` | 已有值 ⇒ 可继续 |
| SPA 动态渲染 | MutationObserver 45s | DOM 变化继续尝试填 |

**签到流程契约(来自 `CheckinJs.java`)**

```
1. GET /api/status → CHECKIN_ON / TS_ON / turnstile siteKey
   checkin_enabled===false ⇒ 显示"站点未开启签到",结束
2. GET /api/user/checkin?month=YYYY-MM → 当月 records + stats
   今日已签 ⇒ 显示奖励三态,结束(不 POST)
3. POST /api/user/checkin
   响应文本匹配 /turnstile|captcha|验证|校验|人机|challenge|robot/i ⇒ 被拦
   未被拦 ⇒ 成功,进入奖励三态
4. 被拦 ⇒ 两级自动处理,**全部失败即报错,不转人工**(签到 100% 自动化):
   - 第一级:挂官方挂件(challenges.cloudflare.com/turnstile/v0/api.js?render=explicit
     + render(box,{sitekey, appearance:'interaction-only'})) → 拿 token
     → POST /api/user/checkin?turnstile=<token>
   - 第二级:StealthyFetcher(solve_cloudflare=True) 整页求解后重试 POST
   - 两级都过不去 ⇒ 记失败日志 + 报错(含拦截原因),等下一轮调度或用户换代理
5. 奖励三态:
   - 有今日记录且 quota_awarded>0 → 显示 "+$28.07 今日签到"
   - 有今日记录但 quota_awarded==0 → 显示「本站无签到奖励」
   - 查不到记录(只能确认已签) → 只显示「已签」,不显示金额
```

### 3.1 项目结构

```
pc/  (Python Core, 新目录, 替换 src/)
├── main.py              # FastAPI 入口: 挂 API 路由 + 静态 WebUI + 调度启动
├── engine/
│   ├── __init__.py
│   ├── site_client.py   # SiteClient: 站点 API 调用(FetcherSession, 契约见 3.0)
│   ├── oauth_flow.py    # GitHub OAuth 自动化(StealthyFetcher headless 为主)
│   ├── silent_auth.py   # 凭据交换: JWT exp 判定 / 401 重换 / 8s 复用 / 90s 冷却
│   ├── checkin.py       # 签到: 前置判定 → POST → Turnstile 两级兜底
│   ├── authfill.py      # 自动填充: 账号密码 / 2FA / "Use authenticator app" 切换
│   ├── proxy.py         # 代理管理: socks5 / ProxyRotator / 429 换节点
│   └── session.py       # 站点×账号 cookie 隔离(user_data_dir + FetcherSession)
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

### 3.2 Scrapling 功能选用清单(参数已对照官方文档核实)

**按需选用,不全家桶;能用的增强全部用上。** 本项目定位「定时 API 客户端 + 少量浏览器自动化」:

**A. 网络传输层(日常签到/额度刷新)**

| 功能 | 用? | 选法 | 场景 |
|---|---|---|---|
| TLS 指纹伪装 | ✅ | `FetcherSession(impersonate='chrome')` | 日常站点 API 调用,降低 WAF 拦截率 |
| 隐私请求头 | ✅ | `stealthy_headers=True`(默认开) | 自动生成真实浏览器头 + Google referer |
| Cookie 持久会话 | ✅ | `FetcherSession` 上下文管理器 | cookie 型站点自动维持会话;比单请求快约 10 倍 |
| 多指纹轮换 | ✅ | `impersonate=["chrome","firefox"]` 列表随机选 | 每站点固定指纹反易被画像;列表轮换更稳 |
| 通用重试 | ✅ | `retries=2, retry_delay=1` | 网络抖动;**429 逻辑自实现**(见 3.3) |
| ProxyRotator | ✅ | `ProxyRotator(proxies=[...])` 传 Session;浏览器场景每代理独立 context,所用代理在 `response.meta['proxy']` | 多代理轮换 + 429 换节点 |
| DoH(DNS-over-HTTPS) | ✅ | 浏览器 fetcher `dns_over_https=True` | 走代理时防 DNS 泄漏 |
| SSRF 安全跟随 | ✅ | `follow_redirects='safe'`(默认) | 跟随重定向但拒绝内网/私有 IP,回调链路安全 |
| 客户端证书 | ❌ | `cert` 参数 | 站点无此要求 |

**B. 浏览器自动化层(授权/静默换凭据/Turnstile 兜底)**

| 功能 | 用? | 选法 | 场景 |
|---|---|---|---|
| Cloudflare 求解 | ✅ | `StealthyFetcher(..., solve_cloudflare=True)` | Turnstile/Interstitial;POST 被拦时的兜底 |
| 指纹防护 | ✅ | `hide_canvas=True, block_webrtc=True, timezone_id` | 隐身增强(WebGL 保持默认开,禁用反而被 WAF 检出) |
| `user_data_dir` | ✅ | 每站点×账号一个目录 | **授权会话持久化核心**:GitHub 登录态存本地,静默换凭据秒级完成 |
| 标签页池 | ✅ | `StealthySession(max_pages=N)`(0.4.15 起复用标签) | 多账号并行授权复用浏览器,省启动开销;`get_pool_stats()` 暴露给 WebUI 监控 |
| `page_action` | ✅ | 导航后回调,拿 Playwright page 做自动填充 | 全部 AuthFill 逻辑(填账密/点登录/2FA 切换) |
| `page_setup` | ✅ | 导航前回调 | 注册路由/事件监听(如监听 GitHub 会话过期跳转) |
| `wait_selector` + 状态 | ✅ | `wait_selector='#login_field', wait_selector_state='visible'` | 比 sleep 更可靠的「等登录框出现」;4 种状态 attached/detached/visible/hidden |
| `network_idle` | ✅ | 授权页/回调页等待 | SPA 回调页加载完成判定(至少 500ms 无网络连接) |
| `capture_xhr` | ✅ | `capture_xhr=r'/api/oauth/'`(正则) | **授权 token 交换首选**:回调页前端自己发的交换请求响应自动收进 `response.captured_xhr`,免注入 JS |
| `init_script` | ✅ | 页面创建时执行的 JS 文件 | 注入 MutationObserver 等 AuthFill 辅助脚本(SPA 动态渲染 45s 重试) |
| 广告/资源屏蔽 | ✅ | `block_ads=True` + `disable_resources` | 浏览器提速(~25%),屏蔽 font/image/media 等 |
| `real_chrome` / `executable_path` | ✅ | 指向本机 Chrome | 真实浏览器指纹比 bundled Chromium 更稳;CI/服务器无 Chrome 时回落 |
| CDP 接管 | ✅(兜底) | `cdp_url=...` | 连已运行的真实浏览器(授权方式 B 变体) |
| `google_search` referer | ✅(默认开) | 自动设 Google referer | 首次访问像从搜索点进来,更像真人 |
| `locale` / `timezone_id` | ✅ | 与代理出口地一致 | 指纹一致性(走美国代理却带中国时区会被识破) |

**C. 响应解析层**

| 功能 | 用? | 选法 | 场景 |
|---|---|---|---|
| `Response.body` / `.status` / `.headers` | ✅ | — | 站点 API 全是 JSON,`json.loads(resp.body)` 即可;WAF 假 200 判定看 body 是否合法 JSON |
| `captured_xhr` 逐项 | ✅ | `.url / .status / .body` | 授权交换响应直接读 |
| CSS 选择器解析 | ✅(轻量) | `page.css('#login_field')` | 自动填充前探测页面元素是否存在(2FA 切换链接等) |
| adaptive 自适应选择器 | ❌ | — | 本项目表单选择器固定且已验证,无需自适应重定位 |
| `find_similar` / `below_elements` | ❌ | — | 非爬虫场景 |

**D. 明确不用的**

| 功能 | 理由 |
|---|---|
| Spider 爬虫框架(含 AutoThrottle) | 不是爬虫;限速在 SiteClient 自实现(见 3.3) |
| HTTP/3 | 与 impersonate 有兼容问题,签到场景无收益 |
| 导出器(JSON/CSV/XML)、流式抓取、断点续爬 | 非批量采集场景 |
| CLI(`scrapling shell/extract`)、MCP server、Agent Skill | 开发期可临时用 `scrapling shell` 调试站点,不进运行时 |
| 存储系统(SQLiteStorageSystem) | 配置/日志用自有 JSON 方案(兼容原仓库格式) |

### 3.3 自动限速的准确答案(v1.1 澄清)

**问题:是用了 Fetcher 就会自动限速吗?——不是。**

查证结论(官方 readthedocs + 中文 README):

1. **AutoThrottle(自动限速)是 Spider 爬虫框架的特性**:按域名自适应延迟、被封时延迟翻倍或按 `Retry-After` 等待、恢复后提速。它只在 Spider 里生效。
2. **单独用 `Fetcher`/`AsyncFetcher`/`FetcherSession` 不会自动限速**:Fetcher 层只有通用 `retries`(默认 3)/`retry_delay`(默认 1s),**不识别 429/Retry-After**——对 429 也照样立即重试,在签到场景是危险行为(越撞越死)。
3. **本项目不用 Spider**,因此限速必须**在 SiteClient 层自实现**,原仓库逻辑正好完整平移:

```python
class SiteClient:
    # 平移 AuthActivity 429 处理 + Engine 代理切换
    RETRY_BACKOFF = [4, 8, 12]          # 4s × (attempt+1), 共 3 次机会
    PROXY_SWITCH_COOLDOWN = 60          # 秒, 防横跳
    TIMEOUT_CONNECT, TIMEOUT_READ = 15, 20
    def _handle_429(self, resp): ...            # 读 Retry-After, 退避
    def _switch_proxy_on_429(self): ...         # 探测本机备用 socks 端口并切换
    def _detect_waf_fake200(self, resp): ...    # 200 但非 JSON ⇒ WAF 拦截
```

另外两条与限速互补的节流(平移 SilentAuth,防「一次刷新打 4 个接口各换一次凭据」):

| 保护 | 参数 | 作用 |
|---|---|---|
| 同账号串行 + 单轮 token 缓存 | asyncio.Lock | 一轮刷新只交换 1 次 |
| 成功后复用窗口 | 8s | 连点刷新不重复交换 |
| 失败冷却 | 90s | GitHub 会话真失效时不反复打站点(手动授权可清) |

### 3.4 模块职责与 API 对照

| 原 Node/Java | 新 Python 模块 | 关键差异 |
|---|---|---|
| `client.js` SiteClient | `engine/site_client.py` | axios → Scrapling `FetcherSession`(TLS 指纹伪装);SOCKS 代理走 ProxyRotator;同签名 `status() self() usage_log() checkin()`;**接口契约复用原仓库(见 3.0),代码全新** |
| `auth.js` / `SilentAuth.java` | `engine/oauth_flow.py` + `engine/silent_auth.py` | puppeteer → scrapling `StealthyFetcher`(headless);流程(flow_token → 授权 → 回调交换 → 落盘)按 3.0 契约重写 |
| `AuthFillJs.java` | `engine/authfill.py` | JS DOM 操作 → Playwright locator(在 `page_action` 回调里);选择器按 3.0 契约逐一平移 |
| `CheckinJs.java` | `engine/checkin.py` | 前置判定、奖励三态解析逻辑全部保留;Turnstile 挂载由 Python 注入同款 JS,POST 被拦时先 interaction-only、再 StealthyFetcher 求解兜底 |
| `Engine.java` 401 重试 | `silent_auth.py` 装饰器 | `@ensure_credential(account)` 包裹业务请求,401/exp→静默换凭据→重试 |
| WebView Profile | `engine/session.py` | 每「站点×账号」一个 `user_data_dir` 目录(等价 WebView Profile 分区),cookie 隔离 |
| WorkManager / node-cron | `service/scheduler.py` | APScheduler CronTrigger |
| `Store.java` Keystore | `service/crypto.py` | 主密钥 `data/secret.key`,本地生成并 chmod 600 |

---

## 4. WebUI 化设计(核心改造)

### 4.1 形态

- **服务端**:FastAPI 同时托管 `web/static/` 与 `/api/*`。默认监听 `0.0.0.0:7300`,局域网可达(`http://<服务器IP>:7300`)。
- **前端**:直接采用原 `src/index.html` 单一暗色页面(首页总览 / 账号 / 站点 / 日志&设置 / 引擎设置 五个 tab),替换 API 调用基地址为同源 `/api/*`(原生就是同源相对路径,几乎零改动);新增一处「授权回调入口」逻辑。
- **登录态/鉴权**:默认内网可信无鉴权(与原 Node server 一致);可选开启「简易令牌」——访问 WebUI 需填 `JUSTSIGN_TOKEN`(前端 localStorage 持久化,请求带 `Authorization` 头)。

### 4.2 新增/改动页面交互

| 交互 | 原实现 | WebUI 版 |
|---|---|---|
| GitHub OAuth 授权 | 安卓内嵌 WebView 引导 / Electron 窗口 / Node 脚本 | 点「授权」→ 后端起 headless 流程(方式 A,纯后台),失败依次提示降级 B/C;**默认无弹窗** |
| 签到 | 点按钮触发原生流程 | 点按钮 → `POST /api/checkin/{account}` → 结果 + 日志即时回显(SSE 推送) |
| 定时任务 | WorkManager / node-cron | `POST /api/settings` 保存 cron 表达式,APScheduler 生效 |
| 日志 | 页面轮询 `/api/history` | 保留轮询 + 新增 SSE 实时流 |
| 代理设置 | 设置页表单 | 同保留(socks5 host/port/enabled + ProxyRotator 列表) |
| **新增:授权中状态页** | — | 授权进行中显示「headless 授权中…(预计 10s-3min)」+ 当前步骤;失败显示 B/C 降级按钮 |
| **新增:凭据库管理** | App 内 SQLite+Keystore | WebUI 表单:站点账号/密码/TOTP 密钥(写后即加密,读不回显) |

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
POST   /api/oauth/start                   # 发起 headless 授权(方式 A) → 返回 task_id
GET    /api/oauth/status?task=            # 查询授权任务进度(A 跑到哪步/失败原因)
POST   /api/credentials                   # 新增:写凭据(账号/密码/TOTP 密钥, 加密存储)
GET    /api/proxy-test
GET    /api/events                        # SSE 实时日志流
```

> 与原 server.js 的差异:新增 `/api/oauth/start` + `/api/oauth/status`(授权是长任务,需异步句柄)、`/api/credentials`(凭据库从 App 本地搬到服务端);原 `/api/refresh` 端点(返回"授权需在 App 内完成")**删除**。

---

## 5. OAuth 授权改造(v1.1 修订:纯后台优先)

### 5.1 原流程(契约不变)

```
1. POST /api/oauth/state(404 则 GET ?mode=login) → flow_token
2. GET  /api/status → github_client_id
3. 浏览器打开 https://github.com/login/oauth/authorize?client_id&state&scope=user:email
4. (自动填充账号密码 / 2FA / 切 authenticator)         ← 自动化层职责
5. 等回调:站点同域 + hasCode + state 严格匹配 ⇒ shouldExchange(见 3.0 安全规则)
6. 回调页上下文内交换 /api/oauth/{provider}?code&state → access_token
7. 落盘:token + cookie + githubAccount + siteUserId(data.id) + updatedAt
```

### 5.2 授权方式:纯后台优先,弹出浏览器仅兜底

**方式 A(默认,纯后台 headless 全自动)**

用户点「授权」→ 服务端全程 headless 完成,零弹窗:

1. `FetcherSession` 纯 HTTP 拿 flow_token + client_id(不起浏览器;站点前置 Cloudflare 时改用 `StealthyFetcher.fetch(site_login_url, solve_cloudflare=True)` 过挑战后再取)。
2. `StealthyFetcher.fetch(github_authorize_url, headless=True, solve_cloudflare=True,
   user_data_dir=data/profiles/<site>/<account>, block_ads=True, disable_resources=True,
   capture_xhr='/api/oauth/', page_action=<auto_fill>)`:
   - `user_data_dir` 指向「站点×账号」专属目录 ⇒ **GitHub 登录态 cookie 持久化,第二次授权起免登录**(即 SilentAuth 语义)
   - `page_action` 回调内做全部自动填充(选择器契约见 3.0):填账号密码 → 点登录 → 2FA 切 authenticator + 填码(6 位码由服务端 `pyotp` 凭 TOTP 密钥现场生成)→ 等回调跳转
   - `capture_xhr='/api/oauth/'` 自动捕获回调页前端自己发出的交换请求响应,直接读出 `access_token`(**首选**;主动 evaluate fetch 作为备用)
3. 校验 OAuthCallback 规则(同域 + code + state 严格匹配)后,由**服务端直接 GET `/api/oauth/{provider}?code&state` 完成交换**(等价原版 OkHttp 直调;`capture_xhr` 里回调页前端的交换响应可作交叉验证),**抓响应头 `Set-Cookie` 拼 `siteCookie`**(cookie 型站真凭据,见 3.0 规则),连同 token/`data.id`(siteUserId)一起落盘。
4. 预估耗时:已有会话 <10s;首次登录 1-3 分钟(自动填充等待)。

**方式 B(有头浏览器,手动触发的兜底)**

方式 A 失败(GitHub 风控要求设备验证/滑块等人工交互)时,WebUI 提供「在服务器上弹出可见浏览器」按钮:

- `StealthyFetcher(..., headless=False)` 弹真浏览器(服务器需有桌面/Xvfb/VNC;无桌面则按钮置灰)
- 用户手动完成登录/验证,后端继续监听回调完成交换
- **仅兜底,不默认**

**方式 C(手动授权指引,零自动化,永远可用)**

原 `auth.js` 手动指引平移,作为最终兜底:

1. 后端生成授权 URL 返回给 WebUI
2. 用户在自己电脑浏览器打开 → 完成 GitHub 授权 → 回到站点任意页
3. F12 → Network → 找 `/api/oauth/{provider}` 响应 → 复制 `data.access_token`
4. WebUI 粘贴 token 完成绑定(`POST /api/accounts/save`)

### 5.3 静默换凭据(SilentAuth 平移,含「免退出重登」,全站统一路径)

**核心:不实现任何 logout 接口,所有站点统一走"静默重放一遍 GitHub OAuth"换新凭据。** 每次重放服务端都下发全新凭据(cookie 型账号 = 全新 `Set-Cookie` session,旧会话自然作废,等价"退出+重登";token 型账号 = 新 `access_token`),一套流程覆盖全部站点(见 3.0「重新登录」语义)。

Python 侧 `silent_auth.py` 完整规则:

- **触发**:JWT `exp` 剩余 < 60s 预判换新;或业务请求 401 兜底换新(换完重试一次,标记 `reauthed:true`)
- **换新流程** = 方式 A headless 流程,复用「站点×账号」`user_data_dir`(GitHub cookie 在,秒级完成):`fetch /api/oauth/state` → 打开 authorize URL(**带 `login=<期望账号>` 参数**,强制指定 GitHub 账号,防浏览器里登录了别的账号串号)→ 交换 → 落盘
- **落盘内容**:token(三字段名兼容,可能为 null)+ `siteCookie`(从交换响应 `Set-Cookie` 抓取,跳过删除态)+ `siteUserId`(`data.id`);**token 或 cookie 任一变化即算换新成功**
- **防风暴**:同账号串行(asyncio.Lock)+ 成功后 8s 内复用(`LAST_OK`)+ 失败后 90s 冷却(`FAIL_UNTIL`,手动授权可清)
- **转人工判定**:重放途中浏览器导航到 `github.com/login`、`/session`、`two-factor`、`verified-device`、`sudo` 任一 URL ⇒ GitHub 会话本身过期,转方式 B/C(AuthFill 自动填充账密/2FA);会话已登录却卡授权确认页 8s ⇒ 快速转人工不空等
- **身份锚点校验(B1 分层)**:强判据 = 响应有 `github_id`/`github_user_id` 且账号已缓存 githubId,不等即拒;弱判据 = 无 github_id 数据时回退 username 比对;都拿不到 ⇒ 跳过(不误拒)。站内名 `github_<站内id>` 与 GitHub 用户名无关,不可比
- **凭据库**:站点账号/密码/GitHub 用户名/TOTP 密钥,AES-256-GCM 加密落盘(主密钥 `data/secret.key`,0600);TOTP 码由 `pyotp` 现场生成

### 5.4 与原版行为对照

| 原版 | 新版 | 备注 |
|---|---|---|
| SilentAuth 离屏 WebView 后台交换 | 方式 A headless StealthyFetcher | 等价;`user_data_dir` 持久化比 WebView Profile 更稳 |
| AuthActivity 可见 WebView(需人工时) | 方式 B 有头浏览器 | 兜底,不默认 |
| auth.js 手动指引 | 方式 C | 永远可用 |
| WebView Profile 分区(站点×账号) | `user_data_dir` 目录隔离 | 一一对应 |
| AuthFillJs 注入 + JS 自动填充 | `page_action` + Playwright API | 选择器契约照搬(3.0) |
| 2FA 码用户手动输入 | **新增:pyotp 自动生成 TOTP** | 凭据库存 TOTP 密钥 |
| OAuth 交换 OkHttp 直调 + 抓 Set-Cookie | FetcherSession 直调 + 抓 Set-Cookie | 凭据字段化通用规则(首个实例 AgentRouter),平移 |
| authorize URL 带 `login=<账号>` | 保留同参数 | 防 GitHub 账号串号 |
| GitHub 过期 URL 判定转人工(login/session/two-factor/verified-device/sudo) | 保留同清单 | 原版实测定案 |

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

同时,**行为层放开**:将 Turnstile 处理从「仅 interaction-only 静默」升级为两级全自动:POST 被拦时先挂官方挂件(interaction-only,无需交互静默过);仍过不去则用 StealthyFetcher 的 Cloudflare 求解能力(`solve_cloudflare=True`)自动过。**两级都失败 ⇒ 明确报错记日志,不提供任何人工签到兜底**——本版定位是全自动化,签到不允许"转人工"路径;授权流程(§5)不受此限,其 B/C 人工兜底保留。

---

## 8. 部署与运行

### 8.1 服务器(本地 Linux/Windows 均可)

```bash
# 环境: Python 3.11+
pip install "scrapling[fetchers]" fastapi uvicorn apscheduler cryptography pyotp
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
| 三种站点形态 | 保留;`web` 形态标记「不支持自动签到」(不提供人工签到入口,见 §7) |

---

## 10. 风险与对策

| 风险 | 对策 |
|---|---|
| GitHub OAuth 全部依赖浏览器自动化,故障面大 | 三级授权降级链:A headless 默认 → B 有头兜底 → C 手动永远可用;凭据库自动填充可关 |
| headless 授权首次需填 GitHub 账密/2FA | 方式 A `page_action` 全自动填充(凭据库已存则无感);首次或凭据缺失时降级 B/C |
| Scrapling StealthyFetcher 对某些站 Cloudflare 求解失败 | 记失败日志报错,等下轮调度或用户换代理重试;**不转人工签到**(全自动定位) |
| Python 异步生态与 Scrapling 浏览器 fetcher 混用 | 浏览器操作放独立线程池(`asyncio.to_thread`),不阻塞 FastAPI 事件循环 |
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