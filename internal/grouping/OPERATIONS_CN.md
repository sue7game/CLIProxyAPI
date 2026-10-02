# CPA 本地凭证分组：运行、恢复与上游升级说明

更新日期：2026-10-03。适用于当前本地 P 阶段实现，不适用于 Home 双端分组。

已完成 CPA v8.0.11 与管理面板 v1.25.2 的本地合并及验收。管理 API 使用 `/v8/management`，Go 模块使用 `/v8`，后端保留上游的 v0 兼容路由。上游同步的验证证据与此前 P 阶段基线分开记录。本文件不构成已部署、全平台原生运行通过或真实提供商网络兼容承诺。

## 1. 支持范围与不能混淆的概念

### 1.1 本地支持边界

- 单 CPA 写者、本地文件凭证存储。本地策略不能因使用共享卷就自动变成多副本同步系统；远端 auth store 不在当前分组支持范围内。
- 一个令牌或凭证属于一个具体组或 `all`。令牌为 all、凭证为 all、双方同组，任一成立即通过分组资格检查；禁用、模型、路由、配额等原条件继续叠加。
- 管理员仍管理全部分组；这是凭证使用范围，不是管理 RBAC、完整租户隔离或视频任务逐令牌所有权。
- CPA 拒绝 `Home.Enabled && Grouping.Enabled`。本轮不实现 H0–H4、不修改 Home 仓库，不重新打开 Home 模式下已关闭的本地管理入口。
- 分组开启时拒绝无法核验凭证归属的插件直接调用；关闭时恢复原代理授权行为。已初始化的来源 UUID/事务保护不会因此被删除。
- 分组开启时直连 Realtime SDP 媒体返回 503，仅允许 CPA 能关闭的媒体中继。普通 API/Realtime WebSocket 仍可用，但须通过分组授权。
- 未完成稳定身份适配的动态/插件来源不能自动 all。受控 auth 文件上传当前拒绝一文件多凭证和跨文件移植 UUID；不是对任意插件的兼容承诺，也不是对恶意本地进程的沙箱。

### 1.2 UUID、all 与登记状态

配置凭证永久字段为 YAML `grouping-id`；auth JSON 为 `grouping_id`。同一个上游 key/OAuth 账户的每条独立来源记录有不同 UUID，可以分到不同组。不要因为秘密相同而去重，也不要把当前下标、文件名或 Auth.ID 当成永久主键。

下游 API keys 保持字符串数组；服务端以鉴权 provider 和实际 principal 的 HMAC 关联逻辑 UUID。相同下游 key 字符串不能区分两名调用者；上游重复记录可分组，不意味着重复下游字符串能拥有不同权限。

| 名称 | 含义 |
|---|---|
| 所有分组 / `all` | 对已登记有效对象的通配归属，不是跳过原限制 |
| 全部归属 | 管理列表不过滤，不是一个可以绑定的组 |
| `active` | 可参与分组判断，仍受其他限制 |
| `pending_rebind` | 来源身份待核对，不能调度；不是自动回到 all |
| `tombstone` | 来源消失后的保留登记，不能调度；重现先待确认 |

## 2. 数据位置与首次启用

### 2.1 位置与前置条件

配置项示意，不应借此直接修改正在运行的启停状态：

```yaml
grouping:
  enabled: false
  store-path: "grouping-policy"
```

未指定路径时使用 `grouping-policy`；相对路径以配置文件所在目录解析，而非进程工作目录。选择持久、安全的本地存储；不要放在源码、临时目录、构建产物或 `.helloagents` 中，也不要手动预建空策略目录后期望初始化覆盖它。

初始化/启用需要至少一个可认证的 API key、本地 FileTokenStore、可读取并验证的来源和可写配置/auth 目录。初始化会向来源写入永久 UUID，**不是只读扫描**。先备份配置和 auth 文件，再安排变更窗口。

尚未初始化分组时，v8 配置保存保留上游的原位写行为，兼容单文件 bind mount。初始化后来源写入必须支持同目录原子替换与恢复日志（即使分组暂时关闭）；容器请挂载可写目录，不依赖只允许原位写的单文件挂载。替换失败会拒绝操作，不静默降级为不安全写入。

策略目录采用私有文件权限/平台 ACL 检查和 OS 单写者锁；宽权限、路径替换、密钥或快照异常可能被拒绝。不要放宽到公共可写，也不要通过删 `.writer.lock` 试图允许两个进程同时写。

### 2.2 首次初始化到启用的顺序

1. 先确认当前是本地模式，并在需要严格隔离时关闭外部代理入口，避免尚未启用分组期间继续走旧授权。
2. 登录有管理鉴权的面板，读取 `/v8/management/grouping/status`。尚未初始化与已初始化但不健康是两种状态，后者不能重新初始化覆盖。
3. 执行显式 initialize。实现先校验来源、补 UUID、准备完整暂存策略，再发布策略目录与安装回执；已有可验证对象登记为 all，成功不会自动启用分组。
4. 检查 initialized、healthy、revision 和 pending_count；核对重复记录仍是独立 ID。缺稳定身份、无效记录、UUID 冲突须先处理，不以空列表当成功。
5. 创建具体组，分别选取令牌和凭证改组。查看预览，确认范围扩大；首次初始化后全部为 all，所以“只启用开关”本身不会产生分组隔离。
6. 通过 activation 管理端点启用，不直接热改 YAML 标记。启用前重新检查来源与不兼容模式，并防止直连媒体在切换期间进入。
7. 用隔离测试实例检查同组允许、异组拒绝和两种 all；确认健康后才按既有发布流程恢复业务入口。本任务没有代替管理员执行生产启用或上游试跑。

初始化中断时，已写入的来源 UUID 可能保留；只有尚未发布正式策略/安装回执的初始化才可在检查后重试。遗留 `.grouping-initialize-*` 暂存目录不会自动复用，不能擅自将其改名作为正式策略。

## 3. 日常管理与兼容行为

### 3.1 创建、改组、轮换与删除

- **新对象通过原创建入口默认 all，随后显式改组。当前没有创建时指定组的原子接口。** 若业务要求从首次可调度起就在特定组，现有两步操作无法保证；可在关闭外部入口的维护窗口完成创建与改组，不能用关闭分组作为隔离措施。
- 将来增加创建时选组，必须在同一事务完成来源保存、目标组、身份登记与发布，不能先对流量发布 all，再补调用改组接口。
- 编辑重复配置记录时保留各自 `grouping-id`。不要复制已有 ID 来新建第二条记录；新建由服务生成 ID，受控替换保留原 ID/组。
- 明确单令牌 old/new 的受控轮换保留逻辑 token ID 和组。整体 PUT 同时删旧加新且无法明确意图会冲突；不能靠删除后重建来承诺继承权限。
- OAuth 重新登录/上传经 prepare → 保存 → finalize → 运行态发布；保存方须保留 prepare 设置的 `Auth.Storage`。正常 token 刷新不以 access/refresh token 重算长期账户身份。
- 外部文件改动或未知新增可能进入 pending；无关配置保存不会顺便批准它。来源删除留下 tombstone，同身份重现先待确认，不自动恢复通配。
- 停用渠道保留原 UUID/组及 active 登记，不等于仍可调度；运行态凭证及其模型同步撤销。分组开启时，配置发布窗口暂停新授权，完成同步后才恢复；失败继续拒绝。迟到 watcher 事件不能推翻已接受配置。
- 删除具体组要求不存在任何登记引用，包括 pending/tombstone。当前没有强制清理历史身份的 API；不能承诺删除来源文件后该组立即可删，更不能手改 policy 绕过引用检查。
- 停用分组会扩大权限，必须显式确认；策略、UUID、回执保留。重新启用仍须重新验证来源，不是恢复旧缓存即可。

### 3.2 API 版本、筛选与预览

新面板的分组 API 位于现有管理鉴权组 `/v8/management/grouping`，不回退 v0。管理密钥不要放 URL、截图、日志或导出文件；列表只提供安全 ID、provider、来源标签、归属与状态，不输出原 key/fingerprint。

- 初始化之外的写请求用单一带引号的 `If-Match` 修订号。412 表示需刷新，409 表示业务冲突/缺确认，503 表示不可用，不能当作写成功。
- 成功返回 `applied_revision`。普通批量绑定先整体校验；来源/磁盘失败可能留下恢复日志，不能推断每次失败都等于任何文件都未改变。
- v8 配置 GET 返回整份持久化文档的 ETag，与分组策略 revision 不同。删除已有凭证或令牌须携带对应来源快照的 `If-Match`；缺少返回 428，过期返回 412。读取新 ETag 后继续提交旧列表仍是不安全做法。
- 显式令牌轮换使用 `PATCH /v8/management/access/api-keys`，JSON body 为 `old/new`，不在 URL 中传令牌；保留原逻辑 ID 和分组。不把普通列表中的同时删除与新增推断为轮换。
- v8 提供商配置是渠道及嵌套 `keys` 列表。每条 key 保留独立 `grouping-id`；OpenAI 兼容无 key 渠道的身份位于渠道自身。原始 null、空值、继承关系和插件不透明配置不得被运行态默认值覆盖。
- 实际筛选：`filter_mode=actual`，省略 group_id 表示全部归属，`group_id=all` 只看实际 all；包含 pending/tombstone。
- 可访问筛选：仅 credentials 接受 `filter_mode=accessible` 且必须有 group_id；只看分组规则允许的 active 来源。具体组包括自身/all，all 包括所有 active，不代表配额或健康可用。
- limit 为 1–500；offset 非负、要求 limit。分页元数据是 `pagination.total/offset/limit`；同次响应由一个快照生成，多页 revision 不同应重新读取。
- 当前前端加载完整同 revision 快照，列表筛选/25 条分页在浏览器本地完成；服务端上述 query 能力不等于当前页面已采用服务端分页。
- preview 是只读的当前策略比较，不是提交预约；真正写入仍校验 CAS。改组到 all 可能涉及未来对象，所以当前新增访问数为零也可能要求权限扩大确认。
- `credential_access_changes` 按 active 令牌报告可访问凭证集合计数，包含未选中但受影响的令牌；重复凭证按不同 UUID 计数。
- 模型范围是 `registered_model_catalog`：同一次内存目录中已注册公开模型的并集，包含既有 alias/prefix 和 disabled 处理，不访问上游。
- `models_available=true` 才能将 `model_access_changes` 当模型差异；false 时字段为 null 并带受限原因码。不能显示成“没有模型变化”，也不能把模型预览作为配额、健康、冷却或请求成功预测。

详细字段和后端回调契约见 `internal/api/handlers/groupingapi/API.md`。模型预览真实 Service HTTP 测试、本地页面展示/筛选/分页联调均已通过，未发起真实上游请求。

## 4. 备份：作为一个一致性集合保存

最稳妥的备份是在停止写入并关闭 CPA 后，保存同一时点的下列内容。单独复制 policy.json 或 auth 目录都不够；不要把备份放进公共仓库或日志。

| 必须保存的内容 | 原因 |
|---|---|
| 实际配置文件 | 包含下游 keys、上游配置、grouping 开关/路径及每条 `grouping-id` |
| 完整 auth JSON 目录 | 原认证材料、账户元数据及每条 `grouping_id` 必须与策略对应 |
| 整个策略目录，尤其 `policy.json` | 组、逻辑身份、状态、修订号、命名空间及绑定关系 |
| 同目录 `identity.key` | HMAC 身份与恢复签名依赖此密钥；丢失不能生成新密钥顶替 |
| 策略目录旁的 `<store-path>.initialized` | 安装回执，防止丢库被误当首次初始化；**不是策略目录内的 `.initialized`** |
| 若存在，`config.pending` / `activation.pending` | 未完成来源/启停事务的签名恢复依据，不能遗漏或人为清除 |
| 程序版本、配置/auth/策略原路径、必要运维日志 | 用于兼容性、绝对路径与故障时点核对；日志不是策略备份的替代品 |

默认布局示意：

```text
<配置所在目录>/config.yaml
<配置中的 auth-dir>/...json
<配置所在目录>/grouping-policy/
    identity.key
    policy.json
    .writer.lock
    config.pending       # 仅未完成来源事务时存在
    activation.pending   # 仅未完成启停事务时存在；与上者互斥
<配置所在目录>/grouping-policy.initialized
```

备份本身含认证秘密，应按原凭证备份流程限制访问、加密保存。journal 不含原来源字节，但包含路径、身份及前后策略，仍是内部安全材料。存在故障时先保存现场，不让“清理临时文件”删除未完成事务证据。

## 5. 崩溃恢复与故障处理

### 5.1 自动恢复能做什么

来源事务使用 `config.pending`，校验 schema、签名、规范来源路径、存在状态、前后哈希及策略状态；启停使用 `activation.pending`，校验版本、修订号、配置前后哈希与启停标记。只有能唯一识别的前态/后态才完成或取消恢复；未知状态拒绝，不自动赋 all。

OAuth staged 期间由 `sourcePending` 和事务锁排除普通改组、启停、rebind 与其他来源写入；watcher 不修改暂存恢复快照。最新配置副本暂存后，在 finalize 完成时同步重放，包括 watcher 的 `synthesize=false` 来源新增/停用；取消或失败保留队列并拒绝新授权。普通 watcher 的运行态同步、迟到 Add/Modify/裸 ID Delete 和 UUID 复用均有确定性测试，最终 Service 全包 race 已通过。

当前来源日志 schema 为 2，启停日志 version 为 1。未知/旧版未完成日志不会被当作兼容格式自动放行。恢复可能推进修订号，不能手改 revision 让旧 If-Match 继续通过。

初始化、缺失回执相关测试在当前 macOS 环境通过；Windows 回执代码修复不等于 Windows 实机持久化已验证，交叉编译也不能替代原生崩溃恢复验收。

### 5.2 异常处理表

| 现象 | 安全处理 |
|---|---|
| initialized=true、healthy=false，策略目录/密钥缺失 | 停止新业务，保留回执与现场，恢复一致备份；不重新 initialize |
| 来源 missing/重复 UUID、无效 JSON、无法识别稳定身份 | 核对原来源与副本，恢复正确数据；不清空 UUID 或改 all |
| pending_rebind | 核对该逻辑 ID 对应的真实来源，用最新 revision 和显式确认 rebind；保留原组，不接受随意客户端指纹 |
| tombstone | 来源已消失，不能调度；再次出现也先 pending，不把它当自动激活或新 all |
| journal 签名/哈希/路径不匹配，或两个 journal 同时存在 | 不删除日志尝试开机；保留现场，恢复同一时点的匹配配置/凭证/策略/密钥 |
| 宽权限、链接替换、持久卷权限异常 | 停止写者，恢复正确所有权/私有权限并检查完整性；不使用公共可写权限规避 |
| 写操作返回不确定失败 | 先读健康/修订状态，保存 journal 并按恢复流程处理；不要盲目重试扩大权限操作 |
| Home + grouping 配置 | 恢复本次支持的本地组合；不开放 Home 下本地管理接口绕过 |

管理状态不可用时，不保证在线 rebind 能修复；健康校验本身可能阻止管理写。不要把“可显式重新绑定”解释成策略损坏也能在线强制放行。

### 5.3 恢复顺序

1. 隔离外部代理流量，停止所有 CPA 写者；不要先关闭分组来排障。
2. 保存当前现场及日志，再选择匹配的配置、auth、完整策略、identity.key、旁路回执与 journal 集合。
3. 校验运行账号、私有权限、存储位置和二进制格式兼容。未完成 journal 绑定规范来源路径；不要搬目录后编辑日志中的路径/签名。
4. 恢复后先在隔离入口下启动，让程序进行校验和可识别恢复。若仍拒绝，保留错误，不重置策略或生成新 key。
5. 核对 namespace、当前 revision、健康、登记状态、组和来源数量，并检查备份之后的轮换/撤销。旧备份可能恢复已撤销令牌或旧权限，不能忽略这段差异直接恢复业务。
6. 完成隔离验证与人工核对后，按既有变更流程恢复入口。尚无跨平台真实故障演练证据的环境不能标记已验收。

## 6. 管理前端发布边界

分组页面在 [用户的管理前端 fork](https://github.com/sue7game/Cli-Proxy-API-Management-Center.git) 中，固定菜单不依赖插件，核心位于 `src/features/grouping/`，菜单/路由是少量原文件接入。

本次上游合并恢复新面板的插件菜单，同时保留不依赖插件的分组菜单、插件宿主及前端 fork 的 429 定制代码。本任务仅构建、验证本地源代码，未替换生产 `management.html`，也未改变自动资源更新策略。正式部署必须选择包含这些定制的前端构建及更新来源；自动下载官方原版仍可能移除分组入口。

既有兼容缺口：前端的旧 `auth-files/auto-429-probe`、`auth-files/auto-429-events` 调用在合并前后 CPA 中均无对应实现。这不是此次丢失路由，也不能宣称端到端可用。本轮保留前端代码，不新增假接口或另起一套 429 后端；它与已有插件机制及本次分组规则不同。

P 阶段基线通过 CUA 独立内置浏览器验收，没有绕过系统签名限制；覆盖初始化、分组 CRUD/删除保护、独立改组、筛选、凭证与模型预览、分页、409/412、断线锁定/恢复及危险确认。此次 v8 合并补验初始化、默认 all、重复记录独立改组、令牌绑定、启用、实际归属/可访问筛选及新版提供商表单保存后的 UUID/原组保留。390×844、1280×900 无全页横向溢出；弹窗焦点循环及 Escape 关闭后焦点恢复正常。

当前前端 1,494 项 Bun 测试、134 项分组 Node 测试、独立类型检查、lint 和构建通过。开发要求 Bun 1.3.14、Node 24+，旧 Node 会明确报错，不需要修改系统默认运行时。测试仅使用本地虚拟材料，未使用真实上游凭证进行提供商推理或 OAuth 登录；不据此承诺所有浏览器、语言和第三方环境兼容。

P 阶段截图为 `/tmp/cpa-grouping-acceptance-overview.jpg` 和 `/tmp/cpa-grouping-acceptance-final.jpg`；v8 最终静态产物截图为 `/tmp/cpa-v8-final-static.jpg`，移动端为 `/tmp/cpa-v8-grouping-mobile.jpg`。静态面板与冻结后端成功连接、读回重启后的分组，控制台无错误或警告。临时前后端进程与自建标签已关闭，视口恢复；未操作用户远端页面。

## 7. 低交叉接入点：上游更新核验清单

新增逻辑集中在 grouping 模块、Service `grouping_*.go`、通用 request_policy 接口和前端特性目录；上游原文件中的小接入仍是安全边界，不能因解决合并冲突而丢弃。以下是每次更新的待验收清单，不表示本次全部已关闭。

[ ] 配置字段/规范化：`internal/config/`、`sdk/config/grouping.go` 保留 grouping 配置与来源 UUID；原表单保存及配置去重不抹掉重复记录 ID，也不复活无效来源。
[ ] 来源合成：`internal/watcher/synthesizer/` 将配置/文件 ID 传到运行态；重排、刷新、路由编辑保持永久身份；新来源必须满足校验。
[ ] 服务装配：`sdk/cliproxy/service_lifecycle.go` 保留 prepareGrouping、backend、ConfigApply、AuthFileApply、OAuth 双 hook 和 plugin AuthFile applier。
[ ] 来源发布/热重载：`service_config.go`、`service_auth.go` 在运行态可用前完成登记；不把同步写退化为“改共享 cfg 后异步 watcher”。
[ ] OAuth 顺序：自定义 prepare 后才分组 prepare，保留 Auth.Storage，保存成功后分组 finalize，再做既有 runtime hook；`sdk/auth/filestore*` 不抹 UUID。
[ ] 可信主体：`server_middleware.go`、`sdk/access/`、`handlers.go` 的 context 桥接保留；客户端组字段和插件 metadata 不升级为权限。
[ ] 候选与发送：`sdk/cliproxy/auth/` 的 legacy/fast/mixed/plugin delegate、Execute/Stream/CountTokens、HTTP/注入/重试继续检查；新增直发入口也纳入。
[ ] 错误分类：授权拒绝不变成上游故障或跨组 fallback；重定向、refresh、后台维护仍使用正确可信范围。
[ ] 模型目录：各 handler、Codex models、registry 保留有权凭证并集、公开 alias/prefix、disabled 与缓存隔离，新增目录不能重新带回无权模型。
[ ] 长会话：Responses WS 新轮次、Realtime issuer/sideband/中继失权关闭、启用时禁止直连入场、视频稳定绑定与不明身份拒绝仍有效。
[ ] 插件宿主：callback 可信范围/宿主归属、凭证访问限制、流式与 HTTP 桥接、受控 auth 文件写入未被新 ABI 路径绕过。
[ ] 管理 CRUD：`internal/api/handlers/management/` 保留同步 hooks、轮换语义、UUID 与删除前置身份校验，插件配置安装/删除不能直接绕开事务。
[ ] HTTP 管理：`groupingapi` 仍位于既有鉴权下；ETag/CAS、确认、严格参数、脱敏、审计及错误码语义不被新路由绕过。
[ ] P6 预览：`groupingadmin.Options.ModelCatalog` 仍由 Service 注入；同一内存目录比较前后、无上游 I/O；不可用显示为 null/原因，而不是空差异。
[ ] Home 隔离：配置、运行就绪及 Manager 层继续拒绝不兼容组合，Home 原有本地管理关闭边界未放开。
[ ] 前端：固定入口、CRUD ID 保留、防误删、actual/accessible 区分、分页 revision、批量范围与确认仍有效；同时核验 fork 与下载面板功能差异。
[ ] 恢复/存储：policy/identity.key/回执/journal 全链路、单写者、平台私有权限及原子发布保持；新 schema 需迁移方案，不自动兼容未知格式。
[ ] 回归证据：重跑非 race 全库、受影响 race、vet、构建、平台检查及前端完整验收；不得只以没有编译冲突认定分组正确。

不复制调度器、不将组逻辑分散进各 provider executor/translator，是降低维护冲突的方式；并非可以跳过新上游路径审计的理由。恢复新文件但漏接原文件中的一个调用，仍可能失去隔离。

## 8. 升级、回滚与本轮证据

### 8.1 升级与回滚原则

升级先在独立临时配置/虚拟凭证实例合并和回归，不对真实配置试错；发布前按第 4 节建立一致备份。保持同一逻辑身份、命名空间及可解释的修订迁移，不混用新旧进程写同一目录。

**不支持分组的旧版二进制可能忽略新配置并按原 API keys 放行，造成分组绕过。** 不能将只换回旧二进制、删除策略、移除安装回执或清空 UUID 当成安全回滚。确需降级时先隔离入口，确认有等效外部限制或不再提供服务，再制定完整数据与权限恢复方案；本任务未执行任何生产回滚。

### 8.2 P 阶段基线证据（上游合并前）

- 冻结后的非 race 全库：`/tmp/cpa-final-oct03-all-tests.log`。
- 冻结后的 Service 全包 race：`/tmp/cpa-final-oct03-service-race.log`；API 全部子包 race：`/tmp/cpa-final-oct03-api-final-race.log`。
- Store/admin 不可变索引、失权与并发检查：`/tmp/cpa-final-oct03-store-admin-race.log`；admin pending/tombstone 引用删除保护：`/tmp/cpa-final-oct03-admin-references-race.log`。
- 其他请求链 race 的范围和日志逐项列在 P0 记录；最终全库覆盖 Service HTTP 预览、来源事务、初始化、模型与插件桥接。
- 最终 vet/原生构建：`/tmp/cpa-final-oct03-vet.log`、`/tmp/cpa-final-oct03-build.log`。
- Windows/Linux 服务端及 Windows Service/存储测试交叉编译通过，日志以 `/tmp/cpa-final-oct03-windows-*`、`/tmp/cpa-final-oct03-linux-build.log` 命名。不是原生运行或 ACL/崩溃恢复证据。
- 前端 117 项：`/tmp/cpa-final-oct03-frontend-117.log`；最终 typecheck/lint/format/build 日志以 `/tmp/cpa-final-oct03-frontend-*-117.log` 命名。
- 一致备份恢复：`/tmp/cpa-final-oct03-local-recovery.log`。停止虚拟实例后复制整个来源/策略集合，保留原目录并原路径恢复；文件字节/权限及最终构建重启后的 namespace、revision、分组、身份、状态和绑定完全一致。

历史 Service 测试曾假定并行 worker 顺序，失败清理未 join，影响后续用例；已仅修同步与清理，五轮隔离和最后完整回归通过，没有以加大超时或删除断言掩盖问题。

2026-10-03 新增 10/1,000/10,000 身份的 `BeginAttempt → Allows → AuthorizeUse` 微基准。初测发现整图复制/校验，1 万记录约 2ms、6.39MB；改为一次发布的内部只读策略/token 索引后，三个规模约 3.2–3.5µs、3.8KB、59 次分配。公开管理快照仍隔离复制，使用前修订号/关库/失败重验未移除。日志 `/tmp/cpa-grouping-scale-before.log`、`/tmp/cpa-grouping-scale-after.log`，环境 darwin/arm64、M3 Max、三轮、每轮 250ms。旧 2 身份日志 `/tmp/cpa-grouping-benchmark.log` 保留为过程对照，不是当前完整请求成本。

该检查不包含 HTTP、完整调度候选遍历、多令牌认证扫描、真实上游或并发改组压力，不能据此宣传零开销或端到端吞吐倍率。

上述日志均为本机临时证据，详细命令和范围见 `docs/credential-token-groups-p0_CN.md`。生产发布前仍须核对面板更新来源、实际发布系统的原生权限和文件系统故障恢复、真实提供商网络以及完整请求/并发性能。此次上游同步已获准创建本地备份及合并提交；不执行推送、部署、生产配置变更或 Home H0–H4。

### 8.3 本次 v8 上游合并证据

- CPA upstream：`e2bff0107bb307337aaa19018ccddd55f64253d5`（v8.0.11）；原分组实现本地备份提交 `c9441b26`。
- 面板 upstream：`752e0ee772220ce49aae1221a3f39f23236590d7`（v1.25.2）；备份提交 `57b3de4`；本地合并提交 `025f8ef`。两个仓库使用 `codex/upstream-v8-sync`，原 main 保留。
- 合并前完整备份位于仓库父目录的 `merge-backups/20261003-upstream-sync`，包含源码、patch、Git bundle 和 SHA-256/权限清单；未收集真实忽略配置、auth 或 `.env`。
- 修复并覆盖：未被接纳的外部凭证/令牌变更不能由无关保存批准；已 pending 的来源保持 pending；重复 key 夹空记录可继续保存；null/alias 启停保留其他配置；两个版本的管理控制面仍可鉴权访问；流式日志收尾竞态不再丢块。
- 冻结后全库：`/tmp/cpa-v8-frozen-all.log`；Service 全包 race：`/tmp/cpa-v8-service-final-race.log`；API 全子包 race：`/tmp/cpa-v8-api-race-response-writer-fixed.log`；日志竞态定向连续 100 次通过。
- core auth 全包 race：`/tmp/cpa-v8-auth-full-race.log`；插件和各请求处理链另有分包/race 回归。
- vet、原生构建、Windows/Linux 交叉构建：`/tmp/cpa-v8-frozen-vet.log`、`/tmp/cpa-v8-frozen-build.log`、`/tmp/cpa-v8-frozen-windows.log`、`/tmp/cpa-v8-frozen-linux.log`。交叉编译不等于目标系统原生验收。
- 前端完整验证：相邻面板仓库 `node_modules/.cache/verify-v8-final.log`；单文件 `dist/index.html` SHA-256 为 `480f321301be5c0bf806a87fe6d36a7d9ce2982230e623f9773452e048c2b59b`。
- 最终二进制原路径恢复：`/tmp/cpa-v8-local-recovery.log`。虚拟实例停机后完整复制来源/策略/回执，字节和权限相同；保留原目录，恢复后 namespace、revision、组、身份、状态和绑定完全一致。未模拟断电故障。
