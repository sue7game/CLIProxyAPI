# Antigravity Guard

`antigravity-guard` 是一个 Go C ABI 插件，只管理当前 CLIProxyAPI 进程中的 Antigravity 凭证。它提供 429 自动保护、周限手动检测和运行时代理管理，不会重写凭证 JSON。

## 功能边界

- 只观察和操作 `provider=antigravity` 的凭证。
- 所有覆盖、统计和代理别名只保存在内存中。CLIProxyAPI 重启后，429 计数、冷却、周限隔离、周限标记、临时代理和别名全部重新开始。
- 不持久化优先级、禁用状态、代理或额度状态。
- 暂不支持 Home 模式的凭证调度；插件只管理本地 Auth Manager 路由的凭证。
- 插件依赖本源码中的 `host.auth.set_runtime_override` 和 `host.auth.request`。CLIProxyAPI 主程序与插件必须使用同一版本源码构建。

## 429 自动保护

- 忽略 `Generate=false` 的 Usage 记录，因此 `count_tokens` 不会触发或重置连续 429 计数。
- 只有连续出现达到阈值的 429 才会执行动作，默认连续 3 次。可以通过配置或管理页面的 `consecutive_429_threshold` 修改；正常的非 429 生成请求会清零计数。
- `QUOTA_EXHAUSTED`、明确的额度耗尽文案和 weighted-token 耗尽，在计算 Retry 时间时按额度 429 处理。
- `RATE_LIMIT_EXCEEDED` 的 Retry 时间不少于 5 分钟时按额度耗尽处理，短时间限制仍视为普通限流；两类 429 使用同一个连续阈值。
- 支持读取 `Retry-After`、RateLimit reset headers、`retryDelay`、`quotaResetDelay`、`quotaResetTimeStamp` 等字段。
- 连续 429 达到阈值后，插件会先通过该凭证的有效代理查询 Gemini 周限和 5 小时限额，再决定动作。周限已空时，无论配置的是禁用还是降优先级，都会原子写入 `temporary_priority` 并禁用凭证。该周限隔离不会自行恢复，刷新时间只用于倒计时和排序；凭证会保持隔离，直到手动解除、关闭守卫或插件，或者重启进程。如果周限可用但 5 小时限额已空，则按上游返回的 5 小时刷新时间执行当前禁用或降优先级策略，到时自动恢复。两项额度都可用时执行当前策略的普通冷却规则；额度查询失败时回退执行当前策略，并在页面保留查询错误。
- 冷却动作可以选择临时禁用凭证，或把运行时优先级改为指定值。执行前会保存受影响的 `disabled` 或 `priority` 原运行时值。
- Retry 时间到达后恢复已保存的运行时值；如果该字段原本没有运行时覆盖，则清除该字段，让最新配置值重新生效。
- 宿主为 `disabled`、`priority`、`proxy_url` 分别维护进程内 revision。普通冷却按单字段 CAS 写入；周限隔离会同时校验并原子写入 `disabled` 与 `priority`。解除时先恢复优先级，再恢复禁用状态，并分别校验 revision。同值人工重写也会推进 revision，并被识别为 `manual_takeover`；修改代理不会干扰优先级或禁用状态的恢复。
- 关闭自动守卫时会立即尝试恢复全部自动冷却和周限隔离。恢复失败的凭证仍保留恢复任务，并按 `restore_retry` 间隔重试，所有状态都不会写入磁盘。
- 管理页面可以在当前进程中开关自动守卫、选择“临时禁用”或“降低优先级”，并填写 `temporary_priority` 和连续 429 阈值。两种策略下的周限隔离都会使用 `temporary_priority`；已经进入冷却或隔离的凭证保持触发时的处理值。
- 凭证重载、Token 刷新等流程触发相同规范化配置的 `plugin.reconfigure` 时，会保留管理页面当前设置。只有插件配置实际变化时才会改用新配置；重启进程后也会重新从配置开始。

除周限隔离外，只有 `action: disable` 能保证额度耗尽的凭证不再收到新的本地路由请求。使用 `action: priority` 时，`temporary_priority` 必须低于所有需要降级的凭证；插件会原样设置该值，不会根据原优先级自动计算。优先级模式只有在其他兼容凭证的有效优先级更高时才会转移请求；没有更优凭证时，冷却凭证仍可能被选择。

## 周限标记

在插件管理页点击某个凭证的“获取额度”时会请求 Antigravity 额度接口。凭证连续 429 达到配置阈值时，自动守卫也会查询一次；凭证已有生效中或写入中的冷却时不会重复查询。两条路径使用的接口地址和请求结构都与 CLIProxyAPI Management Center 当前实现一致。

- 所有匹配的周限 bucket 都为空时，才标记“周限已空”。
- 任意一个匹配的周限 bucket 仍有额度，就显示“周限可用”。
- 无论周限是否耗尽，只要上游返回 `resetTime`，页面都会显示精确到分钟的自动倒计时。再次获取额度会替换缓存的刷新时间并校正倒计时。
- 周限已空的凭证排在周限可用或未知的凭证之后，并按已知刷新时间从近到远排列；刷新时间未知的已空凭证排在最后。
- `weekly_group` 默认是 `gemini-models`，因此只有 Gemini 周限会影响页面标记和自动强制禁用判断。只有明确需要合并检查全部周限分组时，才设置为空字符串。
- 使用响应 `Date` 修正服务器与本机时钟偏差。
- 已进入周限隔离的空额度结果在 `resetTime` 后仍会保留，并显示“刷新时间已到”，直到再次获取额度或手动解除隔离。其他额度缓存到点后只在本地清除，不会自动再次请求额度。

## 代理管理

- 代理修改通过宿主运行时覆盖立即生效，不会写回凭证 JSON；CLIProxyAPI 重启后恢复凭证原配置。
- 按有效代理分组，只显示配置凭证总数，以及当前正在使用或处于 5 小时冷却中的凭证数。
- 使用随机进程密钥和 HMAC-SHA256，为每个当前可复用代理生成不透明的 `proxy_id`。该标识不会暴露代理地址或密码，并且会在进程重启后变化。
- 可以为每个当前可复用的 Antigravity 代理设置易读别名。别名忽略大小写后必须唯一，最多 40 个 Unicode 字符，只在当前进程内保存；提交空别名即可清除。
- 可以按全部、正在使用、可用、冷却等待恢复中、隔离中和禁用中筛选凭证；“可用”表示周限已刷新可用、但当前没有投入使用的凭证。
- 页面每 30 秒低频刷新一次状态；标签页不可见、页面正在执行操作或已有刷新请求时不会重复请求。
- 正在使用的凭证出现连续 429 后会置顶并使用琥珀色背景提示；冷却和周限隔离按预计恢复或刷新时间排序。周限已经恢复可用的禁用凭证单独进入“可用”分组，不再按下一次周限刷新时间排序；仍为空的周限继续按刷新时间排序。
- 凭证存在代理别名时只显示别名，不再重复显示代理地址和配置来源。
- 支持单个或批量设置临时代理、使用 `direct` 强制直连、清除覆盖并恢复原配置。
- 每个凭证可以直接选择另一个 Antigravity 凭证当前使用的代理；浏览器只提交来源凭证，不接触原始代理密码。
- 页面展示的代理会隐藏全部用户信息、查询参数和片段，避免用户名型 Token 或 URL 参数泄露；代理成功应用后会清空输入框。
- 搜索忽略大小写和常见分隔符，并支持按最近使用模型搜索。

## 构建

需要 Go 1.26+、CGO 和可用的 C 编译器。

```bash
cd examples/plugin/antigravity-guard/go
go test ./...
```

Linux：

```bash
go build -buildmode=c-shared -o antigravity-guard.so .
```

macOS：

```bash
go build -buildmode=c-shared -o antigravity-guard.dylib .
```

文件名必须是 `antigravity-guard.so`、`antigravity-guard.dylib` 或 `antigravity-guard.dll`，这样宿主识别出的插件 ID 才是 `antigravity-guard`。构建生成的 C 头文件运行时不需要。

## 安装与配置

把动态库复制到 `plugins.dir`，然后配置：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    antigravity-guard:
      enabled: true
      priority: 10
      auto_429_enabled: true
      action: disable
      temporary_priority: 13
      consecutive_429_threshold: 3
      generic_require_retry: true
      fallback_cooldown: 5h
      recent_window: 10m
      restore_retry: 15s
      weekly_group: "gemini-models"
      weekly_empty_threshold: 0
      quota_user_agent: "antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)"
```

兼容迁移：未配置 `consecutive_429_threshold` 时，旧的 `quota_429_threshold` 和 `generic_429_threshold` 仍会被读取，并取两者较大值作为统一阈值；新字段存在时优先使用新字段。

`plugins.configs.antigravity-guard.enabled` 控制宿主是否启用并暴露插件。关闭已经加载的实例时，宿主会原地停用插件，立即尝试恢复自动冷却，并安全清理插件管理的代理覆盖；重新开启时继续复用同一实例。`auto_429_enabled` 只控制 429 自动动作，关闭后仍可使用额度和代理管理。宿主层的 `priority` 是插件执行顺序，不是凭证优先级。

如需自定义额度接口顺序：

```yaml
      quota_urls:
        - "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
        - "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:retrieveUserQuotaSummary"
        - "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
```

首次安装或替换动态库后，需要重启 CLIProxyAPI。

## 管理页面

访问：

```text
/v0/resource/plugins/antigravity-guard/dashboard
```

页面会要求输入 Management Key，并且只保存在当前标签页的 `sessionStorage`。所有修改操作都通过已认证的 Management API：

- `GET /v0/management/plugins/antigravity-guard/state`
- `POST /v0/management/plugins/antigravity-guard/settings`
- `POST /v0/management/plugins/antigravity-guard/quota`
- `POST /v0/management/plugins/antigravity-guard/proxy`
- `POST /v0/management/plugins/antigravity-guard/proxy/alias`
- `POST /v0/management/plugins/antigravity-guard/cooldown/clear`

设置或清除代理别名：

```json
{
  "proxy_id": "p_...",
  "alias": "美国住宅 01"
}
```

`proxy_id` 必须对应当前 Antigravity 凭证正在使用的代理。提交空 `alias` 会清除现有别名。

输入 Management Key 或带账号密码的代理地址时，应使用 HTTPS 或可信的本地连接。

## 安全与状态说明

- 插件只读取宿主提供的运行时凭证摘要，不读取完整凭证 JSON 或 OAuth Token。
- `$TOKEN$` 只由宿主在请求头中替换，Token 不会返回插件。
- 每次管理操作都会重新确认目标 `auth_index` 属于 Antigravity，确认后才调用有副作用的宿主接口。
- 浏览器 ResourceRoute 只返回静态资源；所有修改操作都放在需要 Management Key 的 ManagementRoute。
- 关闭 `auto_429_enabled` 会立即恢复插件创建的自动冷却和周限隔离，但不会清除手动设置的临时代理；恢复失败会保留状态并按 `restore_retry` 重试。
- 在宿主层关闭插件时，宿主会先移除插件路由，再通过 `plugin.reconfigure` 发送 `enabled: false`。动态库保持加载，重新启用不需要重启进程；插件管理的代理若因瞬时错误清理失败，会按 `restore_retry` 重试。
- 冷却或隔离解除只会撤销守卫自己写入的字段 revision。后续运行时值即使被同值重写，也视为人工接管，守卫不会覆盖。
- 代理别名和使用进程密钥生成的 `proxy_id` 都不会持久化，重启后会重新生成。
- 插件正常卸载时会先停止恢复循环，再尝试清除自动冷却、周限隔离和代理覆盖；代理清理同样使用 CAS，不会清除卸载前已被其他操作接管的代理。宿主热替换插件时会关闭旧实例，进程重启后所有运行时状态自然清空。

## 验证

```bash
cd examples/plugin/antigravity-guard/go
gofmt -w *.go
go test ./...
go build -buildmode=c-shared -o /tmp/antigravity-guard.so .
```
