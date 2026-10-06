# 更新日志

**中文** | [English](CHANGELOG.en.md)

本文件记录 `oixc-proxy` 各版本中值得注意的变更。版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.6.0] - 2026-10-06

### 新功能

- `traffic` 查询和人类可读输出尊重本机时区及 `TZ`；时间参数支持无后缀本地时间、`Z` 和显式 UTC 偏移，夏令时不存在/歧义时间要求显式偏移。磁盘及 JSON 仍保留 Unix 秒，旧统计文件无需迁移。
- 新增本地 TCP/UDP 应用层上传、下载流量统计，`serve`/`serve-map` 默认每分钟将时间戳和增量同步到配置/token 文件旁的 `0600` JSONL 文件；独立线程写盘，正常退出补写，重启保留历史。支持 `--traffic-file`，避免多实例共用文件；写入失败保留内存增量重试，未完成末行可恢复。
- 新增 `traffic [--all] [--from TIME] [--to TIME] [--json]`，只读查询累计历史或按采样时间筛选时段，分列 TCP/UDP 上传、下载；仅包含已落盘样本，不等同账户计费，异常退出可能丢失未落盘部分。中英文文档说明统计精度、故障和存储边界。
- 控制面请求对齐官方 v0.0.39 的 `User-Agent: oixCloud Helper` 和 `X-oixCloud-Client: oixcloud-helper`。
- 新增 `login --output PATH`，显式导入配置中的旧 token，调用官方重绑定接口取得 Helper 专属 token，并保存到新的 `0600` 配置；保留其他设置、不覆盖原配置、不自动重载服务，也不重试或回退到备用 API。启动和只读命令不会自动迁移 token；暂不提供邮箱/密码登录。

### 使用说明与验证

- SIGTERM、SIGINT（Ctrl-C）及正常退出会补写并同步不足一分钟的流量；新增真实进程信号和 TCP/UDP 流量回归测试。SIGKILL、崩溃或断电仍可能丢失未落盘部分。
- macOS 更新流程改为显式 SIGTERM 并等待 KeepAlive 拉起新进程；中英文 README、部署文档和部署 Skill 统一说明优雅重启、systemd 默认信号及生成 unit 的 10 秒停止超时。

## [0.5.0] - 2026-10-05

### 新功能

- 新增 `refresh-nodes`，通过私有控制 socket 手动刷新正在运行的节点目录，无需重启。命令等待实际结果；失败保留原目录和连接池，与定时及 ECH 触发的刷新串行执行。
- 新增 `reload-config`，支持热重载 token、API 地址、节点过滤、超时、并发、复用、刷新间隔和性能日志采样。先校验并准备新状态，失败保留完整当前配置；token 或 API 地址变化时先获取并验证新目录。已有隧道继续运行，调低客户端连接上限时计入已有连接。
- 新增 `diagnose --output PATH`，导出权限为 `0600`、禁止覆盖的脱敏 JSON 诊断包。包含当前生效配置摘要、运行信息、匿名节点状态、最近 128 条刷新/重载事件及每节点最近 16 条 ECH 建连事件；不包含 token、PSK、地址、路径、节点名、过滤条件或原始日志。磁盘配置损坏时仍可导出。
- 新增 `/status`，显示目录刷新结果、缓存年龄、物理出口、根证书状态和 ECH 建连统计；每节点提供健康状态、连续失败次数、DNS/TCP/TLS/总耗时及最近 64 次成功连接的 p50/p95。统计来自真实物理建连，不主动测速，也不重复统计复用会话。
- 新增 `api-fallback-urls`，允许最多三个可信的 HTTPS 备用 API 地址。网络错误、超时和 HTTP 5xx 可回退，全部尝试共用一个请求时间预算；认证、限流、格式及签名错误不回退。
- 新增 `node-filter-lines`、`node-filter-regions`、`node-filter-include`、`node-filter-exclude` 和 `preview-nodes`，支持按名称进行本地字面筛选和只读预览；保留默认 Fusion/CIA 筛选及现有绕过方式。
- Clash provider 成功响应附加有效的 `Subscription-Userinfo`，提供实际流量、额度及可选到期时间。元数据与账户绑定的节点缓存一起保存，缺失、无效或过期时省略；认证失效时清除。

### 修复

- ECH 外层 ClientHello 使用浏览器常见的 `h2` / `http/1.1` ALPN，Snell 协议标识只放在加密的内层。
- ECH 配置被服务端拒绝时触发节点目录刷新，多节点请求合并并限制为每 30 秒最多触发一次；刷新失败保留已有目录。
- DNS/TCP 连接错误保留底层错误类型，使诊断可以正确分类常见网络故障。

### 使用说明

- 新管理命令仅支持 `serve`，通过配置目录内权限为 `0600` 的 Unix socket 通信，需以服务用户运行（root 服务使用 `sudo`）。
- `listen`、`nodelist-listen`、`outbound-ip`、`udp-port-range` 和 `udp-advertise-address` 的变化需要重启，热重载会拒绝整次修改。
- 未变节点在刷新和仅调整过滤时保留连接池及统计；token 或拨号/复用参数变化会重建客户端并关闭旧空闲连接。账户绑定的旧版缓存仍可读取，账户元数据在首次成功刷新后补齐。
- 更新中英文命令示例、故障排查、脱敏范围和安装版本说明。

## [0.4.0] - 2026-10-01

### 新功能

- 新增 `tcp-idle-timeout` 配置，关闭长时间没有数据往来的 TCP 隧道。默认 1 小时，取值范围 1 分钟到 24 小时，适用于 SOCKS5、HTTP CONNECT 和普通 HTTP 转发。
- serve-map 每小时原地刷新节点路由，节点轮换地址、PSK 或 ECH 配置后无需重启；端口与节点名的对应关系保持不变，新增或移除的节点只记录日志。

### 行为变更

- 普通 HTTP 代理连接每条只转发一个请求，最终响应头始终带 `Connection: close`。这样可以避免 keep-alive 连接上的后续请求连同 `Proxy-Authorization` 被发往错误的上游。帧边界不明确的请求会在拨号前被拒绝；支持 `Expect: 100-continue`，1xx 中间响应原样透传；Upgrade 请求仍按不透明隧道转发。
- 监听器不再因单个连接的 accept 错误停止；资源耗尽（EMFILE、ENFILE、ENOBUFS、ENOMEM）时退避后重试；遇到其他无法恢复的错误时进程带错误退出，交由服务管理器重启。
- 选择 IPv6 源地址时会跳过 tentative 和 DAD 失败的地址，并按“全局优先于 ULA、preferred 优先于 deprecated、稳定地址优先于临时地址”排序。显式配置的非回环 `outbound-ip` 仍按原样使用。

### 修复

- Snell：每次写入记录后都会 flush，修复数据滞留在 TLS 缓冲区导致转发停顿的问题。
- Snell：复用空闲连接前先探测其是否仍然可用；连接回收限时 2 秒，关闭时不再逐个串行等待。
- ECH：服务端下发 retry configs 时使用新配置重试握手。
- SOCKS5：客户端半关闭后继续等待上游响应，不再被 2 秒关闭超时截断；上游先结束的连接视为正常结束，Snell 连接可以回到连接池复用。
- SOCKS5：UDP 关联遇到单个错误数据报时只丢弃该数据报，不再整体中断；空闲计时同时统计双向流量；无法建立关联时返回 SOCKS5 失败应答。
- HTTP：转发与 CONNECT 请求一起发出的首批数据；继续扫描后续请求头以查找代理凭据；绝对形式请求中的 IPv6 字面量地址可以正常拨号。
- DNS：忽略来源或问题段不匹配的响应，SERVFAIL 和截断响应会重试；只有 A/AAAA 都成功时才长期缓存，部分成功的结果只短暂缓存。
- TLS：系统信任库不完整时在后台重新加载，不阻塞拨号。
- 节点目录：忽略未知的顶层字段，单个无法使用的节点被跳过并记录日志，不再导致整个目录被拒绝。
- API：错误响应正文按字符边界截断，修复遇到中文等多字节文本时的崩溃。

### 性能

- Snell 下载方向直接从解密后的记录写出，省去一次拷贝。
- ECH 连接尝试失败时立即开始下一个地址的尝试（RFC 8305），不再等待 250ms 的错开间隔。
- macOS 上复用默认路由查询结果，最多每 30 秒重新检查一次，拨号不再排队等待 `route` 进程。
- 关闭 tracing 时不再构造 trace 字段。

### 文档

- 节点过滤说明中移除已不再适用的 IXP。

## [0.3.0] - 2026-10-01

### 性能

- Snell 记录层的 AES-128-GCM 改用 `ring` 实现。1 KiB 记录的加解密吞吐约为原来的 1.95–1.99 倍，最大记录约为 2.8–2.94 倍；64 字节的小帧略慢，端到端吞吐没有稳定可测的提升。

## [0.2.2] - 2026-09-29

### 修复

- TLS：系统信任库不完整导致 `UnknownIssuer` 时刷新信任库并重试一次，刷新之间有 30 秒冷却。

### 诊断

- 增加物理出口选择相关的 tracing。

## [0.2.1] - 2026-09-15

### 修复

- 在受限的 Linux 环境中无法枚举网卡（`getifaddrs` 被拒绝）时，仍保留固定的 `outbound-ip`；systemd 单元允许 `AF_NETLINK`。

## [0.2.0] - 2026-09-15

### 新功能

- 新增 `udp-port-range` 和 `udp-advertise-address`，用于固定 UDP 中继端口范围和对外通告的地址。
- 绑定并跟踪物理出口：macOS 上绑定网卡以绕过隧道接口；非回环的 `outbound-ip` 作为严格的源地址；网络变化时让 DNS 缓存、地址偏好和空闲连接失效。
- API 请求的 User-Agent 取自 Cargo 包版本。

### 修复

- 节点目录缓存与账号绑定（HMAC 指纹和带版本的封装），拒绝旧格式、超大或属于其他账号的缓存。

### 文档

- 提供中英文 README 和部署 skill 文档，补充 UDP 默认值说明。

## [0.1.0] - 2026-09-01

首个 Rust 版本。

### 新功能

- 混合 HTTP/SOCKS5 入站监听器；`socks5-listen` 更名为 `listen`，旧名称保留为别名。
- 节点过滤只发布名称包含 `Fusion` 或独立 `CIA` 标记的节点，可用 `--disable-node-filter` 或 `?all=1` 关闭。
- 节点列表默认通告 HTTP 代理，加 `socks=1` 改为 SOCKS5；提供 `/clash-proxies.yaml` Clash provider；Surge provider 不再包含 test-timeout。
- 启动时可直接使用节点缓存。
- `version` 子命令输出版本、提交和构建时间。
- 启动时提高 `RLIMIT_NOFILE`。
- 面向 macOS 和 Linux musl（x86_64/aarch64）的发布流水线和 `install.sh`，以及部署指南 `DEPLOY.md`。

### 性能

- Snell 热路径：原地 AES-GCM、缓冲读取和批量写入、ARMv8 加密指令，去掉异步互斥锁。
- DNS 与 TCP 竞速：共享传输上下文、合并签名 DNS 查询、A/AAAA 并发查询、错开的连接尝试。
- 拨号时间预算、采样的性能 tracing 和连接复用调优。

[0.6.0]: https://github.com/we11adam/oixc-proxy/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/we11adam/oixc-proxy/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/we11adam/oixc-proxy/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/we11adam/oixc-proxy/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/we11adam/oixc-proxy/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/we11adam/oixc-proxy/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/we11adam/oixc-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/we11adam/oixc-proxy/releases/tag/v0.1.0
