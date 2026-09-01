# oixc-proxy

**中文** | [English](README.en.md)

`oixc-proxy` 是一个面向 oixCloud 的纯净室 Rust 客户端和本地命名节点代理。它会获取、认证并解密托管节点目录，然后通过一个混合 HTTP/SOCKS5 监听器和一个独立的 HTTP 节点列表监听器，仅发布名称中包含 `Fusion` 或独立 `CIA`/`IXP` 标记的节点。

本仓库是 Go 版 `oixc` 的 Rust 重写。二进制名称、命令、配置、HTTP 端点、Surge provider 格式、SOCKS5 路由凭据、控制面认证以及 Snell/ECH 线路行为均有意保持兼容。

## 安装发布版

GitHub Releases 提供 x86-64 和 aarch64 的原生 macOS 二进制，以及静态 musl Linux 二进制。使用已登录的 GitHub CLI 下载并检查安装脚本，然后运行：

```sh
gh release download --repo we11adam/oixc-proxy --pattern install.sh --clobber
sh install.sh
```

如果仓库公开，也可以从 `https://github.com/we11adam/oixc-proxy/releases/latest/download/install.sh` 下载安装脚本。私有仓库资产需要使用 `gh`，并通过其现有登录状态或只读的 `GH_TOKEN`/`GITHUB_TOKEN` 完成认证。

安装脚本会检测主机目标平台，用 Release 中的 `SHA256SUMS` 验证压缩包，检查二进制版本，并以原子方式安装到 `/usr/local/bin/oixc-proxy`。可通过以下命令安装指定版本或安装到用户可写目录：

```sh
sh install.sh --version v0.1.0
sh install.sh --install-dir "$HOME/.local/bin"
```

安装脚本只安装二进制，不会创建配置、安装服务或重启现有进程。接下来可按照下方平台服务说明操作，也可查阅完整的[部署指南](DEPLOY.md)。

## 构建

需要 Rust 1.85 或更高版本。

```sh
cargo test
cargo build --release
```

优化后的二进制位于 `target/release/oixc-proxy`。Release 构建启用 `opt-level=3`、fat LTO、单个 codegen unit、符号剥离和 panic abort。在 aarch64 macOS 和 Linux 上，仓库构建配置会启用 RustCrypto ARMv8 AES 与 PMULL 后端；这些后端仍会在运行时检测 CPU 支持情况，并在扩展不可用时安全回退。

## 发布版本

修改 `Cargo.toml` 中的包版本，提交发布变更，然后推送对应的 `vVERSION` tag。例如，包版本 `0.1.0` 必须使用 tag `v0.1.0`。Release workflow 会拒绝版本不匹配的 tag，构建全部四个受支持目标，生成 `SHA256SUMS`，并创建或更新 GitHub Release。

## 配置并运行

创建受保护的服务配置：

```sh
install -d -m 0700 ~/.config/oixc-proxy
cp oixc-proxy.conf.example ~/.config/oixc-proxy/oixc-proxy.conf
chmod 0600 ~/.config/oixc-proxy/oixc-proxy.conf
```

替换示例 token，然后以前台模式启动服务：

```sh
target/release/oixc-proxy serve
```

默认端点如下：

| 端点 | 地址 | 用途 |
| --- | --- | --- |
| 混合代理 | `127.0.0.1:6172` | 在同一端口提供 HTTP 和 SOCKS5；通过 provider 凭据路由到指定命名节点 |
| 节点列表 | `http://127.0.0.1:6173/surge-proxies.conf` | Surge 列表（`?all=1` 发布全部节点，`?socks=1` 声明为 SOCKS5） |
| Clash | `http://127.0.0.1:6173/clash-proxies.yaml` | Clash 列表（`?all=1` 发布全部节点，`?socks=1` 声明为 SOCKS5） |
| 健康检查 | `http://127.0.0.1:6173/healthz` | 就绪探针 |

Surge 代理组示例：

```ini
[Proxy Group]
OIXC = select, policy-path=http://127.0.0.1:6173/surge-proxies.conf, update-interval=3600
```

每个 provider 条目都指向共享的混合监听器。条目默认声明为 HTTP 代理；`?socks=1` 会改为声明 SOCKS5（UDP ASSOCIATE 仅在 SOCKS 路径可用）。用户名是节点准确名称的可逆 URL-safe 编码，密码是稳定的 HMAC 派生路由密钥。HTTP 客户端通过 `Proxy-Authorization: Basic` 发送这些凭据。访问 token、节点地址、PSK 和 ECH 配置绝不会由节点列表 HTTP 端点返回。

默认只发布名称中包含 `Fusion` 或独立 `CIA`/`IXP` token 的节点，匹配不区分大小写。将缩写视为独立 token，可避免错误纳入 `Special` 等普通名称。过滤后目录为空时会拒绝加载，以免控制面命名变化意外暴露普通节点。`GET /surge-proxies.conf?all=1` 和 `/clash-proxies.yaml?all=1` 会发布完整目录；这些额外节点仍通过同一个混合监听器路由。需要客户端使用 SOCKS5 时，再附加 `socks=1`。

## 服务配置

`serve`、`information`、`install-launch-agent` 和 `install-systemd` 默认读取 `~/.config/oixc-proxy/oixc-proxy.conf`。使用 `--config PATH` 可指定其他文件。

配置采用严格的 `key=value` 格式。允许空行和 `#` 注释；未知键、重复键、空值、引号和 section 均会被拒绝。配置必须是 Unix 权限为 `0600` 或更严格的普通文件。

| 配置项 | 必填 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `token` | 是 | — | oixCloud 访问 token |
| `listen` | 否 | `127.0.0.1:6172` | 混合 HTTP/SOCKS5 数字 IP 与端口 |
| `nodelist-listen` | 否 | `127.0.0.1:6173` | HTTP 数字 IP 与端口 |
| `outbound-ip` | 条件必填 | SOCKS5 绑定 IP | 写入 provider 条目并用于 UDP 绑定的指定 IP |
| `node-refresh-interval` | 否 | `1h` | 节点目录刷新周期，范围 `1m` 至 `24h` |
| `request-timeout` | 否 | `15s` | 控制面和节点操作超时，最大 `2m` |
| `udp-idle-timeout` | 否 | `5m` | 单个 SOCKS5 UDP 会话的空闲存活时间 |
| `max-client-connections` | 否 | `256` | 进程级混合代理连接上限，范围 `1` 至 `4096` |
| `dial-concurrency` | 否 | `32` | 进程级新建 ECH-TLS 连接并发上限，范围 `1` 至 `1024` |
| `per-node-dial-concurrency` | 否 | `8` | 单节点新建 ECH-TLS 连接并发上限，范围 `1` 至 `128` |
| `reuse-max-idle` | 否 | `8` | 每个节点最多保留的空闲可复用传输连接数 |
| `reuse-max-uses` | 否 | `32` | 单个物理传输连接允许承载的逻辑会话数 |
| `reuse-idle-timeout` | 否 | `90s` | 可复用传输连接的最大空闲时间 |
| `perf-trace-sample-every` | 否 | `0` | 每 N 个请求输出一次详细追踪；`0` 表示禁用 |

两个监听器都可以使用 `0.0.0.0` 或 `[::]`。当 `listen` 使用通配地址时，必须配置同地址族的明确 `outbound-ip`。受信任局域网主机示例：

```ini
token=REPLACE_WITH_OIXC_ACCESS_TOKEN
listen=0.0.0.0:6172
nodelist-listen=0.0.0.0:6173
outbound-ip=10.0.0.16
node-refresh-interval=1h
```

启动时，如果配置文件旁存在 `nodes-cache.yaml`，程序会先加载它，使 SOCKS5 和节点列表监听器可以在控制面获取完成前开始监听。缓存权限为 `0600`，保存最近一次验证通过的目录。后续刷新失败时继续使用原目录；如果首次启动没有缓存，则仍要求首次获取成功。配置未变化的节点会保留其 Snell 客户端和空闲连接池；发生变化、新增或删除的节点配置会原子轮换。

## 命令

```text
oixc-proxy information [--config PATH] --output PATH

oixc-proxy serve [--config PATH]
oixc-proxy serve-map [--token-file PATH] [--listen IP] [--base-port PORT]
oixc-proxy version
oixc-proxy install-launch-agent [--config PATH]
oixc-proxy install-systemd [--config PATH]
```

`information` 发起只读账户/API 请求，并以 `0600` 权限创建新的 JSON 文件；它拒绝覆盖已有文件。

`serve` 是常规命名节点网关。生成的 provider 中，不同用户名/密码组合会在同一个混合 HTTP/SOCKS5 端口选择不同托管节点。它还会为 `/surge-proxies.conf`、`/clash-proxies.yaml` 和 `/healthz` 提供 `GET`/`HEAD`。附加 `?all=1` 可列出所有节点，附加 `?socks=1` 可将代理声明为 SOCKS5 而非 HTTP。

`serve-map` 自行获取相同的 Fusion/CIA/IXP 目录，然后为每个节点分配一个回环 SOCKS5 端口，默认从 7200 开始。其默认受保护 token 文件为 `token.txt`。该命令不提供 HTTP 节点列表端点。

`version` 会输出包版本、构建二进制时的 Git commit id（短 hash；工作区存在未提交变更时追加 `-dirty`）以及 UTC 构建时间。元数据由 `build.rs` 在编译时捕获；如果不在 Git checkout 中，则 commit id 显示为 `unknown`。

已移除的 `serve-provider`、单节点 `serve --index`、`dump-*`、`probe-*`、`seal-bundle`、`install-bundle` 和 `inspect-binary` 命令不会恢复。它们所依赖的逆向知识保留在 [`docs/protocol.md`](docs/protocol.md) 中。

## 在 macOS 上安装服务

以当前登录用户运行：

```sh
target/release/oixc-proxy install-launch-agent
```

该命令会验证配置，将当前可执行文件安装为 `/usr/local/bin/oixc-proxy`，创建 `~/Library/LaunchAgents/io.oixc.proxy.plist`，然后 bootstrap 并启动服务。如果复制二进制需要管理员权限，安装器只会为该复制操作请求 `sudo`。禁止对整个安装命令使用 `sudo`。

日志位置：

```text
~/Library/Logs/oixc-proxy.stdout.log
~/Library/Logs/oixc-proxy.stderr.log
```

检查服务状态：

```sh
launchctl print "gui/$(id -u)/io.oixc.proxy"
```

当 `perf-trace-sample-every` 非零时，stderr 日志会包含已脱敏、按请求划分的性能事件，覆盖 SOCKS 解析、DNS/TCP/TLS 建连、首个 Snell flight、双向首包和 relay 清理。追踪默认关闭，避免同步日志输出拖慢数据面。它绝不会记录 token、PSK、目标名称、ECH 配置或派生密钥材料。

## 在 Linux 上安装服务

以当前登录用户运行：

```sh
target/release/oixc-proxy install-systemd
```

该命令同样会安装 `/usr/local/bin/oixc-proxy`，创建 `~/.config/systemd/user/oixc-proxy.service`，重新加载用户级 service manager 并启用服务。它拒绝覆盖已有 unit。

```sh
systemctl --user status oixc-proxy.service
journalctl --user -u oixc-proxy.service
```

在无头主机上，管理员可运行 `loginctl enable-linger USER`，使用户服务在注销后继续运行。

## 架构与安全属性

控制面流程：

1. 为每个托管请求生成新的 age/X25519 identity。
2. 发送 bearer token、Unix 时间戳、age recipient 和请求 HMAC。
3. 对准确的加密响应字符串验证 HMAC。
4. 严格解码 Base64、ASCII armor 和 age，并实施 8 MiB 限制。
5. 严格解析单个 YAML 文档并验证 Snell ECH profile。
6. 对 Fusion/CIA/IXP 名称 allowlist 采取 fail-closed 策略。

数据面流程：

```text
Surge / Clash provider
  -> 共享混合 HTTP/SOCKS5 监听器
  -> 用户名选择托管节点
  -> cloud-nodes.com 的签名私有 DNS
  -> 验证证书且强制 ECH 的 TLS 1.3
  -> 与 TLS exporter 绑定的 Snell Identity v2
  -> Snell v4 TCP 或 UDP record
  -> 请求的目标地址
```

连接按需建立：加载目录时不会探测全部节点。新建 TCP 会话时，Identity v2 和加密 CONNECT record 会编码到一次 TLS write 中。SOCKS 成功响应不会等待 Snell CONNECT 状态，因此客户端可以立即发送首个 payload；该状态会在首次上游读取时消费。只有双方都交换 Snell zero record 后，可复用传输连接才会归还连接池。

所有节点 dialer 共用一个系统根证书库、密码学 provider 和签名 DNS 缓存。冷启动的签名 DNS A/AAAA 查询会并发执行，并按 host 合并相同请求；TCP 地址尝试使用错峰 Happy Eyeballs 竞争，并记住节点上次成功的地址。

密码学和协议层均在本仓库实现。Rust crate 提供基础原语（`argon2`、`aes-gcm`、`hmac`、`sha2`）、age 和 ECH-TLS（`rustls`）；项目没有使用第三方 Snell 实现。

## 开发检查

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

单元测试包含 Go/Rust 兼容性的固定测试向量，覆盖请求 HMAC、Identity v2、Argon2id record key、CONNECT 编码和私有 DNS 签名。在线验证还应覆盖 `/healthz`、非空 Fusion/CIA/IXP provider、共享端口 SOCKS 路由、`serve-map` 和真实 HTTPS 请求。

## Go/Rust Snell 客户端基准测试

仓库包含一个仅监听回环地址的 Rust 基准服务器，以及对应的 Go/Rust 客户端。服务器会验证真实 Identity v2 握手、解码 Snell v4 record、实现 zero-record 复用握手并回显应用 payload。两个客户端都使用各自的生产 Snell 客户端和连接池实现。

运行标准对比矩阵：

```sh
scripts/benchmark-go-vs-rust.sh
```

该脚本会构建优化客户端，在 `127.0.0.1:19090` 启动服务器，并比较新建连接、顺序复用、并行复用、按 32 KiB 应用写入拆分的生产式 1 MiB stream，以及单次写入 1 MiB 的 API 压力场景。工作线程的响应缓冲区会复用，避免将 allocator 噪声计入每次操作。若 Go 仓库不在 `/Users/adam/Projects/oixc-go`，可设置 `GO_OIXC_ROOT`；还可通过 `BENCH_LISTEN` 选择其他回环端口，或通过 `RESULTS_FILE` 保留原始 NDJSON 结果。

该基准有意用回环 TCP 和一个静态 exporter 值替代 ECH-TLS，用于隔离 Identity v2、Argon2id、Snell v4 framing/encryption、应用 I/O 和连接池性能。它不测量 DNS、TCP 网络 RTT、TLS/ECH 握手、SOCKS5 解析或远端节点性能。

另行运行仅 Rust 的端到端回环网关矩阵：

```sh
scripts/benchmark-rust-gateway.sh
```

该矩阵在保留认证 Snell 基准服务器的同时，为每个逻辑操作加入新的本地 TCP 连接、SOCKS5 协商、固定路由网关、relay task 和可选性能追踪。设置 `TRACE_SAMPLE_EVERY=1` 可量化完整追踪开销；不设置则测量默认的无追踪数据路径。
