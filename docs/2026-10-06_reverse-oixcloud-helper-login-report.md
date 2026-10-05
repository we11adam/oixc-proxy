# 官方 oixCloud Helper 登录身份与 token 导入分析

分析日期：2026-10-06。工具：radare2 / rabin2、ARM64 定向引用扫描。报告类型：普通兼容性逆向（flavor=null）。

## 结论与范围

官方 v0.0.39 将 API 身份设置为 `User-Agent: oixCloud Helper` 和 `X-oixCloud-Client: oixcloud-helper`。token 导入路径检查账户信息中的客户端身份；身份不同则请求 `/api/v1/token/rebind`，从响应的 `data.token` 读取新 token。仅添加请求头不能证明旧 token 已迁移，官方发布说明也要求旧用户重新登录。本项目对齐共同请求身份和显式 token 导入协议；保留现有配置驱动方式，不增加邮箱/密码登录，也不在服务启动时自动改变账户状态。

授权范围：用户要求分析官方实现以完成本仓库兼容性修改。分析只针对公开发行的离线样本（case `work/oixcloud-helper-login-039`，`auth.status=granted`、`network_profile=offline`，scope guard 已通过）。没有执行官方二进制，没有向真实账户发送登录或重绑定请求，没有修改现有服务。所有网络协议测试在本地模拟服务完成。

## 样本与导入表

- 来源：[官方 v0.0.39](https://github.com/pickrui/oixcloud-external-proxy-program/releases/tag/v0.0.39)。官方仓库只公开发行资产与文档，不包含核心实现源码。
- 文件：`oixcloud-external-proxy-program-arm64`，1,985,520 字节，stripped Mach-O ARM64，Swift。
- SHA-256：`114f88cea62e88c8fbbf2dfdeb41b3ae6b2e64198d325764a60e31a8ce2b6e3d`，与该 Release 的 `SHA256SUMS` 条目一致。
- 导入表包含 Foundation URLRequest/URLSession 的 HTTP 方法、正文、请求头设置和 JSON 处理，Network 的连接/监听接口及 CryptoKit。先完成导入表分类再分析函数；未依据这些正常导入作安全风险判断。

## Evidence

以下虚拟地址均相对本样本的 `0x100000000` 基址。命令中的 `SAMPLE` 指下载并核对上述哈希后的文件路径；样本没有提交到仓库。

| E-id | source_ref | repro_command | content_hash |
| --- | --- | --- | --- |
| E-release | 官方 v0.0.39 发布说明 | `rtk proxy gh api repos/pickrui/oixcloud-external-proxy-program/releases/tags/v0.0.39 --jq .body` | n/a（在线发布说明） |
| E-imports | 样本导入表 | `rtk proxy /opt/homebrew/bin/rabin2 -i "$SAMPLE"` | 样本 SHA-256 如上 |
| E-identity | 初始化函数 `0x100052588` | `rtk proxy /opt/homebrew/bin/r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'pd 125 @ 0x100052588;q' "$SAMPLE"` | 样本 SHA-256 如上 |
| E-request | 通用请求构造 `0x1000c6090` | `rtk proxy /opt/homebrew/bin/r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'pd 90 @ 0x1000c6704;q' "$SAMPLE"` | 样本 SHA-256 如上 |
| E-rebind | 导入分支 `0x1000c1550`、重绑定 `0x1000c50f0` | `rtk proxy /opt/homebrew/bin/r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'pd 40 @ 0x1000c1550;pd 75 @ 0x1000c50f0;pd 85 @ 0x1000c541c;q' "$SAMPLE"` | 样本 SHA-256 如上 |
| E-mock | `src/api.rs` 模拟 HTTP 请求测试 | `rtk proxy cargo test --locked --all-features api::tests` | n/a（随源码可复现） |

`E-identity` 中 `0x10005266c`–`0x100052688` 的 MOV/MOVK 组合恢复 Swift small string `oixCloud Helper`；`0x1000526a0`–`0x1000526c0` 恢复 `oixcloud-helper`。`0x1001789c0` 是 `X-oixCloud-Client` 字符串。初始化将这些字符串分别写入客户端的 `0x30`、`0x40`、`0x50` 字段。

`E-request` 中 `0x1000c6730` 从 `0x30` 字段加载值，`0x1000c674c` 设置 User-Agent。`0x1000c6770`–`0x1000c6778` 从 `0x50` 加载值、从 `0x40` 加载字段名并调用 `URLRequest.setValue`。这同时核实了字符串值与实际用途，避免把展示名称误认为设备注册字段。

`E-rebind` 中 `0x1000c1590` 比较信息对象中的客户端身份与当前客户端的 `0x50` 字段，不同则在 `0x1000c15e0` 调用重绑定。`0x1000c5164` 引用路径字符串 `0x100182800`；`0x1000c5190`–`0x1000c51b0` 使用 POST、无正文、传入 bearer token 调用共同请求构造函数。随后检查 `ret == 200`，依次读取 `data` 和 `token`，去除首尾空白并拒绝空值。

## Findings

| F-id | severity | evidence_ids | confidence | location | status |
| --- | --- | --- | --- | --- | --- |
| F-identity：两种请求身份字段共同固定为 Helper | n/a_re | E-identity, E-request | high | `0x10005266c`、`0x1000c6730` | validated（静态常量与使用点互证） |
| F-import：旧客户端 token 通过显式重绑定取得新 token | n/a_re | E-release, E-rebind | high | `0x1000c1550`、`0x1000c50f0` | validated（公开说明与静态调用流互证） |
| F-local：Rust 请求身份及重绑定报文与恢复的协议一致 | n/a_re | E-request, E-rebind, E-mock | high | `src/api.rs` | validated（本地协议测试）；真实账户归属未在线验证 |

## Path 与实现

P-import，`path_type=callflow`：读取原 token → 官方信息对象与 Helper 身份比较（E-rebind/F-import）→ 需要迁移时 POST `/api/v1/token/rebind`（E-rebind/F-import）→ 通用请求附加两个身份字段和 Bearer（E-request/F-identity）→ 检查 `ret`，读取非空 `data.token`（E-rebind/F-import）。

Rust 中 `login [--config PATH] --output PATH` 是用户显式要求签发 Helper token 的入口；每次调用都会重绑定，不额外复制官方 GUI 的已登录状态判断。配置从一次经过权限和大小校验的快照读取，输出目标先以 `0600`、排他创建方式保留，避免请求已经改变服务器后才发现文件存在。成功保存新 token 后，用户将其更新到原配置并热重载。不会更改已有进程，也不把新 token 输出到终端。

重绑定只请求主 API 一次，没有自动重试或备用 API；超时不能确定服务端未签发。响应受大小和总超时限制，错误正文不进入日志，返回 token 不能含内部空白或控制字符。普通账户信息和节点获取继续保留现有只读 API 回退机制，并共用 Helper 请求身份。

## 验证与限制

本地测试覆盖三个 API 路径的身份请求头、Bearer、无正文 POST、返回 token 解析、拒绝空/错误类型/控制字符 token、脱敏错误、503 不重试/不回退、配置保留和已有目标提前拒绝。`cargo +1.85.0 test --locked --all-features`：119 项通过，4 项真实环境测试未运行；严格 all-targets/all-features clippy 通过。

没有真实 API 请求与官方运行时抓取，因此服务端是否立即迁移现有登录、怎样失效旧 token，以及各账户的筛选归属结果仍需真实账户验证。服务端实现与 token 格式没有纳入分析。官方邮箱/密码登录路径存在，但不属于本次本项目 token 导入实现；不得将本次变更描述为完整复刻官方登录 UI。

## Timeline

1. 2026-10-06：核查官方发行说明与仓库，确认核心源码不公开。
2. 下载 v0.0.39 ARM64 资产，校验 SHA-256，建立离线 scope 并通过 guard。
3. 完成字符串、导入表与定向 ARM64 引用分析，确认身份常量、请求构造和重绑定返回结构。
4. 实现 Rust 身份字段与显式 token 导入，使用本地模拟 HTTP 服务验证，补齐双语文档。

复现脚本和详细 scope/timeline 保存在本地 `work/oixcloud-helper-login-039`；仓库报告只保留兼容性依据，不包含真实凭证或发行二进制。
