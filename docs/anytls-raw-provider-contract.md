# AnyTLS raw provider：与 Spike 的扩展约定

本文件定义 oixc-proxy 原始节点导出与 Spike 原生连接的共同格式。
`obfs=wss-tls` 是两项目之间的扩展，不宣称官方 Surge 支持。

可供两端离线验证的 [实际导出 fixture](../testdata/anytls-raw-provider.conf) 使用保留地址和 mock 口令；oixc-proxy 测试会比较其内容与渲染结果的逐字节一致性。

普通 AnyTLS：

```ini
Mock AnyTLS = anytls, 203.0.113.10, 443, password=mock-secret, sni=origin.example.test, reuse=true, udp-relay=true
```

CDN AnyTLS：

```ini
Mock CDN = anytls, 203.0.113.11, 443, password=mock-secret, sni=origin.example.test, obfs=wss-tls, obfs-host=cdn.example.test, obfs-uri=/carrier, reuse=true, udp-relay=true
```

| 字段 | 语义 |
|---|---|
| 类型 `anytls` | 复用 Spike 既有 AnyTLS 协议和会话池；不可按 Snell 解释 |
| server / port | 实际 TCP 拨号地址，可为解析后的 IP；DNS 失败依次使用最后成功 IP、原始主机名 |
| `password` | AnyTLS 原始口令，由 AnyTLS 层执行鉴权 |
| `sni` | 内层 TLS 的 SNI / 证书名；导出时显式给出，源 sni 为空则用源 server，不能用解析后的 IP 替代 |
| `obfs=wss-tls` | TCP → 外层 TLS → HTTP/1.1 WebSocket → 内层 TLS → AnyTLS；省略则是普通 TLS → AnyTLS |
| `obfs-host` | CDN 外层 TLS 的 SNI / 证书名及 HTTP Host；保留源 server，不跟随解析 IP 改写 |
| `obfs-uri` | 完整 WebSocket path（包含 query）；不可猜默认值或按文件路径归一化 |
| `reuse` | AnyTLS 会话复用；导出默认 true，与 AnyTLS 现有默认策略一致 |
| `udp-relay` | AnyTLS UoT v2 能力，来自节点 udp 或 AnyTLS options.udp |

CDN 必须同时提供 obfs-host、obfs-uri；未知 obfs 模式或残缺参数应明确失败，不得静默退成普通 AnyTLS。两层分别验证证书，外层仅使用 `http/1.1` ALPN，内层默认不提供 ALPN。不应把内层的证书名、pin 或客户端证书等参数意外套用到外层。

Spike 的直连、经 underlying-proxy 拨号、作为其他节点 underlying、TCP/UDP 和会话池应共享 carrier 构造。池键包括封装模式、外层域名 / path、内层 TLS 参数及已有 transport scope / 网络身份，保持 reload 和链路切换隔离。

raw=1 允许 Snell 与 AnyTLS 混排，按源节点类型输出；all=1 仅绕过本地名称筛选。保留原顺序、重名后缀、HTTP 访问控制、no-store 和 DNS 缓存语义。不能安全表示为一行配置的字段拒绝导出并计入跳过数，避免泄露额外配置或注入；既有 Snell 输出保持不变。

实现状态以两个仓库的代码和验证报告为准；字段合同本身不表示运行中的 Spike 已支持。
