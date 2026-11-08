# AnyTLS 与 CDN 传输

当前开发版支持 AnyTLS TCP、UoT v2 UDP，以及官方客户端使用的双层 TLS CDN carrier。Snell v4 ECH-TLS 保持独立实现，现有 HTTP/SOCKS5 入口、节点凭据、筛选、缓存及服务配置方式不变。

## 订阅节点

普通 AnyTLS 节点使用标准 `type: anytls`、`password`、`server`、`port` 和可选 `sni`。例如以下是托管目录中的节点结构，不是服务的本地 key=value 配置：

```yaml
proxies:
  - name: AnyTLS Fusion example
    type: anytls
    server: node.example.com
    port: 443
    password: example-password
    sni: origin.example.com
    udp: true
```

CDN 节点还需要 WebSocket path：

```yaml
proxies:
  - name: AnyTLS CDN Fusion example
    type: anytls
    server: cdn.example.com
    port: 443
    password: example-password
    sni: origin.example.com
    anytls:
      webSocketPath: /carrier
      usesCDN: true
      udp: true
```

`anytls-opts` 是 `anytls` 的别名；`websocket-path`、`uses-cdn` 是对应驼峰字段的别名。也接受 `network: ws` 和 `ws-opts.path`，仅支持省略 headers 或 `Host` 与 server 相同的形式；未实现的传输和自定义 headers 会明确拒绝。`usesCDN: true` 必须有 path；不会猜测默认路径。path 存在时使用 CDN carrier，与静态样本中的分支一致。

普通 AnyTLS 不要求 Snell 的 PSK Identity、ECH、ALPN 或版本字段。内部缓存把 password 保存为统一的 psk 字段，沿用目录私有权限和账户绑定。`sni` 未设置时使用 server。两层 TLS 均校验证书；`skip-cert-verify: true`、不支持的 ALPN/ECH 参数或传输不会静默降级。

新协议出现在普通 Surge / Clash provider 中时，仍导出本机的 SOCKS5 / HTTP 路由。`raw=1` 按实际协议导出 Snell / AnyTLS 混合列表；CDN AnyTLS 使用 `obfs=wss-tls`、`obfs-host`、`obfs-uri`，完整约定见 [Spike 扩展格式](anytls-raw-provider-contract.md)。缺少 CDN 参数或无法安全表示的字段仍跳过整行，访问控制及敏感参数保护不变。接收端需实现扩展，字段约定不代表运行中的 Spike 已升级。

## 数据路径

普通节点：业务 → AnyTLS 会话 → TLS → TCP。

CDN 节点：业务 → AnyTLS 会话 → 内层 TLS → WebSocket binary frames → 外层 TLS → TCP。

外层使用 server 作为证书名和 HTTP Host，ALPN 为 `http/1.1`；内层使用 sni，ALPN 为空。外层先验证 HTTP 101、Upgrade / Connection 和 Sec-WebSocket-Accept，然后才建立内层 TLS。HTTP 头最多 64 KiB；保留头后同包抵达的数据。

WebSocket 使用成熟的 tungstenite 编解码器：客户端帧带随机 mask，发送块最多 64 KiB，接收单帧/消息上限 1 MiB。读写分开推进，写队列与读缓冲有界；flush 按序等待 WebSocket sink 完成，Drop 会中止 carrier worker。嵌套 TLS 握手被取消时也释放 worker 和 socket。

DNS 与物理连接使用现有私有 DNS、Happy Eyeballs、出口绑定及网络代次。证书库 UnknownIssuer 恢复只重建尚未发送 AnyTLS 鉴权的 carrier，不重放业务请求。整个拨号、TLS、WebSocket、鉴权及 SYN-ACK 共用请求超时。

## AnyTLS 会话生命周期

- 鉴权使用 password 的 SHA-256、16 位 padding 长度及 padding；首个会话 flight 合并 Settings、SYN 和目标地址 PSH。
- 声明协议 v2 和真实 `oixc-proxy/VERSION` client 名称，处理 ServerSettings、SYN-ACK、Alert、心跳及服务端 padding 更新。服务端错误文本不写日志或返回给调用方。
- 每个活跃 TCP 请求独占一条会话租约；并发请求使用不同会话。请求完成后，可在同一 TLS 会话以递增 stream ID 打开下一条流。空闲池优先复用序号最大的会话，响应空闲心跳，并在超时、超出使用次数或客户端关闭时回收。
- 网络代次变化后不复用旧代次会话；不同节点、账户和 TLS 参数不共用会话池。目录连接参数改变时沿用现有客户端替换逻辑。
- SYN-ACK 被拒、协议错误、读写失败、握手超时或非正常 relay 不进入空闲池。AnyTLS FIN 表示整条逻辑流关闭，与 Snell 双向 zero-record 握手不同。
- v1 服务端没有 ServerSettings 时，初次读等待最多 250 ms 后允许发送应用数据；已识别 v2 则继续等待 SYN-ACK，受整体拨号时限约束。
- UDP 使用 `sp.v2.udp-over-tcp.arpa` 和 non-connect UoT v2；保留每个数据报的目标、长度及边界。TCP/UDP 统计只记业务载荷，不包含鉴权、padding、地址、WebSocket 或 TLS 开销。

## 验证与边界

本地测试使用临时证书和模拟服务，覆盖普通 TLS、外层/内层不同 SNI、双层 TLS + WebSocket、会话复用、padding 更新、UDP 分帧重组、空闲心跳、截断帧、SYN-ACK 拒绝/超时、内层证书错误、WebSocket 背压/flush/取消，以及 SOCKS5 和 HTTP CONNECT 网关路径。已有 Snell 与流量统计测试继续运行。

未连接真实官方 AnyTLS 节点。内部字段来源已经静态确认，但面板是否要求额外能力宣告、是否使用不同的订阅字段转换，仍需实际订阅样本确认；不会臆造能力参数或宣告尚未实现的 Snell v6 / HTTP/3。浏览器风格 HTTP User-Agent 与样本策略对齐，不宣称 rustls 的 ClientHello 指纹完全等同官方实现。

协议依据：[AnyTLS 协议说明](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)、[UoT v2](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/)、[本地 CDN 静态分析](2026-11-08_reverse-oixcloud-cdn-report.md)。
