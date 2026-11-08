# 官方客户端 AnyTLS CDN 封装静态分析

分析日期：2026-11-08。工具：radare2 6.2.2、IDA Pro 9.5 / Hex-Rays、Hex-Rays 官方 IDA MCP（Git 提交 `391c2f0606a773050fbafcd3ff62942688a0713b`）。报告类型：普通兼容性逆向，`flavor = null`。

## 结论

样本的 AnyTLS CDN 路径使用 **外层 TLS → HTTP/1.1 WebSocket Upgrade → WebSocket 字节流 → 内层 TLS → AnyTLS**。不是把 AnyTLS 明文帧直接装进 WSS：WebSocket 建立成功后，会再创建一个 TLSClient，使用 WebSocketProxyConnection / TunneledTransport 完成第二次 TLS 握手。

这意味着 oixc-proxy 跟进时，需要实现 AnyTLS 本身，以及能作为 TLS 底层流的 WebSocket 适配器。仅添加 WebSocket HTTP 请求或在现有 Snell 连接外套 WSS 都不足以兼容这条路径。本次只分析本地样本，没有修改协议实现或部署服务。

## 范围与样本身份

- 输入：`~/Downloads/oixcloud-external-proxy-program-arm64`。
- SHA-256：`0587064cacc6ed8a74568175768093387519a034f4d34a4ce3037b797a68ffa3`。
- 格式：Mach-O arm64，4,365,568 字节，首选映像基址 `0x100000000`；以下均为未加 ASLR slide 的虚拟地址。
- 本地签名元数据显示 Developer ID Application `PENDLETON STREET HEALTH TECH LLC (WJHBZFHR7D)`，签名时间 2026-11-08 10:29:19（本地时区）；未据此宣称签名校验或公证通过。
- 未运行样本，也未执行 `--version`。文件发布日期背景指向新版，但本报告以哈希标识样本，不把版本号当作已验证事实。
- [授权范围](../work/oixcloud-cdn-060/scope.md)：本地样本静态分析，`auth.status=granted`、`network_profile=offline`。IDA MCP 仅监听本机回环，分析副本位于 case 目录。工具包获取不涉及样本联网。
- [原始导入表分类](../work/oixcloud-cdn-060/evidence/E-triage.md)：Foundation URLRequest / HTTP 头接口、Network 连接、CryptoKit、安全及文件接口。先完成导入分类，再进入函数分析。
- 原始反编译结果保存在被 Git 忽略的 `work/oixcloud-cdn-060/evidence/`；本报告中的地址及命令可独立复核。

## 分层与调用链

P-001，`path_type=callflow`，目标是确认 AnyTLS CDN 的传输层次：

1. `0x100044DF4`：节点含 AnyTLS options 时创建 AnyTLSDialer，注册 carrier factory `0x100045D44`。E-01。
2. `0x100045D44`：创建 AnyTLSCarrierDial，调用 `0x100044FE8`。E-01。
3. `0x100044FE8`：存在 WebSocket path 字符串的分支创建外层 TLSClient；使用节点 server、节点端口，拨号地址可使用预先解析的 resolvedIP。E-02。
4. TLS 成功回调经 `0x100048054 → 0x1000459E4 → 0x100045A24` 创建 WebSocketConnection，底层 send/receive/cancel 接至这个 TLSClient。E-03。
5. `0x100249784` 发出 HTTP Upgrade，`0x10024A6F0` 验证响应。E-04。
6. 成功回调 `0x100047A74` 创建新的 TLSClient 和 WebSocketProxyConnection，调用 `0x1001F82C8`。E-05。
7. `0x1001F82C8` 创建 TunneledTransport，把 WebSocketProxyConnection 存为 tunnel，调用 `0x1001F8BE0`；后者生成、保存并发送内层 ClientHello。E-05。
8. 内层完成回调 `0x1001FED78 → 0x100045C08 → 0x100045C0C` 包装 TLSProxyConnection，交回 carrier completion；AnyTLS 拨号/会话层消费该连接。E-05。

无 WebSocket path 的 carrier 分支直接建立节点 TLS，回调也汇入 `0x100045C0C`，不经过 WebSocket 或第二层 TLS。这里的分支条件来自 path 的 Optional String 表示；不能把 `usesCDN` 字段的名字当成这处条件的替代证据。

## 配置与 TLS 参数

Swift 类型描述符和字段记录保留了以下布局：

| 类型 / 描述符 | 字段 | 证据 |
|---|---|---|
| AnyTLSOptions `0x10028598C` | `webSocketPath`、`usesCDN`、`udp` | 字段描述符 `0x1002936FC` |
| WebSocketConfiguration `0x1002889EC` | `host`、`path` | 字段描述符 `0x100297B1C` |
| WebSocketTransport `0x100288A08` | `send`、`receive`、`cancel` | 字段描述符 `0x100297AE8` |
| TLSConfiguration `0x100287EF0` | `serverName`、`alpn`、`maxVersion`、`echEnabled`、`echConfig`、`fingerprint`、`skipCertVerify`、`systemRootsOnly` | 字段描述符 `0x100296D80` |

AnyTLSOptions 的 Codable 键匹配函数 `0x1000C5ABC` 也匹配上述三个驼峰名称，`0x1000C5BD8` 对 path 使用 decodeIfPresent，对另外两个字段使用 decode。**这证明内部 Codable 格式，不等于托管订阅公开格式一定原样使用这些键。**订阅到内部节点的转换尚未完整还原。

由 `0x100044FE8` 与 `0x1000479B0` 的结构写入可还原：

| 层 | serverName / SNI | ALPN | 证书与 ECH 配置 |
|---|---|---|---|
| 外层 TLS | 节点 `server` | 单项 `http/1.1`，静态数组在 `0x1002D1140` | `skipCertVerify=false`；这处构造不启用 ECH、不带 ECH config |
| 内层 TLS | 节点 `sni` 非空时使用，否则节点 `server` | 空列表 | 继承节点 `skipCertVerify`；这处构造同样不启用 ECH、不带 ECH config |

两层均把一个服务器名判定函数的结果写入 `systemRootsOnly`，该判定策略未继续还原。`maxVersion`、`fingerprint` 的原始枚举值可见，但未进一步映射语义，不能据此宣称某个确切 TLS 版本或完整浏览器 TLS 指纹。

## HTTP 握手

`0x100249784` 按顺序生成如下请求。示例中的主机、路径和 key 只是占位语义，未提取真实节点凭据：

```http
GET <webSocketPath> HTTP/1.1
Host: <node.server>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 of 16 random bytes>
Sec-WebSocket-Version: 13
User-Agent: <generated browser-style UA>

```

`0x100045A24` 调用随机字节函数生成 16 字节，再 Base64 编码作为 key。此构造函数未见额外自定义 Header、Origin 或 Sec-WebSocket-Protocol。

`0x100168C00` 生成 Windows Chrome 风格 UA：`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<major>.0.0.0 Safari/537.36`。major 以 144 为基准，按 2026-01-13 UTC 起的天数计算增长；它不是固定版本字符串。UA 长相本身不能证明 TLS 指纹一致。

响应处理已确认：

- `0x10024B0E8` 增量寻找头结束分隔符，头限制 64 KiB，并保留头之后已收到的数据。
- `0x10024A6F0` 检查 HTTP 状态 101；失败时返回 Upgrade 错误。
- `0x10024F724` 计算 `Base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`，供 `Sec-WebSocket-Accept` 校验。
- 空响应、Upgrade 期间关闭、超大头以及 Accept 缺失/不符均有显式失败路径。

这些证据确认当前 carrier 使用 HTTP/1.1 Upgrade；样本别处存在 HTTP/2 / QUIC 相关实现，不足以证明这条 CDN 分支也会使用扩展 CONNECT 或 HTTP/3。

## WebSocket 数据封装

`0x10024EF28` 是帧编码函数：首字节 `0x80 | opcode`，客户端 MASK 位始终置位，每帧另生成 4 字节随机 mask，payload 按 `mask[i & 3]` 异或。长度编码支持 7 位、16 位和 64 位网络字节序。

`0x10024DB3C`、`0x10024E22C` 的发送路径调用该函数时使用 opcode `2`；超过 65,536 字节的写入拆成若干不超过 64 KiB 的 binary frame。每帧 FIN=1，属于多个完整二进制消息，不应误实现成必须靠 continuation frame 才能拼接的数据协议。

`0x10024C528` 增量解析长度、mask 和 payload，能处理带 mask 的输入；64 位长度分支对大于 1 MiB 的帧记录错误。`0x10024D658` 另有限制接收积压的逻辑。接收端识别 Close/Ping/Pong，Close 会解析状态码；`0x10024BBD0` 中存在回应控制帧的路径。此处不宣称已验证全部 RFC 边界条件。

供内层 TLS 使用的是连续字节流：WebSocket 帧/消息边界应由适配器处理，不能暴露成一次 TLS read 必须刚好等于一帧的限制。这个要求来自 TunneledTransport 与 TLS 握手的组合关系。

## oixc-proxy 的跟进顺序

1. 增加 AnyTLS 节点模型与协议实现，区分 Snell 和 AnyTLS；保留新字段的前向兼容，明确拒绝未实现的连接类型。
2. 先实现直接 TLS 上的 AnyTLS 鉴权、padding、帧、多流会话及关闭流程，用本地模拟服务验证。
3. 增加 WebSocket 到异步字节流的适配器，实现 masking、控制帧、分段读取、积压上限、取消和 EOF 传播。
4. 组合外层 TLS → WebSocket → 内层 TLS → AnyTLS；分别配置两层 SNI、ALPN 和证书验证。现有 `src/transport/ech.rs` 的连接结果固定为 `TlsStream<TcpStream>`，需要为嵌套流设计通用传输接口，不能直接复用这个具体类型。
5. 补本地互通测试：错误 101/Accept、响应头与首帧同包、拆包、跨 WS 帧 TLS record、64 KiB/1 MiB 边界、Ping/Close、握手取消、双层证书失败、连接复用隔离。订阅字段转换与真实服务端互通应作为独立验证阶段。

本次没有读取真实账号/节点配置，尚不能承诺特定 CDN 节点已可用，也没有确定 path 的默认值、`usesCDN` 的完整策略、UDP 策略、完整会话池键或所有复用边界。

## Evidence → Finding

以下 `content_hash` 均为本地工具生成的证据文本 SHA-256；共同 `source_ref` 是本文样本哈希对应的二进制。完整命令上下文见复现小节。

| E-id | 原始证据 / 关键位置 | content_hash |
|---|---|---|
| E-01 | `ida-carrier-factory.txt`、`ida-options-upgrade.txt`；`0x100044DF4 → 0x100045D44` | n/a，多文件，位置可重现 |
| E-02 | `ida-carrier-connect.txt`；`0x100044FE8` | `bd4a311d38717b04e5421c81430f457732440ce8425deceff3be6ddbec64e585` |
| E-03 | `ida-ws-creation.txt`；`0x100045A24` | n/a，地址可重现 |
| E-04 | `ida-ws-handshake.txt`；`0x100249784`、`0x10024A6F0` | `d2aec4c5316b2880221b99d4bf8414054da143b67b39bd457d368f91c3d7d6da` |
| E-05 | `ida-carrier-callbacks.txt`、`ida-ws-handshake.txt`、`ida-inner-tls-completion.txt`；`0x100047A74 → 0x1001F82C8 → 0x1001F8BE0` | callbacks：`471873adc939332c3b69cce11673427bdcc2110a7f9c17571c3c772dd0c2b9b3` |
| E-06 | `ida-ws-frame-encode.txt`；`0x10024EF28` | `7ccb0acac6dd342518ae5f6130c36d3f132abd4e849b5fbf4288d10033e7d632` |
| E-07 | `ida-websocket-framing.txt`；`0x10024C528`、`0x10024DB3C`、`0x10024E22C` | `b739ae3a8d4b02d63f9ca21b9a1826ed47cfcee9e453ad3170aba604171a2ef3` |
| E-08 | `ida-anytls-options.txt`；`0x1000C5ABC`、`0x1000C5BD8`，及 Swift 字段描述符 | `d70f71b7826eafe1b1cf7148d2cbe123077151cf5805fdcad70b8b429e20c643` |

| F-id | 发现 | severity | evidence_ids | confidence / status / location |
|---|---|---|---|---|
| F-01 | CDN carrier 是双层 TLS，中间为 WebSocket | n/a_re | E-02、E-03、E-05 | high / 静态确认，运行时未验证 / `0x100047A74` |
| F-02 | HTTP/1.1 Upgrade 及 101、Accept、64 KiB 头校验 | n/a_re | E-03、E-04 | high / 静态确认，未做 wire test / `0x100249784` |
| F-03 | masked binary frames、64 KiB 发送拆分 | n/a_re | E-06、E-07 | high / 静态确认，未验证完整 RFC 行为 / `0x10024EF28` |
| F-04 | 内部 AnyTLS options 三个字段及 Codable 键 | n/a_re | E-08 | high / 静态确认，订阅映射未确认 / `0x10028598C` |

## 复现与时间线

无需运行目标程序。先验证文件哈希，再使用相同基址查看函数：

```sh
rtk proxy shasum -a 256 "$HOME/Downloads/oixcloud-external-proxy-program-arm64"
rtk proxy /opt/homebrew/bin/rabin2 -I "$HOME/Downloads/oixcloud-external-proxy-program-arm64"
rtk proxy /opt/homebrew/bin/r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'af @ 0x100045A24;pdf @ 0x100045A24;af @ 0x100047A74;pdf @ 0x100047A74;q' \
  "$HOME/Downloads/oixcloud-external-proxy-program-arm64"
```

IDA Pro 9.5 打开副本并完成自动分析后，在已连接的官方 IDA MCP 中先查询 `reference("decompile function")`，再调用 `execute_python`：

```python
for ea in [0x100044FE8, 0x100045A24, 0x100047A74, 0x1001F82C8,
           0x1001F8BE0, 0x100249784, 0x10024A6F0, 0x10024EF28]:
    print(hex(ea))
    print(str(db.pseudocode.decompile(ea)))
```

时间线（Asia/Singapore）：18:05 建立离线 case 并通过 guard；随后完成哈希、导入表及字符串定位；18:10–18:12 接通官方 IDA MCP 并取得 Hex-Rays 输出；后续沿 carrier 成功回调确认内层 TLS，复核 WebSocket 编解码并整理报告。[Case 时间线](../work/oixcloud-cdn-060/timeline.md)。

检查：范围及导入表证据已记录；E/F/P 齐全；原始样本未执行或修改；未使用真实凭据；未修改协议源码、未部署；运行时互通仍待单独验证。
