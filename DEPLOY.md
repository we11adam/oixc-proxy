# oixc-proxy 部署指南

本文档描述如何在三种平台上部署 `oixc-proxy`：macOS（LaunchAgent 用户服务）、
Linux（systemd 用户服务）以及运行 OpenWrt 的嵌入式设备（以斐讯 N1 为例，
procd 守护进程）。

> **约定**：`~` 即用户主目录。示例 token 统一写作
> `YOUR_OIXCLOUD_ACCESS_TOKEN`，请替换为真实值。命令在**控制机**的终端
> 中执行（macOS/Linux 为登录用户本机，OpenWrt 一节通过 SSH 操作设备）。

| 平台 | 运行方式 | 适用场景 | 二进制来源 |
| --- | --- | --- | --- |
| macOS | LaunchAgent 用户服务，登录后开机自启 | 本机代理 | `target/release/oixc-proxy` 本机构建 |
| Linux | systemd 用户服务 | 本机 / 服务器代理 | 本机构建或交叉编译 |
| OpenWrt（斐讯 N1） | procd 守护进程，断电自启 | 局域网共享、7×24 低功耗 | aarch64 musl 静态交叉编译 |

---

## 通用准备

### 前置条件

- [ ] 有效的 oixCloud access token
- [ ] 已编译好的 `oixc-proxy` 二进制（各平台要求见对应章节）

macOS / Linux 需要 Rust 工具链（1.85 或更新），`cargo --version` 可运行；
未安装时用 [rustup](https://rustup.rs/)：

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 构建

在仓库根目录执行：

```sh
cargo test          # 可选，跑一遍单元测试
cargo build --release
```

产物位于 `target/release/oixc-proxy`。

- 发布构建启用 `opt-level=3`、fat LTO、strip 符号、abort-on-panic。
- 在 aarch64 macOS / Linux 上会自动启用 ARMv8 AES / PMULL 后端；这两个
  后端在运行时检测 CPU 支持，不支持时安全回退，无需额外操作。
- OpenWrt 目标需要独立的 aarch64 musl 静态交叉编译产物，见
  [OpenWrt 一节](#openwrt斐讯-n1)的“传输二进制”。

### 配置

创建受保护的配置文件（macOS / Linux 在本机执行）：

```sh
install -d -m 0700 ~/.config/oixc-proxy
cp oixc-proxy.conf.example ~/.config/oixc-proxy/oixc-proxy.conf
chmod 0600 ~/.config/oixc-proxy/oixc-proxy.conf
```

最小配置：

```ini
token=YOUR_OIXCLOUD_ACCESS_TOKEN
```

| 键 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `token` | 是 | — | oixCloud access token |
| `socks5-listen` | 否 | `127.0.0.1:6172` | SOCKS5 监听地址 |
| `nodelist-listen` | 否 | `127.0.0.1:6173` | HTTP nodelist 监听地址 |
| `outbound-ip` | 条件 | 同 socks5 IP | listen 为 `0.0.0.0` 时**必填**，写入 provider 条目并用于 UDP 绑定 |
| `node-refresh-interval` | 否 | `1h` | 节点目录刷新周期，范围 `1m` ~ `24h` |

格式约束：严格 `key=value`；不允许引号、section、未知键、重复键；
空行和 `#` 注释可用；文件必须是普通文件且权限为 `0600` 或更严格。

#### 局域网共享（可选）

默认只监听本机回环地址。若要让局域网内其他设备（手机、其他电脑）通过
代理上网，改成通配监听并指定出站 IP：

```ini
token=YOUR_OIXCLOUD_ACCESS_TOKEN
socks5-listen=0.0.0.0:6172
nodelist-listen=0.0.0.0:6173
outbound-ip=192.168.1.10        # 替换为本机局域网 IP（ifconfig | grep "inet " 查看）
node-refresh-interval=1h
```

- macOS：首次监听 `0.0.0.0` 时，macOS 会弹出“是否允许传入网络连接”的
  防火墙对话框，选择**允许**；之后可在系统设置 → 网络 → 防火墙 → 选项
  中调整。
- Linux：需在系统防火墙放行 6172/6173 端口（`firewalld` / `ufw`）。

### 验证 token（可选但推荐）

先做一次只读的 API 检查，确认 token 有效、账户能拉到节点目录，再部署：

```sh
target/release/oixc-proxy information --output ~/oixc-info.json
```

- 该命令只做账户/API 请求，不修改任何服务状态；
- 成功时创建 `~/oixc-info.json`（权限 `0600`），并打印节点概况；
- 它**拒绝覆盖**已存在的文件，重复运行请先删除旧文件或换输出路径；
- 失败则说明 token 无效或网络不通，先在这一步解决，别急着部署。

### 默认端点

| 端点 | 地址 | 用途 |
| --- | --- | --- |
| SOCKS5 | `127.0.0.1:6172` | 用 provider 凭据路由到指定命名节点 |
| Surge provider | `http://127.0.0.1:6173/surge-proxies.conf` | Surge external-policy list |
| Clash provider | `http://127.0.0.1:6173/clash-proxies.yaml` | Clash proxy-provider |
| 健康检查 | `http://127.0.0.1:6173/healthz` | 就绪探针（204） |

### 客户端接入

#### Surge

```ini
[Proxy Group]
OIXC = select, policy-path=http://127.0.0.1:6173/surge-proxies.conf, update-interval=3600
```

#### Clash / Clash Meta / mihomo / Clash Verge

```yaml
proxy-providers:
  oixc:
    type: http
    url: "http://127.0.0.1:6173/clash-proxies.yaml"
    interval: 3600
    path: ./providers/oixc.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300

proxy-groups:
  - name: OIXC
    type: select
    use:
      - oixc

rules:
  - GEOIP,CN,DIRECT
  - MATCH,OIXC
```

要点：

- provider 中每个节点已包含 `server`、`port`、`username`、`password`、
  `udp`，客户端**无需**额外配置认证信息；
- `username` 是节点名的可逆编码（selector），`password` 是 HMAC 派生的
  路由密钥；均由 oixc-proxy 自动生成，**不要手动修改**；
- 默认只发布名称含 `Fusion`、`CIA` 或 `IXP` 标记的节点；若账户没有这些
  类型的节点，`serve` 需加 `--disable-node-filter`（各平台做法见对应章节）；
- 节点目录每小时自动刷新；客户端按自己的 `interval` 拉取即可感知变更。

---

## macOS（LaunchAgent 开机自启）

### 安装

通用准备完成后，以**登录用户**身份执行（不要加 `sudo`）：

```sh
target/release/oixc-proxy install-launch-agent
```

该命令依次完成：

1. 校验配置文件（`~/.config/oixc-proxy/oixc-proxy.conf`，可用
   `--config PATH` 指定其他文件）；
2. 把当前可执行文件安装到 `/usr/local/bin/oixc-proxy`。若该目录不可写，
   会**只为复制二进制这一步**请求 `sudo`；用 `sudo` 整体运行安装器会被拒绝；
3. 创建 `~/Library/LaunchAgents/io.oixc.proxy.plist`（已存在则报错，
   见故障排查）；
4. 创建日志目录并 `launchctl bootstrap` 注册、`kickstart -k` 启动。

成功输出：

```text
Installed /usr/local/bin/oixc-proxy and started LaunchAgent io.oixc.proxy from /Users/you/Library/LaunchAgents/io.oixc.proxy.plist
```

### 运行行为与日志

- plist 中 `RunAtLoad` + `KeepAlive` 均为 `true`：**登录后自动启动**，
  进程异常退出时自动拉起；
- 服务以登录用户身份运行；
- 日志保存在 `~/Library/Logs/oixc-proxy.stdout.log` / `oixc-proxy.stderr.log`，
  不含任何敏感信息（stderr 日志只含脱敏的、按请求统计的性能事件；从不
  记录 token、PSK、目标名、ECH 配置或派生密钥）。

查看服务状态：

```sh
launchctl print "gui/$(id -u)/io.oixc.proxy"
```

输出中 `state = running` 即正常运行。

查看日志：

```sh
tail -f ~/Library/Logs/oixc-proxy.stderr.log    # 服务日志与性能事件
tail -f ~/Library/Logs/oixc-proxy.stdout.log    # 标准输出
```

启动成功的标志性日志（stderr）：

```text
Proxy ready: SOCKS5 127.0.0.1:6172; nodelist http://127.0.0.1:6173/surge-proxies.conf; clash http://127.0.0.1:6173/clash-proxies.yaml; 91 named nodes; refresh 1h0m0s
```

### 验证运行

```sh
# 健康检查（期望 204）
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:6173/healthz

# Surge provider（前几行）
curl -s http://127.0.0.1:6173/surge-proxies.conf | head -5

# Clash provider（前几行）
curl -s http://127.0.0.1:6173/clash-proxies.yaml | head -5

# SOCKS5 连通性：从 provider 中取任意一对 username/password
curl -x socks5://USERNAME:PASSWORD@127.0.0.1:6172 https://ip.sb
```

### 更新

更新只涉及替换二进制，**不要**直接重跑 `install-launch-agent`
（plist 已存在会报错，见故障排查）。

```sh
# 1. 重新构建
cargo build --release

# 2. 原子替换已安装的二进制。不要原地 cp 覆写：macOS 内核会缓存代码签名，
#    被覆写的可执行文件下次启动会被杀（Killed: 9 / OS_REASON_CODESIGNING）
cp target/release/oixc-proxy /usr/local/bin/oixc-proxy.new
mv /usr/local/bin/oixc-proxy.new /usr/local/bin/oixc-proxy
# 若提示权限不足：
# sudo mv /usr/local/bin/oixc-proxy.new /usr/local/bin/oixc-proxy

# 3. 重启服务（kill 并立即重启，KeepAlive 也会兜底）
launchctl kickstart -k "gui/$(id -u)/io.oixc.proxy"

# 4. 确认新版本运行
launchctl print "gui/$(id -u)/io.oixc.proxy" | grep -i "state"
tail -3 ~/Library/Logs/oixc-proxy.stderr.log
```

### 卸载

```sh
# 1. 停止并注销服务
launchctl bootout "gui/$(id -u)/io.oixc.proxy"

# 2. 删除 plist（否则下次 install-launch-agent 会报“已存在”）
rm ~/Library/LaunchAgents/io.oixc.proxy.plist

# 3. 删除二进制（可能需 sudo）
sudo rm /usr/local/bin/oixc-proxy

# 4. 可选：清理配置与日志
rm -rf ~/.config/oixc-proxy
rm -f ~/Library/Logs/oixc-proxy.stdout.log ~/Library/Logs/oixc-proxy.stderr.log
```

### 故障排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `do not run install-launch-agent with sudo` | 用 sudo 整体运行了安装器 | 以登录用户身份运行；sudo 只会在复制二进制时按需请求 |
| 安装报 `service definition already exists` | plist 已存在（服务已装过） | 先 `launchctl bootout "gui/$(id -u)/io.oixc.proxy"`，`rm ~/Library/LaunchAgents/io.oixc.proxy.plist`，再重跑安装器 |
| `launchctl bootstrap failed: 5: Input/output error` | 服务已在运行，重复注册 | 用 `launchctl kickstart -k "gui/$(id -u)/io.oixc.proxy"` 重启即可 |
| 更新后启动报 `Killed: 9`（日志含 `OS_REASON_CODESIGNING`） | 用 `cp` 原地覆写了正在运行的签名可执行文件，内核代码签名缓存失效 | 用「临时文件 + `mv`」原子替换二进制（见“更新”一节），再 `launchctl kickstart -k` |
| 启动报 `permissions` 错误 | 配置文件权限过宽 | `chmod 600 ~/.config/oixc-proxy/oixc-proxy.conf` |
| 启动报 `outbound-ip is required` | listen 为 `0.0.0.0` 但未设 outbound-ip | 在配置中添加 `outbound-ip=<本机局域网 IP>` |
| 启动报 TLS / certificate 错误 | 系统时间不正确 | 系统设置 → 通用 → 日期与时间，打开“自动设置时间与日期” |
| 启动报 DNS 解析失败 | 无法解析 `oix-api.dler.io` | `nslookup oix-api.dler.io`；检查网络与 DNS 设置 |
| provider 返回 503 | 节点目录尚未加载完成 | 等待 5~10 秒后重试 |
| provider 节点数为 0 | token 无效，或账户无 Fusion/CIA/IXP 节点 | `oixc-proxy information` 先验证 token；若账户确实无此类节点，手动编辑 `~/Library/LaunchAgents/io.oixc.proxy.plist`，在 `ProgramArguments` 数组中 `serve` 之后追加 `--disable-node-filter`，再 `launchctl kickstart -k "gui/$(id -u)/io.oixc.proxy"` |
| 端口被占用 | 其他服务占用 6172/6173 | `lsof -nP -i :6172 -i :6173`；换端口或停掉冲突服务 |
| 客户端连不上 SOCKS5 | 未允许 macOS 防火墙传入连接 | 系统设置 → 网络 → 防火墙 → 选项，允许 `oixc-proxy` 接受传入连接；确认监听为 `0.0.0.0` 且配置了 `outbound-ip` |
| 局域网其他设备连不上 | 不在同一子网或路由不通 | 确认设备与本机同网段；从其他设备 `curl http://<本机IP>:6173/healthz` 测试 |
| 运行一段时间后节点不再更新 | token 过期 | 更新配置文件中的 token 后 `launchctl kickstart -k "gui/$(id -u)/io.oixc.proxy"` |

---

## Linux（systemd 用户服务）

### 安装

通用准备完成后，以**登录用户**身份执行（不要加 `sudo`）：

```sh
target/release/oixc-proxy install-systemd
```

该命令依次完成：

1. 校验配置文件（`~/.config/oixc-proxy/oixc-proxy.conf`，可用
   `--config PATH` 指定其他文件）；
2. 把当前可执行文件安装到 `/usr/local/bin/oixc-proxy`。若该目录不可写，
   会**只为复制二进制这一步**请求 `sudo`；用 `sudo` 整体运行安装器会被拒绝；
3. 创建 `~/.config/systemd/user/oixc-proxy.service`（已存在则报错，
   见故障排查）；
4. `systemctl --user daemon-reload` 并 `enable --now` 启动。

成功输出：

```text
Installed /usr/local/bin/oixc-proxy and started systemd user service oixc-proxy.service from /home/you/.config/systemd/user/oixc-proxy.service
```

### 运行行为与日志

- 单元为 `Type=simple`，`Restart=on-failure`（5 秒后重拉），开机/登录后
  随 user manager 启动；
- 服务以登录用户身份运行，并启用加固（`NoNewPrivileges`、`PrivateTmp`、
  `ProtectSystem=strict`、`ProtectHome=read-only`、受限地址族等）；
- 标准输出/错误进入 journal，不落敏感信息（同 macOS，见上一节说明）。

查看状态与日志：

```sh
systemctl --user status oixc-proxy.service
journalctl --user -u oixc-proxy.service -f      # 实时日志
journalctl --user -u oixc-proxy.service | tail -20
```

启动成功的标志性日志：

```text
Proxy ready: SOCKS5 127.0.0.1:6172; nodelist http://127.0.0.1:6173/surge-proxies.conf; clash http://127.0.0.1:6173/clash-proxies.yaml; 91 named nodes; refresh 1h0m0s
```

### 无头服务器（可选）

SSH 登入的机器上没有交互登录会话，user manager 默认会在最后一个会话
退出后停止用户服务。让服务在登出后继续运行：

```sh
sudo loginctl enable-linger YOUR_USER
```

### 更新

更新只涉及替换二进制，**不要**直接重跑 `install-systemd`
（单元已存在会报错，见故障排查）。

```sh
# 1. 重新构建
cargo build --release

# 2. 覆盖已安装的二进制（/usr/local/bin 不可写时需要 sudo）
cp target/release/oixc-proxy /usr/local/bin/oixc-proxy
# 若提示权限不足：
# sudo cp target/release/oixc-proxy /usr/local/bin/oixc-proxy

# 3. 重启服务
systemctl --user restart oixc-proxy.service

# 4. 确认新版本运行
systemctl --user status oixc-proxy.service | head -3
journalctl --user -u oixc-proxy.service | tail -3
```

### 卸载

```sh
# 1. 停止并禁用服务
systemctl --user disable --now oixc-proxy.service

# 2. 删除单元（否则下次 install-systemd 会报“已存在”）
rm ~/.config/systemd/user/oixc-proxy.service

# 3. 重新加载 user manager
systemctl --user daemon-reload

# 4. 删除二进制（可能需 sudo）
sudo rm /usr/local/bin/oixc-proxy

# 5. 可选：清理配置
rm -rf ~/.config/oixc-proxy
```

### 故障排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `do not run install-systemd with sudo` | 用 sudo 整体运行了安装器 | 以登录用户身份运行；sudo 只会在复制二进制时按需请求 |
| 安装报 `service definition already exists` | 单元已存在（服务已装过） | 先 `systemctl --user disable --now oixc-proxy.service`，`rm ~/.config/systemd/user/oixc-proxy.service`，`systemctl --user daemon-reload`，再重跑安装器 |
| `Failed to connect to bus` | 无登录会话，user manager 未启动 | 用 `loginctl enable-linger YOUR_USER` 启用 linger；或先在桌面会话中安装 |
| 启动报 `permissions` 错误 | 配置文件权限过宽 | `chmod 600 ~/.config/oixc-proxy/oixc-proxy.conf` |
| 启动报 `outbound-ip is required` | listen 为 `0.0.0.0` 但未设 outbound-ip | 在配置中添加 `outbound-ip=<本机局域网 IP>` |
| 启动报 TLS / certificate 错误 | 系统时间不正确 | 确认 `timedatectl` 已启用 NTP 同步 |
| 启动报 DNS 解析失败 | 无法解析 `oix-api.dler.io` | `nslookup oix-api.dler.io`；检查 DNS 设置 |
| provider 返回 503 | 节点目录尚未加载完成 | 等待 5~10 秒后重试 |
| provider 节点数为 0 | token 无效，或账户无 Fusion/CIA/IXP 节点 | `oixc-proxy information` 先验证 token；若账户确实无此类节点，编辑 `~/.config/systemd/user/oixc-proxy.service` 的 `ExecStart` 行，在 `serve` 之后追加 `--disable-node-filter`，然后 `systemctl --user daemon-reload && systemctl --user restart oixc-proxy.service` |
| 端口被占用 | 其他服务占用 6172/6173 | `ss -tlnp \| grep -E '617[23]'`；换端口或停掉冲突服务 |
| 客户端连不上 SOCKS5 | 系统防火墙未放行传入连接 | 放行 6172/6173 端口（`firewalld` / `ufw`）；确认监听为 `0.0.0.0` 且配置了 `outbound-ip` |
| 运行一段时间后节点不再更新 | token 过期 | 更新配置文件中的 token 后 `systemctl --user restart oixc-proxy.service` |

---

## OpenWrt（斐讯 N1）

本文档面向自动化 agent（可能运行在 Windows、macOS 或 Linux 上），描述如何
在运行 OpenWrt 的斐讯 N1 上部署 `oixc-proxy` 静态二进制，并让局域网内的
Clash 系客户端通过 HTTP proxy-provider 引用节点。

> **约定**：下文以 N1 LAN IP `192.168.1.2`、SSH 用户 `root` 为例。
> 所有远程命令均通过 SSH 执行；文件创建优先使用 SSH heredoc 以避免
> Windows CRLF 换行符问题。

### 前提检查

在开始之前，确认以下条件：

- [ ] 拥有有效的 oixCloud access token
- [ ] 已编译好 aarch64 musl 静态二进制（ELF 64-bit ARM aarch64, statically linked）
- [ ] 知道 N1 的 LAN IP 地址
- [ ] 能通过 SSH 连接到 N1（密码或密钥）

**Windows 环境注意事项**：Windows 10 1809+ 自带 OpenSSH 客户端
（`ssh.exe`、`scp.exe`、`sftp.exe`），通常位于 `C:\Windows\System32\OpenSSH\`。
如果不可用，可安装 [PuTTY](https://www.putty.org/)（提供 `plink.exe`、
`pscp.exe`）。**CRLF 陷阱**：Windows 上创建的文本文件默认使用 `\r\n`
换行，传入 `\r` 会导致 Shell 脚本和配置解析失败。本文档所有远程文件均
通过 SSH heredoc 直接写入 N1，从根本上避免此问题；如果必须从本地传输
文本文件，上传后在 N1 上执行 `sed -i 's/\r$//' <file>` 修复。

```sh
ssh -o StrictHostKeyChecking=accept-new root@192.168.1.2 '
  echo "=== arch ===";    uname -m
  echo "=== storage ==="; df -h /usr/bin /root
  echo "=== time ===";    date -u
  echo "=== ntp ===";     ntptime 2>/dev/null || echo "ntptime not available"
  echo "=== dns ===";     nslookup oix-api.dler.io 2>&1 | head -6
'
```

逐项确认：

| 检查项 | 期望值 | 不满足时的处理 |
| --- | --- | --- |
| `uname -m` | `aarch64` | 二进制不兼容，停止部署 |
| `/usr/bin` 可用空间 | ≥ 10 MB | 清理包或改放 `/root/` |
| `date -u` | 与真实 UTC 偏差 < 5 分钟 | 见下方 NTP 修复 |
| DNS 解析 | 返回 `oix-api.dler.io` 的 IP | 检查 `/etc/resolv.conf` 或 WAN DNS |

#### NTP 修复（关键）

N1 无硬件 RTC，断电后时钟归零。**TLS 证书校验要求系统时间正确**，
否则 oixc-proxy 无法连接 oixCloud API 和节点。

```sh
ssh root@192.168.1.2 '
  # 确认 NTP 已启用
  uci get system.ntp.enabled 2>/dev/null || uci set system.ntp.enabled=1
  # 如果 NTP 服务器列表为空，添加公共服务器
  uci get system.ntp.server 2>/dev/null || {
    uci add_list system.ntp.server="ntp.aliyun.com"
    uci add_list system.ntp.server="pool.ntp.org"
  }
  uci commit system
  /etc/init.d/sysntpd restart
  sleep 3
  date -u
'
```

如果 `date -u` 仍然偏差很大，手动设置：

```sh
ssh root@192.168.1.2 'date -s "2026-07-31 12:00:00"'  # 替换为当前真实时间
```

### 传输二进制

二进制约 5 MB，静态链接，无运行时依赖。需要先交叉编译
aarch64 musl 目标（在控制机仓库根目录）：

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

#### 方式 A：scp（推荐，Windows/macOS/Linux 通用）

```sh
scp -o StrictHostKeyChecking=accept-new \
  target/aarch64-unknown-linux-musl/release/oixc-proxy \
  root@192.168.1.2:/usr/bin/oixc-proxy
```

Windows 上若 `scp` 不在 PATH 中，使用完整路径
`C:\Windows\System32\OpenSSH\scp.exe`，或改用 PuTTY 的 `pscp.exe`：

```powershell
pscp.exe -batch target\aarch64-unknown-linux-musl\release\oixc-proxy root@192.168.1.2:/usr/bin/oixc-proxy
```

#### 方式 B：HTTP 拉取（无 scp 时的备选）

在本机启动临时 HTTP 服务，让 N1 用 `wget` 拉取：

```sh
# 本机（在二进制所在目录执行）
python3 -m http.server 8888
# 或 Windows PowerShell:
# python -m http.server 8888
```

```sh
# N1 上拉取（替换 192.168.1.100 为本机 LAN IP）
ssh root@192.168.1.2 '
  wget -O /usr/bin/oixc-proxy http://192.168.1.100:8888/oixc-proxy
'
```

完成后关闭本机 HTTP 服务。

#### 设置权限并验证

```sh
ssh root@192.168.1.2 '
  chmod 755 /usr/bin/oixc-proxy
  file /usr/bin/oixc-proxy 2>/dev/null || head -c 20 /usr/bin/oixc-proxy | od -A x -t x1z | head -2
'
```

ELF 头应以 `7f 45 4c 46 02 01 01` 开头（ELF, 64-bit, little-endian）。

### 配置文件

通过 SSH heredoc 直接写入，避免 CRLF 问题（键的语义见
[通用准备 → 配置](#配置)）：

```sh
ssh root@192.168.1.2 '
  mkdir -p /root/.config/oixc-proxy
  cat > /root/.config/oixc-proxy/oixc-proxy.conf << "OIXC_EOF"
token=YOUR_OIXCLOUD_ACCESS_TOKEN
socks5-listen=0.0.0.0:6172
nodelist-listen=0.0.0.0:6173
outbound-ip=192.168.1.2
node-refresh-interval=1h
OIXC_EOF
  chmod 600 /root/.config/oixc-proxy/oixc-proxy.conf
'
```

> 将 `YOUR_OIXCLOUD_ACCESS_TOKEN` 替换为真实 token，
> `192.168.1.2` 替换为 N1 的实际 LAN IP。局域网共享必须监听 `0.0.0.0`
> 并填写 `outbound-ip`（即 N1 的 LAN IP）。

### 防火墙

OpenWrt 默认阻止 LAN 到路由器自身的新入站连接。放行两个端口：

```sh
ssh root@192.168.1.2 '
  # 避免重复添加：先检查是否已存在
  if ! uci show firewall 2>/dev/null | grep -q "oixc-proxy"; then
    uci add firewall rule
    uci set firewall.@rule[-1].name="oixc-proxy"
    uci set firewall.@rule[-1].src="lan"
    uci set firewall.@rule[-1].proto="tcp"
    uci set firewall.@rule[-1].dest_port="6172 6173"
    uci set firewall.@rule[-1].target="ACCEPT"
    uci commit firewall
    /etc/init.d/firewall reload
    echo "firewall rule added"
  else
    echo "firewall rule already exists"
  fi
'
```

同时确认 N1 的**出站** HTTPS（443）未被阻止（默认允许）：

```sh
ssh root@192.168.1.2 'wget -q -O /dev/null --timeout=5 https://oix-api.dler.io && echo "outbound HTTPS OK" || echo "outbound HTTPS BLOCKED"'
```

### procd 服务（开机自启）

#### 手动测试

```sh
ssh root@192.168.1.2 '/usr/bin/oixc-proxy serve'
```

正常输出：

```text
Proxy ready: SOCKS5 0.0.0.0:6172; nodelist http://0.0.0.0:6173/surge-proxies.conf; clash http://0.0.0.0:6173/clash-proxies.yaml; 91 named nodes; refresh 1h0m0s
```

确认节点数 > 0 且无报错后，`Ctrl-C` 停止，改用 procd 托管。

#### procd init 脚本

通过 SSH heredoc 写入 init 脚本（**不要**在 Windows 本地编辑后传输）：

```sh
ssh root@192.168.1.2 '
  cat > /etc/init.d/oixc-proxy << "INIT_EOF"
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

PROG=/usr/bin/oixc-proxy
CONF=/root/.config/oixc-proxy/oixc-proxy.conf

start_service() {
    procd_open_instance oixc-proxy
    procd_set_param command "$PROG" serve --config "$CONF"
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param limits nofile="4096 4096"
    procd_close_instance
}
INIT_EOF
  chmod 755 /etc/init.d/oixc-proxy
  /etc/init.d/oixc-proxy enable
  /etc/init.d/oixc-proxy start
  echo "service started"
'
```

> **节点过滤**：默认只发布名称含 `Fusion`、`CIA` 或 `IXP` 标记的节点。
> 如果你的账户没有这些类型的节点，需要在 init 脚本的 `procd_set_param command`
> 行追加 `--disable-node-filter` 以发布全部可用节点：
>
> ```sh
> procd_set_param command "$PROG" serve --config "$CONF" --disable-node-filter
> ```
>
> 修改后执行 `/etc/init.d/oixc-proxy restart`。

查看运行状态和日志：

```sh
ssh root@192.168.1.2 '
  /etc/init.d/oixc-proxy status
  logread -e oixc-proxy | tail -20
'
```

### 验证

N1 上可能没有 `curl`，优先使用 busybox 自带的 `wget`：

```sh
ssh root@192.168.1.2 '
  echo "=== healthz ==="
  wget -q -S -O /dev/null http://127.0.0.1:6173/healthz 2>&1 | grep "HTTP/"

  echo "=== clash provider (first 8 lines) ==="
  wget -q -O - http://127.0.0.1:6173/clash-proxies.yaml 2>/dev/null | head -8

  echo "=== surge provider (first 3 lines) ==="
  wget -q -O - http://127.0.0.1:6173/surge-proxies.conf 2>/dev/null | head -3
'
```

从局域网另一台机器验证外部可达性（在该机器上执行）：

```sh
# 健康检查（期望 204）
curl -s -o /dev/null -w "%{http_code}\n" http://192.168.1.2:6173/healthz

# SOCKS5 连通性：从 clash provider 中取任意一对 username/password
curl -x socks5://USERNAME:PASSWORD@192.168.1.2:6172 https://ip.sb
```

Clash 系客户端接入见 [通用准备 → 客户端接入](#客户端接入)，把其中的
`127.0.0.1:6173` 换成 `192.168.1.2:6173`。如果客户端与 N1 不在同一子网，
确保路由可达且防火墙放行。

### 更新

```sh
# 传输新二进制（方式同上方“传输二进制”）
scp target/aarch64-unknown-linux-musl/release/oixc-proxy root@192.168.1.2:/usr/bin/oixc-proxy

# 重启服务
ssh root@192.168.1.2 '/etc/init.d/oixc-proxy restart'

# 确认新版本运行
ssh root@192.168.1.2 'logread -e oixc-proxy | tail -3'
```

> 如果正在运行的二进制被覆盖，Linux 允许已打开的文件继续执行直到进程退出。
> procd 的 `restart` 会先 SIGTERM 旧进程再启动新进程，无需手动 kill。

### 故障排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 启动报 `permissions` 错误 | 配置文件权限过宽 | `chmod 600 /root/.config/oixc-proxy/oixc-proxy.conf` |
| 启动报 `outbound-ip is required` | listen 为 `0.0.0.0` 但未设 outbound-ip | 在配置中添加 `outbound-ip=<N1 LAN IP>` |
| 启动报 TLS / certificate 错误 | N1 系统时间不正确 | 修复 NTP（见“前提检查”），重启服务 |
| 启动报 DNS 解析失败 | N1 无法解析 `oix-api.dler.io` | 检查 WAN DNS、`/etc/resolv.conf` |
| 客户端连不上 SOCKS5 | 防火墙未放行 | `iptables -L INPUT -n \| grep 617`；重新执行“防火墙”一节 |
| provider 返回 503 | 节点目录尚未加载完成 | 等待 5~10 秒后重试 |
| provider 节点数为 0 | token 无效，或账户无 Fusion/CIA/IXP 节点且未加 `--disable-node-filter` | 检查 token；若账户无此类节点，在 init 脚本中追加 `--disable-node-filter`（见“procd 服务”一节） |
| `logread` 无 oixc-proxy 输出 | procd 未捕获 stdout/stderr | 确认 init 脚本含 `procd_set_param stdout 1` 和 `stderr 1` |
| init 脚本执行报 `not found` 或语法错误 | CRLF 换行符 | `sed -i 's/\r$//' /etc/init.d/oixc-proxy` |
| 配置文件解析报未知键 | 使用了引号、section 或拼写错误 | 严格 `key=value`，无引号，无 `[]` section |
| 端口被占用 | 其他服务占用了 6172/6173 | `netstat -tlnp \| grep -E '617[23]'`；更换端口或停止冲突服务 |
| 二进制无法执行 | 架构不匹配或文件损坏 | `uname -m` 确认 `aarch64`；重新传输并校验 ELF 头 |
| 运行一段时间后节点不再更新 | token 过期 | 更新配置中的 token，`/etc/init.d/oixc-proxy restart` |
