# Linux Exit Node

## 使用

作为出口的节点先启用主机转发，再运行 daemon：

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo ./target/release/nnlan --config ./nnlan.toml run
```

在该节点的另一终端发布 / 撤回出口服务：

```bash
sudo ./target/release/nnlan exit serve on
sudo ./target/release/nnlan exit serve off
```

其他节点显式选择出口，查询状态或停用：

```bash
sudo ./target/release/nnlan exit use B
sudo ./target/release/nnlan routes
sudo ./target/release/nnlan status
sudo ./target/release/nnlan exit off
```

`B` 可以是完整公钥、唯一名称或覆盖网络 IP，保存到配置的是完整公钥。
首次选择时要求该节点已签名发布出口能力。失联不删除选择，不自动换到另一个出口；
再次 `exit use C` 才切换。与子网选择相同，修改在返回成功前原子保存并应用。
选择者自身不同时发布出口服务，避免默认路由转发环；普通 relay 和 Subnet Router 能力独立。

`routes.exit_state` 显示 `disabled`、`active` 或 `unreachable`，这里的 active 指覆盖网络中存在
可信的出口能力声明和到该节点的路径，不是对整个互联网可达性的保证。
某一地址族的外部路径失效时，该族不会使用客户端本地 WAN；内核错误或超时交给应用。

## 主机条件

主机全局 sysctl 由管理员管理，daemon 不重设系统全局转发设置。
开启服务前检查 IPv4/IPv6 forwarding；客户端使用严格 IPv4 反向路径检查时，还需：

```bash
sudo sysctl -w net.ipv4.conf.all.src_valid_mark=1
```

缺失该设置时选择操作报错并保持原配置。`rp_filter` 的实际模式取 all/interface 的最大值，
测试同时设置相关接口，避免把 loose 模式误认为已验收 strict 模式。
现有主机防火墙继续参与判定；本程序不清空其他规则，也不覆盖其 DROP 策略。

## 路由与持久保护

- 使用与 Subnet Router 相同的专用 table `33033` / rule priority `23333`，不替换主路由表的默认路由。
- 选择出口后，IPv4 和 IPv6 各有一条 TUN 默认路由，首选源为本机对应 VIP；另有独立于 TUN 的 blackhole 默认路由。
- nft OUTPUT/FORWARD 规则禁止普通应用走物理接口。允许 loopback 和必要的 IPv6 邻居发现；没有“root 用户全部放行”或“DNS 端口全部放行”。
- 底层 UDP socket 和配置 peer 专用的 DNS socket 使用 `SO_MARK=0x336733`，这才是物理出口例外。
  nft 保存 / 恢复相应 conntrack mark，入站 daemon UDP 端口也获得用于反向路径检查的标记；Noise 仍验证实际身份。
- 独立的 `arp nnlan` 表给 ARP request 标记，维持严格 RPF 下物理链路的动态邻居解析。
  ARP 不经过 inet 链，仅恢复 IP 收包标记仍会导致邻居过期后底层断连；这里没有给普通 IP 流量增加例外。
- nft 保护先于 TUN 创建、peer 连接和 DNS 查询安装；运行中启用 / 切换出口也先保护再保存选择、更新路由。
  显式 off 则先保存关闭意图，再解除出口约束。
- daemon 正常停止、SIGKILL 或 TUN 被删除，都不自动解除选择的保护；nft 规则不依赖 TUN 仍然存在。
- 节点 VIP 池的物理直出也被阻断，避免节点记录过期后把 `33.0.0.0/8` 或 `fd33::/16` 发往 WAN。
- VIP 作为目的地址的物理入站包同样阻断，避免 Linux weak-host 行为让 VIP 服务绕过加密 TUN 暴露在底层链路上。
- 手动接受的具体子网前缀优先于 Exit 默认路由；已失效的更具体选择仍然阻断，不回落到 Exit。

进程异常退出后，可重启恢复选择，也可在**原 daemon 的 network namespace** 中显式关闭：

```bash
sudo ./target/release/nnlan exit off --offline
# 若 daemon 在单独 namespace：
sudo ip netns exec NAMESPACE ./target/release/nnlan \
  --config /absolute/path/nnlan.toml exit off --offline
```

offline 模式先检查身份锁和现有 nft 所有权标识；运行中的 daemon、错误 namespace 或其他实例的规则会报错。
只清理本实例的出口默认路由 / 约束，保留已接受子网的阻断意图，不改其他服务的网络策略。

## DNS：应用查询与底层引导分开

### 应用查询

应用的 IP 包经逐跳 Noise 链路到选定出口，路径上的中继均可信。出口内核把从 TUN 到达的 UDP/TCP 53 重定向给内置 DNS 转发器；
返回时由 conntrack 恢复原 DNS 地址，客户端不需要覆盖 `/etc/resolv.conf`。
本地 `127.0.0.53` stub 的普通上游查询也走所选出口；已测试这种间接路径。
IPv4 link-local resolver 地址同样可在出口被 DNS 重定向处理。
DoH / DoT 是普通加密 IP 流量，遵守同一默认路由与防直出规则，不进行内容解密。

转发器只绑定 TUN 设备，监听内部 UDP/TCP `7353`，并配合 nft 入站限制；不是开放在 WAN 上的公共 DNS 服务。
查询长度上限 4096 字节、并发 64、任务集合 128、单次解析总时限 3 s、TCP 连接时限 30 s。
使用 Hickory 的报文解析，验证响应源、随机事务 ID 与完整问题；UDP 截断重试 TCP，
超过客户端 UDP 容量的响应设置 TC 让客户端改用 TCP。出口侧按系统上游或显式 `dns_servers` 转发。

### 底层 peer 主机名

这是单独的有界 Hickory resolver，只解析配置中的 peer 名称，不对应用提供代理接口。
UDP 与 TCP socket 都带本实例 mark，所以即使应用防直出已生效，冷启动仍能解析 peer 并恢复连接。
IP 字面量 peer 不创建 DNS resolver。

通常读取系统 DNS；检测到全为 loopback stub 时，尝试 systemd-resolved 的实际上游文件。
其他本地 stub 环境可在顶层配置显式指定实际上游地址：

```toml
dns_servers = ["DNS_SERVER_IP:53"]
```

最多 8 个 IP:port，不自动选择第三方公共 DNS。peer 引导需要直接上游而不是 loopback stub；
没有可用上游时明确报错并保留已安装的出口保护。
该配置也供出口 DNS 转发器使用；客户端和出口可各自使用其底层可达的上游。

## 验收与仍待覆盖

```bash
nix develop --command make e2e-exit
```

`tests/e2e/exit_netns.py` 创建五个 namespace：客户端 A、中继 R、出口 B/C、双栈模拟互联网。
A 自身有可工作的双栈本地 WAN，以便证明失败时没有回落；模拟互联网记录实际应用请求和 DNS 来源。
覆盖双栈多跳 TCP、UDP/TCP DNS、上游 TC→TCP、本地 stub、显式出口切换、单地址族故障、
出口失联、客户端 SIGKILL、TUN 删除、路由表清空后独立 nft 保护、冷启动标记 DNS、
严格 RPF 下强制清空邻居缓存后的 ARP 恢复、VIP 物理明文访问隔离、TUN 启动失败后的保护，
以及在线 / 离线显式关闭。ARP 测试不使用静态邻居条目或放宽 RPF。
还在保持出口选择与 daemon 运行的情况下删除、替换客户端物理 IPv4 地址，验证已认证底层路径迁移后仍经原出口通信。
失败断言既检查应用结果，也检查互联网端没有收到泄漏请求，不把接收侧丢包误当作没有发送。
封禁所选出口身份时保留该选择，双栈应用/DNS 持续阻断，客户端 SIGKILL 后重启亦如此；
显式 `members allow` 后恢复原出口，不选择另一个健康出口或本地 WAN。

独立 `guard`、systemd unit 和 NixOS 模块现已接通；另外的 `make e2e-boot` 用两台真实 VM
验证静态双栈 networkd 的启动前保护、daemon 失败、崩溃重启及 guard 失败阻止网络配置服务启动。
详见 [Linux 开机保护](linux-boot-guard.md)。`make e2e-dhcp` 已验证真实 networkd DHCPv4/v6、
续租、IPv4 地址/默认网关变更和 daemon 停机后的应用阻断，见 [DHCP 与底层更新](linux-dhcp.md)。
NetworkManager、initrd 配网及 IPv6 动态前缀/多路由器矩阵仍待覆盖。

实现接口参考：[Hickory RuntimeProvider](https://docs.rs/hickory-net/0.26.3/hickory_net/runtime/trait.RuntimeProvider.html)、
[Linux IP sysctl](https://kernel.org/doc/html/latest/networking/ip-sysctl.html)、
[nftables 手册](https://netfilter.org/projects/nftables/manpage.html)。
