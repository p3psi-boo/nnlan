# Linux Subnet Router

## 操作

发布节点先由管理员启用需要的地址族转发，再启动 daemon：

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo ./target/release/nnlan --config ./nnlan.toml run
```

这里只展示临时 sysctl；需要开机保留时写入该主机的 sysctl 配置。
nnlan 检查转发状态，不自动重设宿主机的全局 sysctl；未开启对应地址族时发布操作报错，配置不变。
已有防火墙仍参与判定，不清空现有规则、不覆盖其 DROP 策略。

在发布节点的另一终端：

```bash
sudo ./target/release/nnlan routes advertise 192.168.77.0/24
sudo ./target/release/nnlan routes advertise fd77::/64
sudo ./target/release/nnlan routes withdraw 192.168.77.0/24
```

在接收节点：

```bash
sudo ./target/release/nnlan routes
sudo ./target/release/nnlan routes accept 192.168.77.0/24 --via B
sudo ./target/release/nnlan routes accept fd77::/64 --via B
sudo ./target/release/nnlan routes accept 192.168.77.0/24 --via C --replace
sudo ./target/release/nnlan routes reject 192.168.77.0/24
```

`--via` 接受完整公钥、唯一节点名或覆盖网络 IP；持久化的是完整公钥。
接受时要求节点可信且确实发布了该前缀。配置中同一个前缀最多选择一个发布者；
切换到另一个相同前缀的物理 LAN 必须使用 `--replace`。
`routes` 中 `accepted` 是持久化选择，`selected[].state` 是当前 `forward` / `blocked` 状态。

命令通过 0600 Unix socket 到运行中的 daemon，原子更新配置并立即应用；保留原配置文件的 uid/gid。
`--no-tun` 模式不接受路由变更。也可以在停机后编辑配置，再启动应用。

## 数据与隔离

- 普通节点 VIP 通信与子网通信共用逐跳 Noise、FEC/RTX；目的发布者是 Envelope 的节点身份，CIDR 不充当节点身份。可信中继可读载荷，但仍按选定发布者转发。
- 子网请求的 IP 源必须属于发起者；子网回复的源必须匹配本地所选发布者的最长前缀。
  更具体前缀失效时不回落到较宽前缀或另一个发布者。
- 发布节点只向自己显式发布的目的前缀转发，不因默认 `relay=true` 而开放 LAN 转发。
- IPv4/IPv6 出 LAN 做 masquerade，因此 LAN 主机不需要配置覆盖网络的返回路由。
  LAN 到 TUN 只允许 conntrack established/related 返回流量；这不是 LAN 主机主动接入组网的代理方案。
- 子网路由进入专用 table `33033`，rule priority `23333`，优先于主路由表。
  路由指定本机 VIP 为首选源地址，因此即使本机连接同 CIDR 的 LAN，也会按显式选择访问远端 LAN。
  Linux local 表仍优先：本机已拥有的地址仍指向本机，不重写 local 表。
- 本进程带 `SO_MARK=0x336733` 的底层 UDP 和 peer 主机名解析 socket 跳过该子网策略，避免底层地址被接受网段覆盖时绕回 TUN。
  严格 IPv4 RPF 需要 `src_valid_mark=1`；收包恢复连接标记，独立 ARP request 标记维持底层邻居解析。
- `inet nnlan` 和 `arp nnlan` nft 表附带完整节点身份及 TUN 名的所有权标识；预先占用的表、规则或路由会报错，不接管。
  当前同一 network namespace 运行一个实例；多个网络使用独立 namespace。

## 失效行为

接受过的前缀始终保留 TUN 路由和较低优先级的 blackhole 路由；用户态对已失联或撤回发布的选择丢弃数据。
持久 nft OUTPUT/FORWARD 规则另外禁止这些前缀走物理接口。
SIGKILL 或 TUN 消失后，blackhole 和 nft 规则仍然生效，不会连接本机同名网段里的另一台机器。
重启保留选择并认领自身的规则。显式 `routes reject` 删除该前缀的本地选择与保护，才恢复主路由表行为。
正常停止也保留选择的保护；停止状态下可重新启动再 reject，或显式编辑配置后重启。

配置 fsync 后若内核更新失败，命令明确返回错误并终止 daemon，不继续声称内核和配置一致。
已安装的 nft 保护不随 daemon 退出删除。通过 nft 事务先更新保护，再更新专用路由。

## 验证

```bash
nix develop --command make e2e-subnet
```

`tests/e2e/subnet_netns.py` 创建六个隔离 namespace：A/B/C 和各自的 LAN 主机。
三个 daemon 构成 A→B→C，多跳访问 C 不依赖 A/C 直连。
三个 LAN 均为 `192.168.77.0/24` + `fd77::/64`，三个服务地址完全相同，HTTP 返回不同的 LAN 标识。
测试覆盖：广告不自动接受、双栈 TCP/masquerade、拒绝隐式换发布者、撤回不回落、显式替换、
最长前缀撤回阻断、发布者重启、客户端 SIGKILL 后无物理 LAN 泄漏、重启保持选择、显式 reject 恢复本地 LAN。
每个 HTTP 响应校验 45056 字节应用负载及对端实际看到的 NAT 源地址。
另在 SIGKILL 后清空专用路由表，独立验证 nft 保护不是依赖 blackhole 才阻断。
本地封禁所选发布者时，保留其选择并阻断双栈访问，不回落到另一个同前缀发布者或物理 LAN；
显式 `members allow` 后恢复原发布者。

内核语义参考：[Linux IP sysctl](https://kernel.org/doc/html/latest/networking/ip-sysctl.html)、
[nftables 手册](https://netfilter.org/projects/nftables/manpage.html)。
Exit Node 的默认路由、全流量防直出和 DNS 例外独立实现，不能以子网测试代替其验收。
