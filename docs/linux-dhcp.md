# DHCP 与底层路由更新

## 配置

Exit Node 的默认防直出会同时覆盖普通应用和系统 DHCP socket。
`dhcp_client_uid` 是一个显式、窄范围的底层例外，只授予运行 DHCP 客户端的系统 UID：

```bash
id -u systemd-network
```

将实际输出填入配置**顶层**，例如本机服务 UID 为 123 时：

```toml
dhcp_client_uid = 123
```

默认不授权任何 UID。使用专用系统服务 UID，不与普通应用共享；不会按进程名猜测或自动信任桌面用户。
选择其他网络管理器时，先确认创建 DHCP socket 的实际 UID；root 服务可显式填写 0。
当前实现不读取远程 NSS，也不依赖网络已建立才能解析用户名。改变客户端服务 UID 时同时更新此配置。

已有 daemon 需重启加载此项；退出期间持久 guard 保留，随后启动核验并更新自身规则。
在尚未启动 daemon 时可以先执行 `nnlan --config … guard`。
配置 peer 仍只需 endpoint 与公钥；此项用于安装了出口/子网防回落策略的 DHCP 主机。

## 两道约束

- IPv4：指定 UID 的 UDP `68 → 67`。
- IPv6：同一 UID 的 UDP `546 → 547`。
- 不放行该 UID 的其他端口、TCP、DNS或任意应用 UID。

第一道是优先级 23332 的策略路由，按 UID、UDP 和源/目的端口选择 main 表，
使 socket 在首次路由查找时不会被出口 blackhole 截断。第二道是 nft output 再次匹配
同样的 UID/协议/端口，设置本实例 mark；mark 沿 conntrack 恢复。
标记在 route 类型的 output chain 中完成，内核会按需要重新查找路由。
返回的 DHCP 端口对在物理 prerouting 标记，保持严格 IPv4 RPF 下的续租可用。

先安装 nft，再更新路由例外；UID 变更、删除配置、重复执行均核验既有专用规则。
优先级 23332 与原来的 23333、表 33033 同属实例所有权检查，外部冲突明确报错。
内核主路由表由系统网络管理器维护，nnlan 不复制或固定旧网关，也不写主机 sysctl。

规则属于客户端链路维护，不代表信任 DHCP 服务器发布的任何覆盖成员、子网或出口。
AF_PACKET 原始包是有能力权限的 OS 网络服务行为，不通过 inet output；普通应用没有因此获得原始包权限。

## 多地址 UDP 回复

通配地址监听使用 `IP_PKTINFO` / `IPV6_PKTINFO` 记录每个认证邻居实际访问的本机地址，
回复从该地址发出，而不是任由内核选择出口网卡的主地址。例如 peer 访问本机 WAN 地址，
但回复经 LAN 路由发送时，仍保持原来的 WAN 源地址。远端公钥和端点验证没有放宽。

本地地址绑定保存在有界握手/邻居状态中，未认证包不更新已建立连接的绑定。
IPv4 与全局 IPv6 不固定入口网卡，网关更换后继续使用系统路由；link-local IPv6 保留 scope。
明确的地址失效错误清除旧绑定，连接迁移继续经过已有认证和换钥流程。

## 验证

```bash
nix develop --command make e2e-dhcp-policy
make e2e-dhcp
```

`dhcp_policy_netns.py` 已在内核中验证两个地址族的正确 UID、错误 UID、错误源端口、
错误目的端口、TCP、严格 RPF 回复，以及删除策略表后 nft 的独立约束。
测试将低端口设为普通 UID 可绑定，证明保护不是偶然依赖“应用绑定不了 68/546”。
还检查 UID 替换、重复执行、移除授权后的规则回收，测试结束清理自己的 namespace。

`tests/nixos/dhcp.nix` 使用真实 networkd、dnsmasq、三个 VM 和实际 TUN，
已通过 DHCPv4/v6 冷启动、RA 默认路由、IPv4 单播续租与 IPv6 T1 续租、IPv4 地址和网关更新、
daemon 停机时 DHCP 与应用防直出的分离，以及显式 off 的正向对照。
结果在 `target/dhcp-result/dhcp.json`，含二进制与测试文件摘要；不会用 UDP 合成探针代替实际租约验收。
测试同时验证 UDP 通配监听经不同网卡回复时保留目标地址、真实 TCP 负载和双栈 UDP/TCP DNS。

租约为 120 秒，保留 OS 的真实 T1/T2/到期处理，不靠重启 networkd 或手工设置地址来加速测试。
固定版本 networkd 的 renew 命令只主动触发 IPv4，IPv6 等待自身 T1；IPv4 续租 socket 绑定
租约地址，服务器广播 NAK 后可能要等重绑定/到期才重新发现。实测换址等待约 54–102 秒（取决于租约剩余时间），
不把它描述成瞬时切换；nnlan 的 boot ID 在底层变化前后保持不变。

仍需补充的矩阵包括不同网络管理器、IPv6 动态前缀/多路由器切换、服务器长期离线直至租约到期与更长时间更新压力。

接口参考：[dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)、
[systemd.network](https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html)、
[Linux ip-rule](https://man7.org/linux/man-pages/man8/ip-rule.8.html)。
测试计时依据：[固定版本 networkd renew](https://github.com/systemd/systemd/blob/v261.2/src/network/networkd-link-varlink.c)、
[DHCP socket 与地址绑定](https://github.com/systemd/systemd/blob/v261.2/src/libsystemd-network/dhcp-client-send.c)。
