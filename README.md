# nnlan

Rust 实现的去中心化 Linux 组网软件。**当前已接通双栈 TUN、多跳加密网络、Subnet Router 和
Exit Node（含 DNS、崩溃防直出、networkd 开机保护与 DHCP 更新）；NAT/PMTU 扩展验收和性能仍在推进。**

产品决策见 [docs/project-decisions.md](docs/project-decisions.md)，
已验证范围和剩余工作见 [docs/implementation-status.md](docs/implementation-status.md)。

当前原型使用 **GGB3** 线格式和单层逐跳加密；所有互联节点需一起升级，已有身份、地址与配置可保留。GGB1/GGB2 报文会被明确拒绝，见 [单层加密说明](docs/hop-encryption.md)。

项目已更名为 **nnlan**，命令为 `nnlan`，默认配置为 `nnlan.toml`、TUN 为 `nnlan0`。
此前更名本身不改变公钥、地址派生或 GGB2 协议；更名历史见 [更名说明](docs/project-rename.md)。
`cp` 文件传输暂缓，当前未开放此子命令。

## 开发环境

```bash
nix develop
make check
make build
make perf-compare # 同机对照 nnlan / 内核 WireGuard / wireguard-go（IPv4）
make perf-gigabit # 双向 1000 Mbit/s 整形的底层/覆盖网络对照
make perf    # 预热、重复单 TCP 流测量，含吞吐、CPU、负载下 RTT 与原始数据
make perf-crossed-rekey # 自然交叉换钥后的双栈持续吞吐回归，约 3 分钟
make perf-rekey-transition # 持续 TCP/ICMP 跨越换钥瞬间，再测交叉世代吞吐，约 4 分钟
```

`flake.nix` / `flake.lock` 提供 x86_64-linux、aarch64-linux 的开发环境，
固定 Rust 1.97.1 发布工具链包及网络测试工具；各工具自身的 `--version` 编号可能不同。
包含 rust-analyzer、rustfmt、Clippy、C 编译器、Make、Python、ip/tc、nft、iptables、
ping、iperf3、tcpdump、conntrack、perf 等。`.envrc` 可通过 `direnv allow` 自动启用。
未启用 flakes 时使用 `nix --extra-experimental-features 'nix-command flakes' develop`。
进入 shell 不改路由、防火墙或系统权限。非 Nix 环境使用 `rust-toolchain.toml` 与 `Cargo.lock`。
性能测量范围及前后对照见 [吞吐测量与热点优化](docs/performance-baseline.md)，
成熟实现的同机数据面对照见 [WireGuard 横评](docs/performance-comparison.md)。
TUN GSO/GRO 与按需发送唤醒见 [数据面批处理优化](docs/datapath-batching.md)；
后续的认证大包探测、按组缩减 FEC 填充和实测见 [协议开销优化](docs/protocol-overhead.md)。
直连身份复用、单片/ACK 压缩及小包瓶颈定位见 [紧凑数据记录](docs/compact-data.md)。
高 RTT 的缓存扫描优化、未采用的扩容/缩队列试验见 [高 RTT 记录](docs/high-rtt.md)。
- [高 RTT 待确认容量与 TUN 背压](docs/backpressure.md)
- [满载排队与按流调度](docs/queueing.md)
这些改动保留 GGB3 互通与 FEC/RTX。

FEC 与有限重传默认同时开启；`[repair]` 支持独立的 `fec` / `rtx` 发送开关，修改后重启。
真实双栈弱网对照运行 `nix develop --command make e2e-weaknet`，见 [弱网矩阵](docs/weak-network-testing.md)。

## 成员策略

```bash
nnlan --config ./state/nnlan.toml members
nnlan --config ./state/nnlan.toml members deny PUBLIC_KEY
nnlan --config ./state/nnlan.toml members allow PUBLIC_KEY
```

封禁按完整公钥持久化，覆盖直接握手与传递引荐；不自动更换已选子网/出口。
语义、撤销收敛和验收入口见 [成员策略](docs/membership-policy.md)。

## 开机服务

独立 `guard` 命令和 systemd unit 位于 `packaging/systemd/`；flake 同时提供 NixOS 模块。
部署步骤与开机验收见 [Linux 开机保护](docs/linux-boot-guard.md)。

```bash
nix build                         # 可复现的 Linux 包
make e2e-boot                     # 两台隔离 VM 的真实开机测试
make e2e-dhcp                     # 三台 VM 的 DHCPv4/v6、网关更新与停机保护
```

使用 DHCP 的出口客户端需配置专用服务的 `dhcp_client_uid`，见 [DHCP 与底层更新](docs/linux-dhcp.md)。

## 两个节点开始

分别在两台 Linux 主机初始化配置和身份：

```bash
nnlan --config ./state/nnlan.toml init
nnlan --config ./state/nnlan.toml identity
```

在 A 中登记 B 的真实 UDP 地址和公钥（可通过 CLI 快捷添加，也可手动编辑配置文件）：

```bash
# 推荐：使用 CLI 命令添加 Peer
nnlan --config ./state/nnlan.toml peer add "HOST:7331" "B 的 64 位十六进制公钥"

# 或手动编辑配置文件追加 [[peers]]（初始化配置已包含注释模板，无语法冲突）
# [[peers]]
# endpoint = "HOST:7331"
# public_key = "B 的 64 位十六进制公钥"
```

**B 不需要反向登记 A**；双方用实际密码握手证明身份，A 验证固定的 B 公钥。
公钥用来验证身份，不是保密的入网口令。每个节点默认 relay，默认最多 16 个直连邻居。

```bash
# 一键自检环境（TUN 设备、权限、工具链、配置文件与端口占用）
nnlan --config ./state/nnlan.toml doctor
nnlan --config ./state/nnlan.toml check
nnlan --config ./state/nnlan.toml run --dry-run
sudo ./target/release/nnlan --config ./state/nnlan.toml run
```

运行需要 Linux TUN、iproute2、nftables 和相应网络管理权限。默认 TUN 名 `nnlan0`、MTU 1280；
已有同名接口或冲突主机路由会报错，不接管别的软件的接口/路由。
节点地址只安装已知成员的精确 `/32`、`/128` 路由，不把整个 `33.0.0.0/8` 导入 TUN。
数据只在相邻节点之间通过 Noise 加密一次；可信中继解密后按目标身份转发，再交给下一跳链路加密。中继可读取内层 IP 流量；没有独立端到端密钥或握手。

## 管理和诊断

另一个终端中，使用与 daemon 相同用户（root daemon 对应 sudo）：

```bash
nnlan --config ./state/nnlan.toml status
nnlan --config ./state/nnlan.toml peers
nnlan --config ./state/nnlan.toml routes
nnlan --config ./state/nnlan.toml trace B
nnlan --config ./state/nnlan.toml ping B --size 8192
nnlan --config ./state/nnlan.toml shutdown
```

终端交互默认输出整洁的人类可读 ASCII 表格与状态信息；加 `--json` 参数（如 `nnlan --json status`）可输出完整 JSON 供脚本解析。
目标可用完整公钥、前 8 位短公钥、唯一节点名或覆盖网络 IP。
`trace` 使用签名逐跳探测，展示实际响应节点，不把控制面的预测路径当成 trace。
`ping` 是逐跳加密的覆盖网络回显，结果标注 `hop_encrypted`；系统 `ping` 另用于验证 TUN 上的 ICMP IPv4/IPv6。
`routes` 支持发布、撤回、手动接受、显式替换与拒绝；操作与持久保护见
[Linux 子网路由](docs/linux-subnet-routing.md)。`plan` / `run --dry-run` 始终不操作网络，不代表当前 daemon 状态。

## Exit Node

出口主机先启用 IPv4/IPv6 forwarding，在已运行的 daemon 上操作：

```bash
# 出口节点 B 发布服务
nnlan --config ./state/nnlan.toml exit serve on
# 客户端选择 B；失联保持阻断，不自动直出或换出口
nnlan --config ./state/nnlan.toml exit use B
# 客户端显式停止使用出口
nnlan --config ./state/nnlan.toml exit off
# 客户端 daemon 已停止时，在原 network namespace 中恢复本地出口
nnlan --config ./state/nnlan.toml exit off --offline
```

操作用户需与 daemon 相同。双栈策略路由、DNS、严格 RPF 主机条件和恢复流程见
[Linux Exit Node](docs/linux-exit-node.md)。防直出不依赖进程或 TUN 持续存活；
开机前置 guard 与 networkd 验收见 [Linux 开机保护](docs/linux-boot-guard.md)。

## 无 TUN 运行

没有 TUN 权限时仍可运行真实控制面、多跳和加密回显：

```bash
nnlan --config ./state/nnlan.toml run --no-tun
```

这不是 TUN 的模拟实现；该模式明确不创建接口或系统路由。
本地管理 socket 与配置同名、后缀 `.sock`，权限 `0600`。
身份旁的 `.lock` 防止同身份重复启动；`.state.json` 持久化 IPv4 探测计数和签名序号预留区间。
每次启动签发新的 boot ID，远端验证后更新节点记录；邻接重新建立逐跳会话，无独立端到端会话需要恢复。

逐跳认证 MTU 探测和可变宽度 FEC 见 [路径 MTU](docs/path-mtu.md)。

## 实现边界

- 节点信息和已认证邻接共同签名，邻接同时构成可传递的成员引荐；只有双向确认的远端邻接参与选路。
- 发现不等于全连接。用户流量触发按需直连，失败时保留多跳；配置 peer 预留名额，入站/出站共享限制。
- 闲置自动直连可回收；单向配置入口和必要桥接保留，并发回收采用确定性保留图和跳数约束，见 [邻居生命周期](docs/neighbor-lifecycle.md)。
- 本地接口和邻居观察的候选会更新、替换和过期，不因反复换网永久填满地址名额；见 [候选生命周期](docs/candidate-lifecycle.md)。
- 地址池为 `33.0.0.0/8` 和 `fd33::/16`。IPv4 冲突由完整公钥决定胜者，败者持久化新 probe 并更新 TUN；IPv6 不随 probe 改变。
- 相邻链路已有 RS FEC、有限 RTX、反馈/BWE、共享保护预算与 Burst AIMD pacing；原始包不等封组。
  当前不是 CM256、WebRTC 或 WireGuard 线上格式的兼容实现。
- 多网络采用独立身份/配置/进程，推荐各自放在 network namespace 中，避免地址池与子网重叠影响系统路由。
- NAT/PMTU 扩展场景、性能与完整弱网对照、Exit Node 开机时序和动态底层地址更新仍在开发。

传输参数与机制见 [docs/transport-implementation.md](docs/transport-implementation.md)。

## 测试

```bash
nix develop --command make check
nix develop --command cargo test --locked --test daemon
nix develop --command make build
nix develop --command make e2e-subnet
nix develop --command make e2e-exit
nix develop --command make e2e-nat
nix develop --command make e2e-nat-matrix
nix develop --command make e2e-nat-topologies
nix develop --command make e2e-ipv6-discovery
nix develop --command make e2e-candidates
nix develop --command make e2e-interfaces
nix develop --command make scale  # 100 个独立进程；不启用 TUN
nix develop --command make scale-rekey  # 135 s，自然换钥后重验 PMTU / 加密回显 / trace
nix develop --command make scale-tun    # 100 个真实 TUN：碰撞合并、分区恢复、中继重启
nix develop --command make e2e-tun-routes # 内核路由 ACK、冲突不覆盖、限定接口删除
# 动态 MTU、ICMP 黑洞、双向不对称和 IPv6 底层
nix develop --command make e2e-pmtu
# 生产空闲计时器、名额复用、桥接保护及并发回收
nix develop --command make e2e-neighbors
nix develop --command python3 tests/e2e/overlay_netns.py \
  --collision --output target/e2e-overlay-collision.json
```

普通测试不需要 root。namespace 测试需要 root 或非交互 sudo；只创建唯一命名的隔离网络，
在其中部署四个 daemon、真实 TUN、双栈 ICMP、多跳 trace 和 netem 丢包，并清理本次创建的资源。
碰撞模式使用仓库中的公开测试身份，不使用真实部署身份。
子网测试另外使用六个 namespace 验证同前缀不同 LAN、双栈多跳 TCP、手动选择和进程崩溃保护。
出口测试使用五个 namespace 验证双栈多跳 TCP/DNS、严格 RPF 动态 ARP、出口切换、崩溃防直出及冷启动恢复。
NAT 测试先实测映射与过滤行为，再验证直连/中继、NAT 端口重绑定和引导节点离线。
扩展 81 组有序矩阵已验证 57 组直连、24 组中继；另有双层 NAT 与 hairpin 开关四组实际拓扑，
见 [Linux NAT 验收](docs/linux-nat-testing.md)。
候选测试连续执行 20 次真实 NAT 换端口，验证旧候选撤回、接口变更、不中断 daemon 的恢复与后续直连。
PMTU 测试覆盖真实链路缩小/恢复、ICMP 过滤、双向不同大小及 IPv6 底层，并核对没有 IP 分片。
邻居测试使用生产 60 秒空闲计时器，验证名额复用、单向业务保活、必要桥接和并发回收。
`make e2e` 运行九套基础内核测试；完整 NAT 矩阵、扩展拓扑与弱网矩阵另行运行。
这些结果不替代开机全时段保护或千进程吞吐验收。
