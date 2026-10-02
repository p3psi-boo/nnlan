# 同机数据面对照：nnlan / WireGuard

本页保留历史构建的测量结果；当前 GGB3 已取消双层加密，
变更与新构建验证见 [单层逐跳加密](hop-encryption.md)。

## 方法

本轮不改动 nnlan 数据面，release 仍为
`175837ff851aed5362b5a7b49ce779abae4fbf002dbaaaa95f2aa27568a2fa45`。
新增 `tests/perf/compare.py`、`compare_loss.py` 和统计/故障边界单测；
devShell 增加 WireGuard 配置工具、wireguard-go、ethtool，不加入运行时依赖。

- Xeon Gold 5218 @ 2.30 GHz，Linux 6.18.46，64 个逻辑 CPU；不绑核、不独占主机。
- 双端 WAN TBF 1000 Mbit/s，burst 625000 字节、latency 20 ms；WAN MTU 1500。
- 三种隧道统一 MTU 1280；WireGuard 未使用更大 MTU 优化其数字。
- 单 TCP 流，显式 `iperf3 -C bbr`，同时每秒 50 个 ICMP。
- 每项独立创建 namespace、进程、密钥与会话；预热 20 s，测量 15 s，三轮轮换实现顺序。
  不与其他本项目压测或编译并发；不复用上一轮 nnlan 已升速的会话。
- 所有实现在同一资源环境使用各自默认工作线程数，不等价于强制单核比较。
- nnlan 保留默认 FEC、有限 RTX、端到端与逐跳加密；WireGuard 无上述 FEC/有限 RTX 层。
  这是成熟数据面的参照，不是同功能或同报文格式比较；独立 wireguard-go 也不是完整 Tailscale 产品。
- 记录全部 iperf JSON、ping 原始回复、进程 CPU、qdisc、接口/offload 状态、nnlan 状态、
  WireGuard 握手/收发计数，以及工具/二进制/夹具 SHA。
- 用户态进程 CPU 以一个逻辑核为 100%；内核 WireGuard 的此项为 `null`，不是零成本。
  全机 CPU 增量仅作环境信息，不归因给某个实现。
- 每项清理 namespace、进程及其唯一命名的 UAPI socket 后才保存成功结果；最后才写 `complete=true`。
  WireGuard 私钥仅在临时目录的 0600 文件中，不进入参数、日志或报告。

工具来自现有 flake.lock 固定的 nixpkgs：wireguard-go `0.0.20250522`，
wireguard-tools `1.0.20260223`，iperf3 `3.21`，ethtool `7.1`；内核 WireGuard 随上述内核。
用户态前台启动和配置方式依据 [wireguard-go](https://git.zx2c4.com/wireguard-go/about/)
与 [wg 手册](https://man7.org/linux/man-pages/man8/wg.8.html)。

## 干净直连：IPv4 三轮

```bash
nix develop --command make perf-compare
# 对应命令：
nix develop --command python3 tests/perf/compare.py --cases ipv4 \
  --output target/perf-comparison-ipv4.json
# 完整方向矩阵入口（本次正式三轮仅测 IPv4，IPv6/反向已做夹具 smoke）：
nix develop --command python3 tests/perf/compare.py \
  --cases ipv4 ipv6 ipv4_reverse --output target/perf-comparison-all.json
```

| 实现 | 三轮 goodput（Mbit/s） | 中位数 | 各轮 RTT p99 中位数（ms） | 进程 CPU A / B 中位数 |
|---|---|---:|---:|---:|
| Underlay | 956.64 / 956.68 / 956.64 | 956.64 | 1.27 | 不归因 |
| nnlan | 287.99 / 286.77 / 283.83 | 286.77 | 9.49 | 76.42% / 72.23% |
| WireGuard 内核版 | 901.73 / 902.00 / 902.07 | 902.00 | 1.18 | 不归因 |
| wireguard-go | 898.83 / 898.95 / 898.91 | 898.91 | 2.31 | 61.29% / 72.33% |

全部 12 项各为 750/750 ICMP 回复，TCP 重传为 0。
**nnlan 只有 wireguard-go 的约 31.9% goodput；上一轮约 60% 的提升并未消除明显差距。**
这里已有同机证据，不再以外部网站的 10 Gbit/s 数字代替本机对照。

原始数据、汇总及 provenance：`target/perf-comparison-ipv4.json`；
日志：`target/perf-comparison-ipv4.log`。
`target/perf-comparison-wg-smoke.json` 的 IPv6/反向每项仅 3 s，是夹具功能检查，不当作正式性能结果。

### 两类成本应分开优化

同一测量窗口，以发送端 qdisc 字节计数与应用接收 goodput 相比：

| 实现 | 计入 qdisc 的正向字节 / 应用接收字节，中位数 |
|---|---:|
| Underlay | 1.044 |
| nnlan | 1.618 |
| WireGuard 内核版 | 1.101 |
| wireguard-go | 1.101 |

这是内核 qdisc 计量，不是物理链路逐帧抓包。nnlan 测量前后控制器均为 1 Gbit/s，
并非冷启动限速；发送端正向 qdisc 约 459–466 Mbit/s，还未耗尽链路预算。

由此有两个独立问题：

1. **每个业务字节需要的底层字节较多**。分片、封装、FEC/反馈共同构成成本，
   1.618 包含这些因素，需分别量化。若保持此次包型与冗余比例，单按账面带宽估算，
   `1000 / 1.618 ≈ 618 Mbit/s`；这是忽略 CPU/调度的量级估算，不是已测速度或严格上界。
2. **仍有明显的处理与调度成本**。实际 287 Mbit/s 连上述量级也未接近。
   先前采样指出发送、TUN 写入、加密与分配成本；FEC 并非已证实的唯一瓶颈，
   也没有依据换语言。下一轮应优先验证 TUN/UDP 整条路径批处理与封装效率，而非仅再微调发送端。

## 弱网比较方法

直接对 GSO 聚合 skb 按概率丢弃会使“1% 丢包”变成不同大小的成组丢包。
弱网套件另建 `A — Router — B` 三个隔离 namespace；只关闭这四个 veth 端口的
TSO/GSO/GRO 与 UDP 分段/转发合并，TUN 的 offload 保留各自实现的默认值。
在路由器施加双向每方向 10 ms 延迟，以及 0% 或 1% 随机丢包。
每轮用相同 seed 起点、不同轮次更换 seed；不同实现消耗的包数不同，不声称丢了同一批业务包。

路由器 forward 链额外统计 `meta length > 1500`：一旦出现聚合大包，该项比较立即失败，
而不是继续发布一个粒度不同的“同丢包率”数字。此检查覆盖预热和正式测量。
netem 用法见 [tc-netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html)，
GSO 的分段边界见 [Linux 文档](https://docs.kernel.org/networking/segmentation-offloads.html)。

```bash
# 两者同样有 20 ms 基础 RTT，用 routed clean 而非直连结果作对照：
nix develop --command python3 tests/perf/compare_loss.py --loss-percent 0 \
  --output target/perf-comparison-routed-clean.json
nix develop --command python3 tests/perf/compare_loss.py --loss-percent 1 \
  --output target/perf-comparison-routed-loss1.json
```

弱网与这个三节点无丢包控制组配对比较，不与上面的直连表混算。

### 20 ms 基础 RTT：三轮结果

| 实现 | 0% 注入丢包 goodput 中位数 | 1% 注入丢包 goodput 中位数 | 0% / 1% RTT p99 中位数 |
|---|---:|---:|---:|
| Underlay | 931.79 Mbit/s | 916.15 Mbit/s | 21.6 / 21.6 ms |
| nnlan | 225.53 Mbit/s | 228.79 Mbit/s | 45.9 / 47.0 ms |
| WireGuard 内核版 | 884.35 Mbit/s | 868.17 Mbit/s | 21.4 / 21.3 ms |
| wireguard-go | 883.97 Mbit/s | 864.69 Mbit/s | 44.9 / 44.9 ms |

24 项测试的路由器聚合大包计数均为 0；1% 组每项都实际发生双向 netem 丢包。
TCP 使用 BBR，这不是所有拥塞算法或网络环境的结论。
两个报告均 `complete=true`：`target/perf-comparison-routed-clean.json`、
`target/perf-comparison-routed-loss1.json`，对应 `.log` 保留每轮输出。

0% 是**未注入底层丢包**，不是系统各层都没有丢包：

- nnlan 在三轮 15 s 测量中，发送端 TUN TX dropped 分别增加 **13314 / 12562 / 12446**；
  同时 TCP 重传 **13135 / 12548 / 12191**，ICMP 回复 **732 / 736 / 739**，每轮发送 750 个。
  nnlan 的 WAN TBF 和路由器 netem 丢包增量均为 0，逐跳重传与链路队列丢弃增量也为 0。
- 1% 组 nnlan 的发送端 TUN 丢包增量进一步为 **17908 / 17187 / 18377**；
  TCP 重传 **18004 / 17281 / 18670**，ICMP 回复 **716 / 717 / 724**。
  接收端链路 FEC 确实恢复了 **6902 / 6809 / 6671** 个源符号，发送端链路 RTX 为
  **7007 / 7935 / 7630**；这些链路符号计数和 TCP 段数不是同一单位。
- wireguard-go 的无注入丢包组也有 TCP 重传 **7884 / 8394 / 7504**，但 TUN 丢包为 0；
  它的发送端 TBF 丢弃计数分别增加 **303 / 488 / 259**，负载尾延迟也上升。
  TBF 计数包含实现相关的 skb 聚合粒度，不与 TCP 重传段数一一对应。
- Underlay 与内核 WireGuard 的无注入丢包组没有 TCP 重传，且每轮 ICMP 为 750/750。

这将 nnlan 的问题进一步定位到 **内核向用户态送包的 TUN 出口**：
相当一部分包在进入 nnlan 加密和 FEC 之前已经丢失。这些未读入的包处于 FEC 覆盖范围之外。
1% 组吞吐略高于 0% 组不视作收益；队列、TCP 和保护层共同反馈，当前本地丢包已干扰弱网收益评估。
先修复本地收包路径，再评估保护层在不同丢包模型下的净收益。

### TUN 队列单变量诊断

使用同样的三 namespace、20 ms 基础 RTT、0% 注入丢包、20 s 预热 / 15 s 测量、
同一 release，仅改变两个夹具 TUN 的 `txqueuelen`。每档**单次诊断**，不是三轮正式验收。
额外保存 TUN qdisc、WAN 统计以及 namespace 的 TCP/SNMP 计数。

```bash
nix develop --command python3 tests/perf/diagnose_tun.py \
  --output target/perf-tun-default.json
nix develop --command python3 tests/perf/diagnose_tun.py --tun-queue 2048 \
  --output target/perf-tun-2048.json
```

| TUN 队列长度 | goodput | RTT p99 | 发送 TUN 丢包增量 | TCP 重传 | ICMP 回复 |
|---|---:|---:|---:|---:|---:|
| 默认 500 | 227.69 Mbit/s | 46.3 ms | 15092 | 14839 | 730/750 |
| 2048 | 215.65 Mbit/s | 64.4 ms | 0 | 0 | 750/750 |

两档的 TUN fq_codel 丢包增量均为 0；默认档丢包记录在 TUN 接口 TX dropped。
扩大队列消除了本次本地丢包，却没有提高吞吐，并增加负载延迟。这支持存在读入/处理瓶颈，
而不是一个简单的“调大缓存即可提速”问题。单次诊断不用于推断普遍的下降百分比。
**生产队列长度保持不变，未把此实验当作性能修复。**

## 下一处优化与验收边界

- 优先验证有界 TUN / UDP 批处理，减少每包进出事件循环与系统调用的成本；
  TUN offload 路径需完整处理分段、校验和、IPv4/IPv6 和回退，不只开启一个标志。
- 批处理同时约束时长和数量，保留控制消息、维护、换钥与双向转发的调度机会；
  不引入无界队列，也不靠关闭 FEC/RTX 或加密提高数字。
- 分别统计应用 goodput、底层字节、TUN/UDP/链路队列丢包、CPU 和负载延迟。
  先重跑同机干净直连与 20 ms 无丢包控制，再跑配对弱网；修复需同时观察吞吐和 p99。
- 本轮完成 36 项三轮正式对照、6 项 WireGuard 方向 smoke、4 项弱网粒度 smoke、
  两档队列诊断；新增 5 项性能工具单测与既有 9 项规模工具单测通过，`cargo fmt --check` 通过。
  Rust 源码和 release 未修改；本轮未重跑 Rust/内核功能全矩阵及百/千节点验收。

原始数据位于 `target/`，本轮校验清单位于 `target/perf-comparison-audit.json`。
历史失败 smoke 报告也保留，正式结果未覆盖失败样本。
