# TUN 批处理与精确发送唤醒

后续在此构建之上的包尺寸/FEC 填充优化见 [协议开销记录](protocol-overhead.md)；本文保留原阶段结果。

2026-09-22。本轮在 GGB3 单层逐跳加密版本上优化；不再修改密码层、协议格式或信任模型。
以下测试是同机 Linux network namespace 的数据面测量，不代表公网、多机器或千节点吞吐。

## 改动及边界

1. **减少每包分配和复制**：单片消息通过原有解析及两个重放窗口后直接交付，不创建重组表项；
   已存在的多片重组仍检查尺寸/类型一致性。发送源片直接编码借用的缓存，不先克隆 shard；
   固定三次发送的时间戳放在内联数组里，ACK 只匹配实际使用的元素；编码长度直接计算。
   路径查询借用现有缓存，不新增路由缓存。
2. **TUN GSO/GRO**：用 `tun-rs 2.8.11` 替换 `tun 0.8.14`。
   原来 UDP 侧已有的分段/聚合与这次 TUN 边界的优化是两回事。
   TUN 读出大包后分段，每个 IP 包仍独立经过路由、来源验证、Envelope、FEC/RTX 和 Noise。
   接收侧只把已经验证的 IP 包做 GRO；不将未认证数据、外层 UDP 或 FEC shard 直接注入内核。
   API 与实现参见 [固定版本文档](https://docs.rs/tun-rs/2.8.11/tun_rs/)，性能以本项目实测为准。
3. **发送唤醒**：保留 1 ms 维护时钟及 I/O 驱动的 250 μs 发送节拍。
   队列有待发数据且下一次机会不足 1 ms 时，通过一个 `CLOCK_MONOTONIC`、非阻塞 `timerfd`
   唤醒；队列空闲则撤销定时。不忙等、不新增工作线程，也不设置持续运行的高速周期定时器。
   时间预测只读现有 token；实际 tick/poll/charge 继续负责预算和扣款。
   更早的待触发时间不被后续 I/O 一直推迟。接口见
   [nix TimerFd](https://docs.rs/nix/0.31.3/nix/sys/timerfd/struct.TimerFd.html)。

为什么三者一起做：GRO 降低了包事件数量，原来依赖频繁 I/O 触发的发送循环不再足够频繁。
单加 GRO 的试跑 CPU 大幅下降，但吞吐反而下降；补上按需唤醒才利用起这些 CPU 余量。

### 有界资源和原有行为

- Engine 仍单所有者；TUN、UDP 每轮各最多 32 包或约 100 μs，然后回到事件选择。
- 单次 TUN 聚合最多 65535 字节、128 段；读取缓冲保留未处理尾部，跨调度轮继续，不丢弃尾段。
- 接收写入最多 32 包，每次事件结束即 flush；没有为凑批额外增加定时等待。
- GRO 需要目的 Vec 有足够 capacity，否则库会静默退为逐包写。32 个缓冲按使用惰性预留，
  默认 MTU 1280 共约 1.31 MB 容量，读缓冲约 230 KB；MTU 9000 时写缓冲最多约 2.10 MB。
  `--no-tun` 不分配这些缓冲。没有把吞吐收益当成无内存成本的收益。
- TCP offload 被内核拒绝时，关闭刚创建的 TUN 后重建 plain 模式，避免 virtio header 状态不一致；
  普通读写路径有真实内核专项验证。其他设备创建错误仍上报，不吞掉配置/权限错误。
- 无 own-unsafe，继续 `unsafe_code = forbid`；依赖内部负责 TUN ioctl、分段及校验和处理。
- FEC、有限 RTX、拥塞估计、ACK 额度、保护预算、发送次数/期限、2048 项缓存/队列上限均保持。
  GGB3 线上字节保持兼容；不是再次升级协议，也没有减掉认证或重放保护。
- TUN `txqueuelen=500` 未调大，但启用 GSO 后一个队列条目可能代表多个 IP 包，**等效字节积压
  并非不变**。发送准入满时仍可能丢弃从 TUN 读出的包；本轮不宣称已经解决过载背压。

## 测量与证据

原始报告、试跑二进制、perf 数据、构建日志在 `target/hotpath/`。
基线为本轮开始时的单层版本 `nnlan-before`，不是更旧的双层版本；
`before-source.tar.gz` 保留源代码快照。最终结果单独存于 `paired/`，试跑不混入中位数。

### 正式配对结果

Linux 6.18.46，Xeon Gold 5218 / 64 个逻辑 CPU；同机两端各一个邻居，未绑核，
双向 1000 Mbit/s 整形，BBR 单 TCP 流，MTU 1280，20 s 预热后测 15 s，50 ICMP/s。
三轮依次为 before→after、after→before、before→after；每次重建独立 namespace，
测量不与其他编译或网络工作负载重叠。所有轮次保留，不按好坏剔除。

- before：`06f4a5bd15a4d8736cf19ab4329e1f1dc98136d7684a584aa847908f37551b1c`
- after：`2a1462496d00b4fd96d7d81ff78652a8e1e64b0931290344123306e73bb141b2`
- 报告：`target/hotpath/paired/`；统计：`paired-summary.json`；顺序：`paired.sh`。

| IPv4 直连 | before Mbit/s | after Mbit/s | before p99 ms | after p99 ms |
|---|---:|---:|---:|---:|
| 第 1 轮 | 506.43 | 700.42 | 12.70 | 4.35 |
| 第 2 轮 | 524.29 | 700.28 | 13.60 | 4.32 |
| 第 3 轮 | 510.57 | 700.10 | 13.70 | 4.41 |
| 中位数 | **510.57** | **700.28** | **13.60** | **4.35** |

吞吐 +37.2%，满载 RTT p99 中位数下降 68.0%。daemon CPU 中位数 A/B 从
79.4% / 91.6% 变为 73.8% / 61.7%（100%=一个逻辑核，只计 daemon，不等于整机消耗）。
新版本三轮 TCP retransmits 均为 0、每轮 ICMP 750/750、TUN RX/TX drops 均为 0；
旧版第二轮出现 41 个发送 TUN drops、40 次 TCP 重传、ICMP 749/750，其余两轮 TCP 无重传。
所有直连轮次两端通用 `dropped` 计数均各增 1，所以这里不声称 daemon 总计数完全零丢弃。

新版本发送链路的线上预算记账约 985.8–986.3 Mbit/s，估计带宽已到 1 Gbit/s 配置上限，
与旧版约 718.9–744.1 Mbit/s 不同。这是软件按协议开销记账，不是物理 NIC 测量。
在 CPU 有余量时进一步逼近 1 Gbit/s 应先量化封装、校验片、分组标记及反馈的占用，
而不是继续假设去掉某次内存分配就能把应用 goodput 提到同样的数字。

补充单轮：IPv6 686.58 Mbit/s / p99 3.75 ms；IPv4 反向 700.24 Mbit/s / p99 3.74 ms。
两项均 TCP 无重传、ICMP 750/750、TUN drops 为 0；未作为三轮中位数或跨版本增幅。

### 20 ms 底层 RTT：收益和回退都保留

中间路由节点逐包施加故障并验证没有超大 skb；以下各一轮，不与直连混算。

| 条件 | before→after Mbit/s | before→after p99 ms | TCP 重传 | ICMP 回复 / 750 |
|---|---:|---:|---:|---:|
| 无注入丢包 | 413.01 → 517.65 | 48.50 → 65.60 | 64384 → 0 | 698 → 750 |
| 双向各 1% 随机丢包 | 425.85 → 510.50 | 51.90 → 71.00 | 80977 → 48 | 689 → 750 |

这里吞吐/交付改善，但 **p99 回退**，不是所有路径的延迟都降低。
RTT 分位数只统计收到的回复；旧版丢失更多请求，未回复请求没有按超时计入 p99，
所以尾延迟数字必须与交付率一起读，不能单凭这一分位数判断整体体验优劣。
无注入丢包时旧版发送/接收节点的 TUN TX drops 为 60226 / 1714，通用 daemon drops 为
4298 / 1；新版 TUN TX drops 为 0 / 0，daemon 为 1 / 1。
1% 丢包时旧版 TUN TX drops 为 66472 / 2432、daemon 为 14338 / 1；新版分别为 0 / 0、12 / 1。
这些通用计数不等同于单一业务丢包原因，且 GSO 前后的 TUN 条目不是同一种包单位。

因此下一步是有界发送准入/背压与高带宽延迟积下的排队控制：避免读取聚合包后才发现
发送缓存不足，同时避免简单扩队列将丢包换成长排队。现有数据尚不足以把 p99 回退全部
归因给某一个队列。千兆应用吞吐、广域网低尾延迟与百/千节点真实 TUN 的本轮验收仍未完成。


### 保留的试跑，包括负面结果

以下每项仅一次试跑，不用来代替最终配对实验。直连与 routed 不能横向当作同一条件：
后者有 20 ms 底层 RTT，关闭中间 veth 的聚合，按实际 IP 包施加故障并检查没有超大 skb。

| 阶段 | 直连 Mbit/s | 直连 p99 ms | 直连 CPU A/B（单核=100%） | routed 无注入丢包 Mbit/s |
|---|---:|---:|---:|---:|
| 减少分配 | 544.38 | 13.10 | 80.5 / 90.5 | 414.27 |
| TUN offload，但 GRO 缓冲不足 | 533.17 | 15.30 | 71.0 / 92.4 | 452.23 |
| 修正 GRO 缓冲 | 485.45 | 9.37 | 49.0 / 40.1 | 521.41 |
| 加按需 timerfd 唤醒 | 700.30 | 4.41 | 73.3 / 61.9 | 517.57 |

对应 `pilot-*`、`offload-*`、`gro-*`、`pacer-*` 报告与 `nnlan-*-pilot` 二进制。
GRO 试跑接收约 88.45 万个 IP 包只需约 6.28 万次 TUN 注入；这个比例随包型、流和调度变化。
它说明合并确实生效，不等于吞吐应同比增长。

最初在 devShell 外启动 pacer 测量，因缺少 `wg` 工具在测量前退出；日志保留为
`pacer-pilot.log`，进入 devShell 后的实际试跑在 `pacer-pilot-devshell.log`。
`profile*` 是优化前固定 daemon 的 perf 采样，非整个宿主的猜测归因：
密码、RS、分配、复制及内核 TUN/TCP 开销并存；不是删除加密/FEC的理由。

## 验证与复现

```bash
nix develop --command make check
nix develop --command make e2e-tun-io
nix develop --command make e2e-offload
nix develop --command python3 tests/e2e/tun_routes_netns.py
nix build

# 默认 FEC+RTX、单层 Noise；每次仅一个性能工作负载。
nix develop --command python3 tests/perf/compare.py \
  --binary target/release/nnlan --implementations nnlan --cases ipv4 --repeats 3
nix develop --command python3 tests/perf/compare_loss.py \
  --binary target/release/nnlan --implementations nnlan --loss-percent 1 --repeats 3
```

新增回归检查编码字节一致性、单片重放/乱序和重组元数据冲突、未使用时间戳、GRO 真正合并与
错误校验和不合并、128 段跨调度尾部、定时器空闲/取消及 token 预测不消费额度。
`offload_netns.py` 在双向 IPv4/IPv6 上发送 960 个 UDP_SEGMENT 应用数据报，检查原始边界和内容，
无应用重试；`compatibility_netns.py` 验证本轮前后 GGB3 构建的双向真实 TUN/echo/trace。

最终 `2a146249…` 构建通过：

- `cargo fmt --check`、Clippy `-D warnings`，170 项 Rust 普通测试、14 项 Python 测试；
- 单独运行两个忽略的真实内核专项：plain/offloaded TUN I/O 和 2000 条双栈路由 ACK/回收；
- Nix 包构建与包内 release 测试；日志 `target/hotpath/final-build.log`；
- 九套真实内核功能场景：多跳/碰撞、成员撤销、相同子网、Exit Node、PMTU、IPv6 发现、
  DHCP 策略、UDP GSO/GRO、前后 GGB3 互通；
- 32 组 FEC/RTX × 弱网矩阵，以及自然交叉换钥：持续 TCP 同时 ICMP **6000/6000**，
  并继续检查换钥后双栈数据；所有功能报告及退出码在 `target/hotpath/regression/`。

本轮未重跑百/千节点集群、NAT 全矩阵或冷启动/DHCP VM；历史结果仍按各自构建解释。
脚本只管理自己创建的 namespace、进程和临时文件；运行结束后没有遗留测试 namespace 或 daemon。
