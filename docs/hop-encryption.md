# GGB3：单层逐跳加密

2026-09-22 用户确认：所有组网成员和中继均在信任边界内，取消双层加密。

本文性能记录属于切换 GGB3 时的构建；后续同协议的数据面优化及新测量见
[TUN 批处理与发送唤醒](datapath-batching.md)，不覆盖本文的历史结果。

## 一套邻接会话

```text
发送：IP / echo → Envelope → 分片、FEC、pacer → 相邻 Noise AEAD → UDP
接收：UDP → AEAD、防重放 → FEC、重组 → Envelope
中继：读取 Envelope → 成员、跳数和路由校验 → 下一跳同一发送路径
目标：校验声明来源及 IP/子网发布者 → TUN / echo
```

独立端到端 Crypto、跨中继握手、密钥维护及待发队列已删除。
直连和中继使用同一数据格式，不添加可选的第二种加密模式。
每跳保留公钥固定、Noise XX 身份认证、ChaChaPoly、独立 nonce/重放窗口、
FEC、有限重传、反馈预算、拥塞控制与换钥；原始片、校验片、ACK/NACK 均在线路加密内。

源身份由上一跳可信成员转述，不是独立端到端密码学证明。
中继可读取、修改尚未由应用自身加密的载荷；HTTPS/SSH 等应用层保护不受影响。
本地封禁仍覆盖声明源、实际邻接和目的路径，但不声称抵抗可信中继冒用其他有效成员。
签名节点记录及主动 trace 的签名保持不变。relay 不自动启用 Subnet Router 或 Exit Node。

## 协议与升级

- 线格式：`GGB3`；Noise prologue：`ggbond.noise.v3`；仅接受 scope=0。
- Envelope 仅接受 DATA、TRACE、TRACE_REPLY；旧端到端握手类型不再转发。
- GGB1/GGB2 不建连、不自动降级或试探性解密；互联节点统一升级。
- `identity.key`、公钥、VIP 地址派生、配置格式及持久化状态保持不变。
- `status` 标注 `wire_protocol="GGB3"`、`encryption="hop-by-hop"`。
- 远端 `ping` 成功返回 `hop_encrypted=true`，删除旧 `end_to_end_encrypted` 字段。
  回显仍校验目标身份、随机请求编号与载荷哈希，但可信中继处于信任边界内。

## 封装与前一轮 I/O 优化

保留上一轮已实现的有界收发批处理（每次至多 32 包 / 包间检查 100 µs）、UDP GSO/GRO。
GRO 仅改变本机内核收包方式：逐段独立认证；调度让出时保留聚合尾部。
不支持 GRO 的内核继续逐包接收；小 PMTU 的发送仍禁用 GSO。
这些 I/O 优化属于上一轮改动，不将其收益重复归因于取消端到端层。

TUN MTU 仍为 1280，队列长度未调大。已知节点的 `/32`、`/128` 主机路由广告 TCP MSS，
减少常规 TCP 满包的逐跳分片；预算随单层封装调整：

```text
1232 UDP payload − 40 Noise header/tag − 19 source header − 23 fragment header
− 66 Envelope header − 1 IP discriminator = 1083 bytes inner IP
IPv4 advertised MSS = 1043；IPv6 = 1023
```

这里是本机 TCP 接收 MSS，不修改 IP MTU，也不丢弃大 UDP 包；低 PMTU 和大包继续分片。
此 MSS 优化仅针对节点主机路由，不声称已经优化所有转发 LAN/出口 TCP 的 MSS。
旧双层实现同预算还需内层 Noise 40 字节，对应 MSS 1003/983。

## 验证

当前 release SHA-256：
`06f4a5bd15a4d8736cf19ab4329e1f1dc98136d7684a584aa847908f37551b1c`，
存档 `target/hop-only/after`。前一轮 GGB2 I/O 优化候选为
`abb21dcfb0ddf9ea91d9f3c8c0c6a0b5ec65f2ccd2442715e75e997048395fe4`，
存档 `target/hop-only/before`，源码快照 `target/hop-only/before-source.tar.gz`。

- fmt、严格 clippy、162 项 Rust 普通测试和 release 构建通过；
  另在隔离 namespace 通过 2000 个双栈主机路由 ACK / 后台 worker / MSS 内核专项。
  日志：`target/hop-only/build-v2.log`。
- 新增真实 Noise + Link/FEC 编解码中继测试：仅建立 A↔C、C↔B 会话，
  C 解密获得原始载荷，下一跳重新加密；篡改及同跳重放被拒绝，A/B 无端到端会话。
- 线格式单测拒绝 GGB1/GGB2、所有非零 scope 和 Envelope 内旧握手类型。
  实际源帧边界测试覆盖 MSS 精确适配以及多 1 字节时继续分片。
- 5 项性能工具、9 项规模工具 Python 测试通过。
- 七套真实 Linux 内核回归通过：四节点多跳/主动 trace/IPv4 碰撞、成员撤销与替代路径、
  同前缀子网发布者切换、双栈 Exit Node 与 DNS/防直出、PMTU 黑洞与恢复、IPv6 发现、DHCP 策略。
  原始记录：`target/hop-only/regression/{overlay,membership,subnet,exit,pmtu,ipv6_discovery,dhcp_policy}.json`。
- `tests/e2e/version_netns.py` 实际启动 GGB2/GGB3，双方持续拒绝对方握手、没有邻接或明文回退；
  仍能读取相同身份及地址候选。记录：`target/hop-only/regression/version.json`。
- 四种 FEC/RTX 策略 × 八种内核故障共 32 组双栈弱网场景通过；
  默认策略在该 seed 的 5% 随机丢包组收到 IPv4/IPv6 各 400/400 个应用包，接收端 FEC 修复 39 片。
  限速等过载组不要求零损失，报告保留实际交付、资源边界与恢复情况。
  记录：`target/hop-only/regression/weaknet.json`。

首轮换钥和 A/B 测量在 PID 查找阶段退出：夹具要求进程名以 `nnlan` 开头，
存档名 `before`/`after` 不满足该约定，尚未进入测量。失败记录保留于
`regression/rekey-fixture-first.*`、`performance-fixture-first/`；
后续使用相同字节的 `target/hop-only/nnlan-before`、`nnlan-after`，不放宽任何断言。

### 自然交叉换钥

`target/hop-only/regression/rekey.json` 通过：只给握手包增加 100 ms 延迟，
自然 120 s 轮换形成双向不同发送世代，持续 TCP/ICMP 负载覆盖真实换钥，未重启 daemon。
连续 6000/6000 个 ICMP 回复，RTT p50/p99/p99.9 为 8.04/14.5/19.2 ms，
换钥后 IPv4 / IPv6 / 反向 IPv4 接收吞吐分别为 516.21 / 500.04 / 513.67 Mbit/s，
三个方向各 500/500 个探测回复，采样 PMTU 始终 1232。
这是独立换钥回归、没有千兆整形，不用它替代下面的配对性能测试。

历史 GGB2 性能和规模报告仍按原构建解释，不因变更协议而视为 GGB3 已通过规模或开机验收。

## 千兆整形下的前后对照

同机 Xeon Gold 5218、Linux 6.18.46，两个真实 TUN/daemon、MTU 1280、BBR 单 TCP 流；
两端 WAN 出口均整形 1000 Mbit/s，每轮新建 namespace，预热 20 s、测量 15 s，
同步 50 ICMP/s。按 before→after、after→before、before→after 轮换，未并发编译或运行其他本项目负载。
原始数据：`target/hop-only/performance/{before,after}-{0,1,2}.json`。

| IPv4 直连，三轮 | 双层 GGB2（已有 I/O 优化） | 单层 GGB3 |
|---|---:|---:|
| 接收 goodput（Mbit/s） | 443.30 / 432.58 / 445.96 | 520.03 / 524.64 / 508.24 |
| goodput 中位数 | **443.30** | **520.03（+17.3%）** |
| 各轮满载 RTT p99（ms） | 11.2 / 15.4 / 15.0 | 13.4 / 14.0 / 14.5 |
| p99 中位数（ms） | 15.0 | 14.0 |
| ICMP 回复 | 每轮 750/750 | 每轮 750/750 |
| TCP 重传 | 0 / 59 / 0 | 0 / 0 / 58 |
| 发送端 TUN 丢包 | 0 / 59 / 0 | 0 / 0 / 58 |

本次对照只涵盖取消独立端到端层、相应 MSS 预算调整及协议切换。
此前约 287→447 Mbit/s 的 I/O 批处理/GRO 收益属于上一轮，不合并归因。
两版满载都有出现本机 TUN 丢包的轮次，未把有重传的轮次删掉；三轮尾延迟不能外推长期 SLA。

补充单轮 GGB3（不是重复测量结论）：

| 场景 | 接收 Mbit/s | RTT p99 ms | ICMP 回复 | TCP 重传 | TUN 丢包 A / B |
|---|---:|---:|---:|---:|---:|
| 直连 IPv6 | 493.72 | 13.8 | 750/750 | 0 | 0 / 0 |
| 直连 IPv4 反向 | 518.13 | 12.1 | 750/750 | 0 | 105 / 0 |
| 底层路由器、20 ms RTT、无注入丢包 | 404.23 | 45.2 | 711/750 | 58088 | 56442 / 2135 |
| 同拓扑、双向 1% 丢包 | 439.25 | 47.6 | 697/750 | 78529 | 58751 / 2215 |

后两项是底层路由器，不是覆盖层中继。夹具关闭边界处的分段/聚合，并核验无超过 MTU 的聚合包
穿过故障边界；FEC、RTX、加密、队列和保护预算保持默认。单轮 1% 丢包结果高于无丢包对照，
不足以得出“丢包提高吞吐”的结论。已有 TUN 排队/调度瓶颈在高时延满载下仍明显：
损失发生在用户态接管和 FEC 保护之前，取消双层并没有解决它。
当前吞吐仍低于历史同机 WireGuard 约 900 Mbit/s；本轮未重测 WireGuard，也未完成千兆性能目标。

复现：

```bash
# 两个存档的进程名保持 nnlan 前缀，供现有性能夹具识别 PID。
nix develop --command python3 tests/e2e/version_netns.py \
  --old-binary target/hop-only/nnlan-before --binary target/hop-only/nnlan-after
nix develop --command python3 tests/perf/crossed_rekey.py \
  --binary target/hop-only/nnlan-after --transition --wire-version 3
nix develop --command python3 tests/perf/compare.py \
  --binary target/hop-only/nnlan-after --implementations nnlan --cases ipv4 --repeats 3
# 精确复现本轮交错顺序：target/hop-only/performance.sh
```

源码、报告和二进制摘要索引：`target/hop-only/audit.json`。
