# 实现状态

完整要求以 [project-decisions.md](project-decisions.md) 为准。本文件区分已运行的功能和剩余交付，
不把某一项测试通过当作整个 MVP 完成。

## 2026-09-26：满载流队列隔离

当前 release `5dbd059166d3d61dc5396e9cfbe589f6340282e8a4d82a1ebfa0addb9491b722`。
本机 TUN 快速读取与发包准入分开，采用 256 个哈希桶的新/旧流字节 DRR；
共享 32 MiB/32768 包上限、500 ms 准入前绝对期限，满时从最大桶丢弃，重试重新校验策略/路径。
不新增依赖、线程或协议字段。移除了试验中吞吐代价偏大的 CoDel/ECN 逻辑；
既有源片 250 ms 未发期限、FEC/RTX、加密、缓存额度和带宽预算保持。

同机千兆整形新旧三轮中位数：100 ms RTT 满载 p99 **304→114 ms**，
200 ms **520→215 ms**；两组分别全部收到 2250/2250 探测回复。
吞吐代价明确：**542.98→506.24 / 494.05→461.09 Mbit/s**，约下降 6.8% / 6.7%。
直连约 763 Mbit/s；最终性能矩阵中 TUN 丢包、ingress 超限/过期均为零。
大流自身仍有数百毫秒驻留，不把短流隔离说成所有流的零排队保证。

195 Rust、16 Python、8 套网络回归通过（过载/撤销、GSO、PMTU、多跳碰撞、成员、旧版互通、
8 弱网、自然换钥 6000/6000 ICMP）。22 次最终性能运行有冻结构建与原始报告；
原始诊断、负面候选、额外内存边界及未重跑项见 [排队记录](queueing.md)。不是整个 MVP 完成。

## 2026-09-26：自适应待确认容量与 TUN 准入背压

该阶段 release `18dec2ed397503df0e8071c4d46dfe6b5e72e93ba33017650ad3dad72cfae137`。
按速率/RTT 调整 2048–16384 项源片缓存，全部邻居/密钥世代共用 32768 项额度；
未发硬队列仍 2048。TUN 使用软工作量水位和有限读批次暂存，ACK/pacer 持续运行，
空间释放后重新检查当前策略/路径。修复了最初 20 ms 批次期限误丢正常冷启动 GSO 尾段的问题。

同机千兆整形单轮：100 ms RTT **176.23→552.62 Mbit/s**，200 ms **80.02→496.38 Mbit/s**；
最终两者都是 750/750 ICMP、TCP RTX0。但成功包 p99 **101→309 / 201→512 ms**，满载尾延迟仍未解决。
直连吞吐基本保持 763.5 Mbit/s；20 ms 该轮吞吐下降约 2.1%，不声称全面改善。

189 Rust、16 Python、8 项网络回归通过（含默认 FEC+RTX 的 8 组弱网、自然换钥 6000/6000 ICMP）；
新的过载/撤销验收通过，原始 GSO 回归连续三轮及最终回归通过。范围、失败候选、
Underlay/WireGuard 高 RTT 参考及未重跑项见 [背压记录](backpressure.md)。不是整个低延迟目标或 MVP 完成。

## 2026-09-24：高 RTT 诊断与缓存扫描优化（容量问题未完成）

该阶段 release `f4d823f71660976dc31308f623f0353ffc00839d582633d8e839db8a289143b1`。
源片按创建顺序有序：最老源片尚未到 RTO/寿命时跳过全表扫描；原 1 ms 维护、2 ms 封组/ACK、
2048 项缓存/队列和重传策略保持。新增缓存扫描/排队统计，以及可选负载采样工具。

同机千兆整形、RTT 20 ms，三轮吞吐中位数 **597.48→624.16 Mbit/s（+4.46%）**；
p99 **63.4→66.1 ms**，没有降低尾延迟。100 ms 单轮 **173.24→174.36 Mbit/s**，
发送端 CPU **25.09%→20.54%**；200 ms 仍约 81 Mbit/s。高 RTT 缓存准入丢弃尚未解决。

试验性扩大待确认缓存到 8192 项可在 100 ms 跑到 539 Mbit/s、500/500 ICMP、TCP 重传 0，
但成功回复 p99 为 318 ms。原版有请求丢失，较低的成功回复 p99 并不等于总体体验更好；
扩容仍需结合深队列治理，暂未启用。缩短 TUN 队列/聚合的试验因交付回退未采用。
180 项 Rust、16 项 Python 与 release 构建通过；网络回归和全部原始结果见
[高 RTT 记录](high-rtt.md)。本轮不是高 RTT 完整修复，也不是整体 MVP 完成。

## 2026-09-23：紧凑直连/单片/ACK 与小包瓶颈

该阶段 release `beefe5806dab7505cadfbfd6cd599dabec5b92654b606d655abb4732651cfdf9`。
GGB3 按认证密钥世代显式交换能力版本 2，旧节点保留旧格式。直连 DATA 省略 66 字节身份头，
单片源帧省略 12 字节可推导字段，32 条 ACK 从 802 降到 378 字节；时间戳精度与逐包反馈保留。
接收统一还原到原 Envelope/Fragment/Ack，多跳和 trace 保留完整身份，FEC/RTX、队列与预算未放宽。

千兆整形同机配对三轮，IPv4 TCP goodput 中位数 **723.78→763.37 Mbit/s（+5.47%）**；
满载 p99 **3.94→4.12 ms**，不是全面降延迟。300 B/100 Mbit/s UDP 从 85.31 Mbit/s、14.69% 丢包
变为约 100 Mbit/s、零丢包：反向 ACK 过大导致 8.1 Mbit/s 初始 pacer 耗尽、源片缓存填满，
本轮压缩反馈而非提高限速/扩大缓存。300 B/200 Mbit/s 仍丢 18.66%，高 RTT/1% 丢包样本的
尾延迟也变差；更高 PPS、排队/背压和纯 UDP 跨换钥仍是后续工作。

179 项 Rust、14 项 Python、两个真实内核专项、Nix 构建、九套功能、32 组弱网和自然换钥 6000/6000 ICMP 通过。
百/千节点与开机 VM 未重跑。原始数据、能力协商、冷启动/换钥范围和负面结果见
[紧凑数据记录](compact-data.md)。以下保留此前构建的历史结果。

## 2026-09-22：大包探测与按组缩短 FEC 填充

该阶段 release `80e5d6c6f0e9e23e413e15ef65b1718c154d8b6b78ab43027a148bc2b8c828a4`。
保留 GGB3 字段与单层认证加密，PMTU 先验证旧版 1232，再探测至 1452；MSS 不超过实际 TUN。
FEC parity 只补齐到本组最长源片（不低于旧解码器要求的 489），K/M 策略、RTX 与预算不变。
未新增身份映射、线程或用户配置；条目数上限未变，但最大条目字节容量增加。

千兆整形同机配对三轮，IPv4 TCP goodput 中位数 **700.29→723.75 Mbit/s（+3.35%）**；
满载 RTT p99 **3.92→3.84 ms**，单轮有反向波动，不声称显著降低尾延迟。
固定 100 Mbit/s 的 1200 B UDP 零丢包，A 端协议记账字节/接收应用字节降低 **14.93%**；
300 B/50 Mbit/s 零丢包时降低 **12.28%**。300 B/100 Mbit/s 旧/新仍各丢约 14.7%，
该小包交付瓶颈未解决。20 ms RTT 满载排队也仍在，不能由直连好结果外推。

173 项 Rust 普通测试、14 项 Python 测试、两个真实内核专项、Nix 构建、九套功能场景、32 组弱网、
自然换钥 6000/6000 ICMP 通过；旧节点接收新版本短 parity 的确定性 8 包恢复通过。
百/千节点和开机 VM 未重跑。下一项格式优化应是紧凑单片头/直连复用会话身份，尚未实现。
完整条件、失败夹具和原始材料见 [协议开销优化记录](protocol-overhead.md)。

以下保留此前构建的历史结果。

## 2026-09-22：TUN 批处理与按需发送唤醒

在 GGB3 单层版本上减少源片复制、单片重组和路径克隆，接入有界 TUN GSO/GRO，
用一个按需 timerfd 补齐聚合后减少的发送唤醒；不新增数据面线程、不扩大协议队列，
认证、重放窗口、FEC、有限 RTX 与预算保持。GGB3 前后构建已验证双向互通。

该阶段 release `2a1462496d00b4fd96d7d81ff78652a8e1e64b0931290344123306e73bb141b2`：
千兆整形同机配对三轮，IPv4 goodput 中位数 **510.57→700.28 Mbit/s（+37.2%）**，
满载 RTT p99 中位数 **13.60→4.35 ms**；单轮 IPv6 686.58、反向 IPv4 700.24 Mbit/s。
20 ms 底层 RTT 单轮无注入丢包时吞吐 413.01→517.65 Mbit/s、ICMP 698→750/750，
但 p99 **48.5→65.6 ms**，仍需改进排队/背压。TUN 条目聚合后等效字节积压可能增大，
没有把清除某次 TUN 丢包当作所有过载问题已解决。

170 项 Rust 普通测试、14 项 Python 测试、两个内核专项、Nix 构建、九套内核功能场景、
32 组弱网和自然换钥持续 6000/6000 ICMP 通过；百/千节点和开机 VM 本轮未重跑。
完整条件、CPU、1% 丢包、负面试跑、二进制和原始报告见 [批处理性能记录](datapath-batching.md)。
下面是此前阶段按原构建保留的历史记录。

## 2026-09-22：取消双层加密，切换 GGB3

按已确认的全成员/中继信任模型，删除端到端 Noise 握手、密钥表和待发队列；
只保留相邻链路的一层认证加密，直连与多跳共用 Envelope。中继可读取内层 IP 载荷，
声明来源由可信邻接背书；签名记录、trace、公钥固定、防重放、FEC/RTX 与成员策略保留。
协议升级为 GGB3，旧版被拒绝，身份/地址/配置保持不变，所有互联节点统一升级。

保留前一轮有界 I/O 批处理和 GRO/GSO，主机路由 MSS 随移除的 40 字节内层封装调整，
没有扩大 TUN 队列、关闭 FEC 或去掉逐跳加密。验证记录见 [单层加密说明](hop-encryption.md)。
当前 release `06f4a5bd15a4d8736cf19ab4329e1f1dc98136d7684a584aa847908f37551b1c`：
162 项 Rust 普通测试、14 项 Python 工具测试、内核路由专项、七套真实内核功能回归、
GGB2/GGB3 实际拒绝混连、32 组弱网和自然换钥连续 6000 个 ICMP 回复通过。
同机千兆整形配对三轮，IPv4 goodput 中位数由已有 I/O 优化的双层版本 443.30 提至
520.03 Mbit/s（+17.3%），满载 RTT p99 中位数 15.0→14.0 ms。
仍有本机 TUN 丢包；20 ms RTT 满载单轮更明显，千兆性能目标尚未完成。
本轮不把旧百/千节点或开机 VM 结果视为当前协议重新验收。

以下性能与规模记录均按其标注的原构建解释，不自动转为当前构建的验收。

## 2026-09-22：同机 WireGuard 对照与 TUN 瓶颈定位

本轮新增对照工具，Rust 数据面/release 未修改。相同主机、MTU 1280、BBR 单 TCP 流、
千兆整形，三轮 IPv4 goodput 中位数：Underlay 956.64、内核 WireGuard 902.00、
wireguard-go 898.91、nnlan 286.77 Mbit/s；nnlan 仍明显偏低。

另完成 20 ms RTT 的无注入丢包与双向 1% 丢包配对测试，确保 netem 接收实际分段后的包。
无注入丢包时，nnlan 每轮 15 s 的发送 TUN 丢包约 1.25 万个，发生在 FEC 覆盖之前。
单次扩大 TUN 队列实验虽清除了丢包，却未提高吞吐、p99 反而上升，因此未合入生产设置。
下一处目标是有界 TUN/UDP 批处理与调度成本；完整条件、负面结果和复现入口见
[同机数据面对照](performance-comparison.md)。5 项性能工具单测、9 项规模工具单测和格式检查通过。

## 2026-09-22：数据面性能优化

release `175837ff851aed5362b5a7b49ce779abae4fbf002dbaaaa95f2aa27568a2fa45`：
加速既有 ChaChaPoly 实现、减少缓冲分配、已验证方向的有界 UDP GSO、I/O 驱动发送；
加密/认证、FEC、有限 RTX、协议、队列和带宽限制不变，小 MTU 路径逐包发送。
同机千兆整形三轮，IPv4 中位数从 178.43 提至 284.72 Mbit/s（+59.6%），
负载 RTT p99 中位数从 14.90 降至 9.53 ms；实测 Underlay 956.59 Mbit/s。

158 项 Rust 普通测试、9 项 Python 测试、独立内核路由测试和 Nix 构建通过；
七套内核场景、32 组弱网、自然换钥连续 6000 个 ICMP 回复及旧版互通通过。
首轮 GSO 的小 MTU 黑洞失败已保留并修正，修正版另行完整复测；
具体条件、限速过载丢包及证据见 [性能记录](performance-baseline.md)。
当前仍只有实测底层 goodput 的约 30%，尚未完成千兆性能目标；
百/千节点和开机 VM 没有在本轮重新验收，历史结果继续按原构建记录。

## 2026-09-22：更名为 nnlan

项目/命令/Cargo 包、默认配置和 TUN、systemd/NixOS、示例与测试入口统一改名为 `nnlan`。
`cp` 暂缓，未完成代码已撤下。协议域、身份文件和地址派生不变；历史构建与证据保留原名。
152 项 Rust 普通测试、9 项 Python 测试、release/Nix 构建与四套真实内核端到端回归通过，
另完成内核路由专项及新旧版本双向通信验证。名称映射、日志与既有部署边界见 [更名说明](project-rename.md)。
以下标注旧构建 hash 的规模/性能结果仍属于旧版本，不视作更名后的重新验收。

## 当前已接通

一个 Cargo 包、一个二进制，无中心协调器、DHT、账户服务或插件容器。

```text
CLI ── 0600 Unix socket ── 单所有者 Engine
                           ├─ 签名节点记录：身份 / boot ID / 邻接引荐 / 地址 probe / 候选
                           ├─ 有界记录传播、传递信任、双向邻接选路
                           ├─ 主动逐跳 trace、逐跳加密 echo
                           ├─ TUN ↔ IP 来源/发布者校验 ↔ Envelope
                           └─ 相邻 UDP：RS/RTX/反馈/pacer → Noise AEAD → socket
```

- `run` 已启动真实 daemon；`--no-tun` 仅关闭系统接口/路由，不模拟网络。
- `status`、`peers`、`routes`（查询/发布/撤回/接受/替换/拒绝）、`trace`、`ping`、`shutdown` 已接通。
- 配置 peer 验证目标公钥；接收侧无需预先批准发起者。入站/出站共享预算，配置 peer 保留名额。
- 签名的已认证邻接也是传递成员引荐；转发边要求双方签名记录互相确认，本地直连采用真实握手证据。
  不再额外发送第二套 Introduction 洪泛。`trust.rs` 保留独立签名引荐模型的测试。
- `members deny/allow` 接入持久化本地公钥策略，优先于配置入口、握手与任何替代引荐。
  新签名邻接撤回引荐后重新计算资格，失去资格时清理直连尝试与诊断、待发/FEC/RTX 队列和 VIP 路由；
  本机旧记录不再给断开后的循环提供信任起点。语义见 [成员策略](membership-policy.md)。
- 记录 60 s 有效、稳定状态每 15 s 更新（实际变化立即发布）、最多 4096 个；记录中最多 128 个邻居，所以配置硬上限同步为 128，默认仍为 16。
- 用户流量触发候选直连，控制面发现本身不全连接；直连失败时继续多跳。
- 自动直连按 60 秒业务空闲回收，保护单向配置入口与必要桥接；确定性保留图与跳数约束防止并发拆环，见 [邻居生命周期](neighbor-lifecycle.md)。
- 直连候选跳过与本机已知端点相同的 IP:port，避免不同 NAT 共用私有地址时向自身握手并浪费重试窗口。
  已直连的热路径不再重复复制候选列表。
- 每个身份最多两条主动候选握手，最早间隔 500 ms，准确绑定各自路径与目标身份；认证成功后取消其他主动尝试。
  单次业务请求产生 8 秒需求窗口，每秒维护继续推进，后台尝试不延长需求；详见 [候选生命周期](candidate-lifecycle.md)。
- 自动候选按来源维护：接口快照替换、每个认证邻居的观察替换、断开/过期撤回；显式配置优先且广告仍最多 16 项。
  接口变化通过 rtnetlink 事件触发有界异步 worker 对账，100 ms 合并、15 s 周期修复；见 [候选生命周期](candidate-lifecycle.md)。
- 频繁路径迁移在新握手证明身份后淘汰最旧非活跃密钥，不再每四次迁移等待邻接超时；每 peer 4 世代、全局 8192 上限不变。
- GGB3 采用单层逐跳 Noise；可信中继解密转发并由下一跳重新加密，每条链路保留 FEC/有限 RTX。
- `trace` 每个 TTL 独立主动探测、回复由实际节点签名；最早到达目标的 TTL 决定路径末尾。
- IPv4 从公钥/probe 派生，冲突由公钥排序决胜，败者原子持久化新 probe 后公布并更新 TUN；IPv6 始终稳定。
- 身份锁防止本机重复启动；签名序号提前 fsync 预留，SIGKILL 后重启不会倒退。
- 每次启动签发 boot ID；远端更新节点记录，相邻链路重新握手，无独立端到端会话恢复步骤。
- 已为真实 Linux TUN 安装已知节点的 `/32`、`/128` 路由。已有接口/路由不接管；本机系统操作失败会明确退出。
- 逐方向认证 PMTU 探测、黑洞下降/恢复增大、可变宽度 FEC 与 ACK 拆分已接入，见 [逐跳路径 MTU](path-mtu.md)。
- RS codec、保护预算、反馈/BWE、迟滞、RTX 和 pacer 的参数/边界见 [传输实现说明](transport-implementation.md)。

- Subnet Router 已有真实 IPv4/IPv6 转发与 masquerade，身份绑定到发布者；广告不自动接受。
- 手动路由选择原子保存，专用策略路由和持久 nft 保护避免同 CIDR 的本地 LAN 回落；操作见 [Linux 子网路由](linux-subnet-routing.md)。
- Exit Node 已接通双栈转发、masquerade、UDP/TCP DNS 和显式出口选择/关闭；普通 relay 不自动提供出口。
- 出口选择先部署独立 nft 防直出，再更新持久配置与默认策略路由；出口失联、SIGKILL 或 TUN 消失不会解除保护。
- 底层 UDP 与 peer 专用 DNS 采用带标记的 socket；conntrack mark 恢复和独立 ARP 标记维持严格 RPF 下的底层连接。
- 通配 UDP 监听使用实际收包目的地址回复，多网卡/IPv4 别名/双栈 socket 不再回复成另一源 IP；
  地址绑定仅由认证会话更新，网关选择仍交给内核。
- 显式 `dhcp_client_uid` 为 OS 客户端开放精确 DHCP UDP 端口对；策略路由和 nft 双重约束，
  不放行该 UID 的其他流量，详见 [DHCP 与底层更新](linux-dhcp.md)。
- 物理入站到 VIP 池的明文包被阻断，VIP 服务仍可通过已认证的 TUN 访问。
- 在线 `exit off` 与持有身份锁、确认原 namespace 所有权的 `exit off --offline` 均已实现；操作见 [Linux Exit Node](linux-exit-node.md)。
- 独立 `guard` 不依赖 TUN、DNS、底层地址或序号 state；同一身份锁防止与 daemon 并发修改。
- systemd guard 先于 network-pre，网络配置服务以 Requires + After 强依赖它；NixOS 模块复用相同 unit。
  guard 与 daemon 停止不撤销规则，详见 [Linux 开机保护](linux-boot-guard.md)。

## 验证证据

### 后台主机路由与非阻塞候选引导（更名前构建）

更名前 release：`d1d5bec34df3452e7e03a0024651f0e7ec5c175bb8258d031fe80c05ead7f93e`，
存档 `target/ggbond-route-worker-startup`。仍是 GGB2，依赖、FEC/RTX、记录 TTL 和验签预算不变。

- 修正规模夹具的 ping 计数问题，保留严格三发三收、满 MTU 和精确 trace 检查；
  旧 `48a1` 在修正夹具后仍有 21 组交换失败，负向报告单独保留。
- 采样明确观察到 Engine 同步 netlink 写入中的内核路由锁竞争。主机路由改由一个专用
  工作线程写入，最多一份最新目标；过时任务合并，只有内核 ACK 后才完成记账。
  `/32`、`/128`、不覆盖已有路由与身份撤销规则保持不变。
- 增加 `status.kernel_routes_ready`，规模测试据此等待实际内核路由完成。
  `members deny/allow` 的成功响应也等待路由完成，但不阻塞主事件循环；待回复数量有界。
- 中间构建 `2871` 的千节点启动失败暴露重复接口快照查询：6 个节点因 2 s 查询超时退出。
  移除启动前重复查询，由原有后台监控立即发现和重试；没有提高超时或让发现失败关闭网络。
  故障注入中旧版启动失败，新版在查询仍阻塞时完成加密回显，之后恢复自动候选且无需重启。
- fmt、Clippy、151 项 Rust 普通测试、9 项 Python 测试通过；隔离内核专项验证同步和后台
  路径各 2000 条真实双栈主机路由增删。六套同版内核回归通过：成员、多跳/碰撞、Subnet、
  Exit、PMTU、接口事件/故障恢复；`target/e2e-route-worker-startup-*.json`。
- 同版百节点真实 TUN 五阶段通过：3000 次满 MTU 双栈回显、500 次精确 trace，全部资源回收；
  `target/tun-scale-100-route-worker-startup.json`。
- 同版千节点初始两个分区在 51.013 s 内完成成员、实际内核路由就绪和内核地址核验。
  初始 1000 组交换仍有 25 组未通过（23 次 ping 检查、3 次精确 trace，有重叠），
  整轮失败，后四阶段未执行；全部资源回收。`target/tun-scale-1000-route-worker-startup.json`。
  后续独立抓包还证实固定计数的 iputils 会提前退出、漏计迟到回复；这些检查失败不直接
  等于线上丢包率，3 次 trace 失败也仍需处理。完整目标未完成。

机制与生命周期见 [后台主机路由](kernel-route-worker.md)，实际规模证据见 [规模测试](scale-testing.md)。
阶段源码与证据核验：`target/route-worker-startup-progress-audit.json`。

### 地址归属索引（48a1 历史构建）

该阶段 release：`48a1ee98707bdeadc92b714e2fbc006f5b038fb410b0785f904966c76e7a597c`，
存档 `target/ggbond-address-index`。用户已确认先满足千级，不为万级增加 DHT 或分层路由。

- 保留完整精简链路状态与有限邻接，增加节点地址缓存及双栈 IP 声明索引，消除 TUN 路由
  生成中的嵌套全表扫描。碰撞仍按完整公钥排序，查询仍检查当前信任；probe 变化和过期同步维护索引。
- 不改协议、依赖、配置、记录有效期、验签预算或 FEC/RTX。fmt、Clippy、148 项 Rust 普通
  测试、8 项 Python 测试通过；另通过隔离 namespace 中的 2000 条双栈主机路由内核专项。
- 同版百节点真实 TUN 五阶段全部通过：3000 次满 MTU 双栈回显、500 次精确 trace，
  包含碰撞合并、分区/恢复、败者重启与 probe 持久化。`target/tun-scale-100-address-index.json`。
- 同版千节点初始两个分区完成成员与内核地址核验，用时 96.047 s，原上限仍为 180 s。
  随后 1000 组流量检查中 184 组未通过，其中 4 次 trace 未满足精确路径；未进入后四阶段。
  **千节点整轮仍失败**，所有进程与 namespace 已回收；`target/tun-scale-1000-address-index.json`。
  ping 计数/期限组合另发现测量混杂因素，不能把 184 组直接解释为网络丢包；详见 [规模测试](scale-testing.md)。
- 同版五套内核回归通过：成员策略、四节点双栈多跳/碰撞、Subnet Router、Exit Node、PMTU；
  `target/e2e-address-index-*.json`。源码及阶段证据核验见 `target/address-index-progress-audit.json`，
  当前完整目标仍未完成，不将初始成员收敛当作千节点完整验收。

### TUN 主机路由更新（fec5 历史构建）

该阶段 release：`fec5c441c04c77e1560663e7255eacf668dedc4487feeec3adf296be733aec12`，
存档 `target/ggbond-netlink-routes`。GGB2、依赖、配置及 FEC/RTX 参数均不变。

- 首轮千节点真实 TUN 测试遇到动态 ARP 表容量限制；夹具改用自有点对点链路的永久邻居项，
  未修改宿主机参数。修正底层后，旧版千节点仍收敛失败，负向报告均保留。
- 消除 TUN 每条主机路由变更同步 fork/wait `ip` 的开销，改为持久 rtnetlink socket 与内核 ACK。
  只在成功 ACK 后更新路由集合，保持已有路由不覆盖、删除限定接口及系统错误明确失败。
- fmt、Clippy、146 项 Rust 普通测试、8 项 Python 测试通过；新增的需隔离 namespace 的
  Rust 内核专项另外通过，覆盖双栈冲突、错误传播和 2000 条路由完整增删。
  证据 `target/netlink-routes-verified-build.log`、`target/netlink-routes-100.log`。
- 同版百节点真实 TUN 五阶段通过：3000 次满 MTU 双栈回显、500 次精确 trace、
  地址碰撞与重启持久化、跨分区阻断及资源回收；`target/tun-scale-100-netlink.json`。
  更大规模结果与失败归因见 [规模测试](scale-testing.md)，完整目标尚未完成。
- 同版千节点真实 TUN 仍失败：直接邻接全部正确，但初始 636 节点分区在 180 s 门槛内
  未完成成员收敛；364 节点分区通过状态检查。没有进入流量验收，全部资源已回收。
  `target/tun-scale-1000-netlink.json` 保留队列丢弃、验签限流及时间边界日志；仍需联合性能采样。
- 同版五套内核回归通过：成员策略、四节点双栈多跳/碰撞、Subnet Router、Exit Node、PMTU。
  报告 `target/e2e-netlink-*.json`；阶段证据核验见 `target/netlink-routes-progress-audit.json`。

### 认证状态与会话编号隔离（6252 历史构建）

该阶段 release：`6252e09a60cd7a965ced3c696c5a6b64ea91307d1ce32b74e1e0dd04ce4ad796`，
存档 `target/ggbond-admission-identity`。仍使用 GGB2，不新增协议、依赖或配置。

- 修复首个认证 DATA 含畸形内容时丢失 Connected 的问题。一次接收的事件由调用方持有，
  已提交的状态通知不因后续解析错误而消失；畸形报文仍被拒绝、计数，防重放不回滚。
- 握手先提交邻居/Link 与事件，再执行可能失败的 READY 发送。真实内核发送错误回归
  验证通知保留，随后重发同一 HS3 能获得缓存 READY，且不再次接纳或重建 Link。
- 新增真实 daemon 检查：暂存 READY，仅发送一个认证但畸形的首包，要求 daemon 实际传播
  包含新邻居的自身节点记录。旧版失败、新版通过，不只验证 UDP 内部状态。
  `target/event-commit-daemon-before.log` 与当前普通测试日志。
- 修复公开会话编号的身份混淆：完成握手缓存过期后，新 HS1 仍不得使用任何活跃/保留密钥的编号。
  旧实现的三身份密码层回归中，发给原身份的数据可被另一身份解密；
  `target/session-collision-before.log` 保留逐跳作用域的负向证据。
  新回归验证逐跳和端到端都拒绝冲突、原通信不变、新编号可正常建连、两条会话保持独立。
- fmt、Clippy、144 项 Rust 测试、4 项 Python 夹具测试及 release 构建通过；
  `target/admission-identity-check-build.log`。事件丢失的两项单元负向对照也保留：
  `target/event-commit-before.log`。其中三类畸形首包、认证失败、重放和重复 READY 均有独立断言。
- 当前同版五套 Linux 内核回归通过：成员策略、四节点双栈多跳及 IPv4 冲突、候选推进、PMTU，
  以及四种扩展 NAT 拓扑（双层 NAT 和 hairpin）。报告 `target/e2e-admission-identity-*.json`。
  阶段源码与证据核验见 `target/admission-identity-progress-audit.json`，完整目标仍未完成。
- 后续新增 `make scale-tun` 并完成同版百节点真实 TUN 验收：60/40 独立分区使用同一初始 IPv4，
  合并消解碰撞；再次分区/恢复、碰撞败者根节点重启均通过。五阶段各 100 个节点完成双栈
  满 MTU 回显和精确路径 trace，合计 3000 个回复、500 次 trace，所有进程和 namespace 回收。
  `target/tun-scale-100.json`；夹具新增 3 项 Python 回归（现合计 7 项），详见 [规模测试](scale-testing.md)。
- 本次未重新进行千节点、连续吞吐和完整 32 组合弱网测量。前述结果仍归属 28e5 等存档，
  不将历史构建结果改标为当前构建；完整规模、性能、部署与健壮性验收继续进行。

### 远端密钥就绪（28e5 历史构建）

该阶段 release：`28e5b50b2d0cd0140bbf0b2ea2ea50c91da83eed88fdd88798a568a6ead9e71e`，
存档 `target/ggbond-key-ready`。线格式升级为 GGB2，所有互联节点需一起升级；身份、地址和配置保留。

- HS2 后只取得本地密钥，等待认证 READY 或正确端点上的认证 DATA 才启用新发送世代。
  换钥期间继续使用旧的已就绪密钥；首次连接等待对端就绪才发布 Connected。
- READY 使用独立保留 nonce，不进入 DATA 重放窗口；丢失后通过缓存 HS3/READY 重试。
  等待确认仍计入原始 8 s 期限和共享 64 条握手预算，迟到确认不回滚较新的发送世代。
  逐跳与端到端共用此机制，端点绑定在临时密钥的解密/重放记账之前检查。
- fmt、Clippy、140 项 Rust 测试、4 项 Python 夹具测试及 release 构建通过；
  `target/key-ready-final-check.log`、`target/key-ready-final-build.log`。
  旧版暂存 HS3 时业务丢失的负向用例已加入常规回归，并覆盖认证失败、重复/乱序确认、
  首包超越 READY、nonce 边界、原始期限和共享容量；旧负向日志保留。
- 同版跨自然换钥连续 120 s 真实 TUN 负载专项通过：6000/6000 ICMP、TCP 172.77 Mbit/s、
  TCP 重传 0、RTT p99.9 为 16.1 ms。三个后续方向各 500/500 回复；
  `target/crossed-transition-key-ready.json`。这是单次同机两节点测量，不是完整性能或长期稳定性验收。

- 本版千进程自然换钥通过：20.996 s 发现、999 条必要边、地址唯一，换钥前后各 1000 次
  8192 字节加密回显及双向 trace 成功；1998 个有向世代全部变化、PMTU 满足要求、全部进程回收。
  `target/daemon-scale-1000-key-ready.json`。一次无 TUN / 135 s 稳态验收不代表长期规模验收。

- 同版九套基础 Linux netns 和全部 32 组双栈弱网组合通过；
  `target/e2e-key-ready-*.json`、`target/key-ready-netns-summary.json`。
  阶段证据核验 `target/key-ready-progress-audit.json` 仍明确完整目标未完成。
- 当时的健壮性诊断发现以下边界（已由上方认证状态提交修复）：合法 AEAD 中的畸形首个 PMTU 报文抢在 READY 前到达，
  UDP 已接纳邻居，但后续解析错误吞掉唯一 Connected 事件；再到达 READY 也不补发。
  真实 UDP 负向复现 `target/malformed-first-data-before.log`：`admitted=true connected_events=0 rejected=1`。
  诊断测试运行后已恢复源码；不计作该历史构建通过的普通测试。

### 跨密钥世代共享路径控制（1687 历史构建）

该阶段 release：`1687a132645fa7662127ad827ac160ef22d88bbf43a7ae738554d4d7e283dab3`，
存档 `target/ggbond-shared-path`。

- Peer 直接拥有一份路径控制器，所有保留的密钥世代显式借用它；同路径换钥保留已学习的 BWE、
  burst、反馈额度和保护债务，不给新世代额外发送预算。每个 tick 合计所有世代的负载，聚合空间复用。
  FEC、缓存、防重放和反馈时钟仍按世代隔离，不跨时钟原点计算延迟。
- 完整窗口才能更新路径过载信号，首个新世代报文不清除过载；1 s 无更新的趋势信号过期。
  真实端点迁移重新估计，并清理旧路径 Link；未提高初始速率或 burst，未延长队列/缓存期限。
- fmt、Clippy、134 项 Rust 测试、4 项 Python 夹具测试及 release 构建通过；
  `target/shared-path-check-build.log`。
  真实 UDP 回归在旧版上出现 9.136→8.1 Mbit/s 的错误重置，修正后保留已学习速率；
  同一测试随后更换真实端点，要求回到初始估计。另覆盖四个世代共享预算、不同反馈时钟及证据过期。
- 同版九套基础 Linux netns 和全部 32 组双栈弱网组合通过，报告 `target/e2e-shared-path-*.json`。
  阶段证据与源码核验见 `target/shared-path-progress-audit.json`，完整目标仍标为未完成。
- 本版千进程通过：23.055 s 发现、999 条必要边、IPv4/IPv6 地址唯一，换钥前后各 1000 次 8192 字节
  加密回显与双向多跳 trace 成功，1998 个有向世代全部变化、PMTU 符合要求，全部进程回收。
  `target/daemon-scale-1000-shared-path.json`。这是无 TUN、135 s 稳态要求下的一次验收，
  不替代真实 TUN 大规模、分区合并、反复 churn 和长时间稳定性验证。
- 跨自然换钥连续 120 s 负载中，BWE 保持 1 Gbit/s、burst 保持 64000，所采样的未首次发送源片丢弃为 0；
  RTT p99.9 为 17.4 ms。但 **只收到 5997/6000 个 ICMP 回复，专项整体仍失败**。
  `target/crossed-transition-shared-path.json`。换钥处双方 invalid UDP 分别增加 128 / 718。
- 后续真实 UDP 故障注入仅暂存 HS3，不改生产代码：双方旧密钥仍有效，但暂存期间业务交付 0，
  释放 HS3 后新消息交付 1；`target/late-hs3-before.log`。待修复“对端尚未收到最后握手便发送新密钥数据”。
  该负向测试源保留在 `target/late-hs3-regression.rs`，诊断后工作树测试文件已原样恢复。


### 同路径换钥保留 PMTU（79ad 阶段）

该阶段 release：`79ad056ec8188a81663a935ec06e221ef2038a24b8769fa7a2e28731f4ff6d44`，
存档 `target/ggbond-path-mtu-retention`。

- 同一认证端点对换钥时保留已证明的 PMTU，清除旧探针 token；新端点或本地源地址变化仍重新探测。
  路径挑战迁移在修改端点时立即清空旧证明，避免后续握手把迁移误判成同路径换钥。
  未修改 FEC/RTX、队列期限、初始 BWE、pacer 或密码世代隔离。
- 确定性真实 UDP 回归在旧版上因 1232→548 失败，修正后通过，并检查旧世代 8192 字节待发消息交付。
  新增旧 token 失效、失败上界保留、路径迁移与同身份新端点重新认证的回归。
- fmt、Clippy、130 项 Rust 测试、4 项 Python 夹具测试及 release 构建通过；
  `target/path-mtu-retention-check-build.log`。三项真实 UDP 换钥测试连续执行 10 轮通过。
- 同版九套基础 Linux netns 回归、完整 32 组双栈弱网组合通过；
  `target/e2e-mtu-retention-*.json`。最新构建尚未复测千进程，先前 cd25 的 997/1000 失败仍是待解决问题。
- `make perf-rekey-transition` 新增跨自然换钥的连续 120 s TCP 与 6000 次 ICMP，保留每约 0.2 s 的状态，
  再运行原有三项换钥后持续吞吐回归。旧版在同一夹具上观测到 548 字节；本版始终观测到 1232 字节。
- **连续换钥负载整体仍失败**：本版只收到 5998/6000 个 ICMP 回复，p99.9 为 243 ms，TCP 重传 289 次。
  换钥后新 Link 的 BWE 仍从 1 Gbit/s 重置至 8.1 Mbit/s、burst 从 64000 重置为 2400，
  随后观测到 117 个未首次发送源片丢弃。PMTU 修正没有解决全部换钥瞬态问题。
  原始报告 `target/crossed-transition-before-mtu-retention.json`、`target/crossed-transition-mtu-retention.json`；
  不能把三项换钥后吞吐与回复通过，写成跨换钥全程无损。


### 接收驱动的有界反馈额度（cd25 阶段）

该阶段 release：`cd25cb49ad69d1a897aaf165f9df57276686dfc243193c05e5070fd27f189abc`，
存档 `target/ggbond-receive-credit`。

- 修复纯反馈方向的额度来源：每次维护取发送估计与实际已认证数据接收额度中较大的一项，
  不相加；不从 ACK/NACK 获取额度，不提高数据 BWE、总 pacer、burst 或实例带宽上限。
  规则及边界见 [传输说明](transport-implementation.md)。
- 单向高负载确定性模型：31,000 条消息，旧实现因反馈不及时使发送缓存占满，
  拒绝 10,288 条、368 个源片缓存过期；新实现全部交付，零拒绝、零过期、反馈队列零丢弃。
  `target/high-rate-feedback-before.log` / `target/high-rate-feedback-after.log`。
- fmt、Clippy、126 项 Rust 测试、4 项 Python 夹具测试及 release 构建通过；
  `target/receive-credit-check-build.log`。新增额度不重复累积、上限和非递归反馈回归。
- 千节点复测 26.784 s 完成发现，但初始回显 997/1000，430、436、437 发起的请求超时，
  **整体失败，未进入稳态或自然换钥**；`target/daemon-scale-1000-receive-credit.json`。
  第一条失败路径 309→102 增加 7 个未发送源片丢弃，排队/调度稳定性仍需独立解决。
- 本版九套基础 Linux netns 回归及完整 32 组双栈弱网组合通过：
  `target/e2e-receive-credit-*.json`、`target/e2e-weaknet-receive-credit.json`。
- 新增 `make perf-crossed-rekey`：仅延迟 LINK 握手，实际等待 120 s 自然换钥，
  要求双方活动世代不同且三种持续 TUN 流量测量全程仍使用这些世代。
  同一夹具在旧版 353e 上重现约 11.8 Mbit/s 持续退速；本版三项约 174.4 / 171.5 / 175.0 Mbit/s，
  各 500 个探测回复齐全，两个方向各仅 3 个握手包进入延迟队列。
  `target/crossed-load-fair-feedback-before.json`、`target/crossed-load-receive-credit.json`。
- 普通 12 项连续采样完成；仍观察到跨越换钥瞬间的一项 goodput 74.49 Mbit/s、RTT p99 249 ms、
  探测回复 497/500，不能宣称无扰动换钥或完整性能验收通过。
  `target/perf-receive-credit.json`。完整数据和强制交叉专项边界见 [性能记录](performance-baseline.md#接收额度修正与强制交叉换钥回归)。

本阶段证据核验 `target/receive-credit-progress-audit.json` 保留 `full_goal_complete=false`，
同时核对源码/构建、模型负向对照、真实内核回归、千节点失败及瞬态性能退化。


### 单所有者运行时与反馈公平性（353e 历史构建）

该阶段 release：`353e1107fa3a85d4629a7bfdfefafd9fc1a5cc1decd5be7933aab100e6249510`，
存档 `target/ggbond-fair-feedback`。

- Engine 的单所有者运行时使用 current-thread；同一 tick 的 Link 维护只执行一次，
  每个实际发包仍经过原有额度、过期、保护预算与公平邻居调度。
- 反馈与业务队列共享发送轮次，修复反馈持续积压时反向原始源片过期的问题；
  不提高带宽、不放宽超时、不关闭 FEC/RTX。新增回归在旧调度失败，
  新调度在 548/1232 字节 PMTU、逐包/批量 poll 下通过。
- fmt、Clippy、122 项 Rust 测试、4 项 Python 夹具测试和 release 构建通过；
  `target/feedback-fairness-check.log`、`target/fair-feedback-build.log`。
- 千节点 / 135 s 自然换钥通过，25.731 s 发现收敛；1998 个有向世代全部变化，
  PMTU 全部恢复，换钥前后各 1000 次 8192 字节加密回显及各两条精确多跳 trace 成功。
  全部进程正常回收；`target/daemon-scale-1000-fair-feedback-rekey.json`。
  该夹具使用真实 UDP 进程但关闭 TUN，不替代千节点 Linux 转发或性能验收。
- 同版重复测试发现收敛 36.644 s，但初始回显为 998/1000，813→313、814→314 超时，
  整体失败且未进入稳态/换钥阶段；`target/daemon-scale-1000-fair-feedback-rekey-repeat.json`。
  失败路径 9→2 增加 11 个未发送源片丢弃；反馈轮转修复并未解决所有排队/调度问题。
  **千节点重复稳定性仍未达标**，不把上一轮完整通过当作稳定性交付完成。
- 该版九套基础 Linux netns 回归通过（含 IPv4 冲突、多跳、子网、Exit、9 种同类 NAT、
  候选、PMTU、邻居回收与 DHCP 策略）：`target/e2e-fair-feedback-*.json`。
- 完整 4 种 FEC/RTX 策略 × 8 种内核故障、双栈真实 TUN 共 32 组合通过；
  `target/e2e-weaknet-fair-feedback.json`。不只沿用上一版本的结果。
- 完成 12 次真实 TUN/底层吞吐采样，但**性能尚未达标**：首次三种隧道方向约 177–183 Mbit/s，
  后续部分窗口降至约 11–12 Mbit/s 并丢失 ICMP 回复。低速窗口伴随双向活动世代不同，
  其相关性和原始数据见 [性能记录](performance-baseline.md#反馈轮转版本的完整轮换采样)。
  需要继续定位高负载交叉换钥/反馈路径，不能只引用首轮峰值。



本阶段证据核验：`target/fair-feedback-progress-audit.json`，明确保留 `full_goal_complete=false`，
同时核对正向功能结果、规模复测失败与性能退化。

前一单所有者构建 `8a1f7ac…` 的一轮千节点 / 65 s 稳态通过，但第二轮初始回显
有 1 次超时，未进入换钥检查；原始失败和有界路径快照均保留，不用首次成功覆盖复测失败。
该前置版本另通过百节点 / 135 s 自然换钥及九套基础 Linux netns 回归
（`target/daemon-scale-100-single-owner-rekey.json`、`target/e2e-single-owner-*.json`）；
这些报告不改标为最新反馈调度版本。详细因果模型与边界见 [规模记录](scale-testing.md#单所有者调度与反馈公平性后续推进)。

### 接收突发合并（4e611 历史构建）

该阶段 release：`4e61104f352a19f8e69bf40ed3203303246ab7e7dcc4f8a49875958b75fca846`。

- fmt、Clippy、120 项普通测试与 release 构建通过；
  `target/trend-burst-check-final.log`、`target/trend-burst-build.log`。
- 百节点 / 135 s 自然换钥通过，198 个有向世代变化、PMTU 全部恢复、
  换钥前后各 100 次 8192 字节加密回显和各两条多跳 trace；
  `target/daemon-scale-100-trend-burst-rekey.json`。
- 默认 FEC+RTX 的 8 种真实内核弱网条件、IPv4/IPv6 TUN 和移除故障后的业务恢复通过；
  `target/e2e-weaknet-trend-burst.json`。这一版没有重跑完整 32 组合，32 组合属于下面的 d418 阶段。
- 千进程在 148.455 s 时通过全部成员、地址唯一性与 999 条边检查，随后加密回显超时，
  **整体失败**；`target/daemon-scale-1000-trend-burst.json`。全部自有进程回收，日志没有观察到验签限流。
  已采样 4 个自有进程的后期 CPU 调用栈，不能把后期热点当作初始退速的因果证明。

周期性批量收包的负向对照、Seal 饥饿和分阶段边界见 [规模记录](scale-testing.md#趋势回归突发合并与-seal-排队后续推进)。
阶段核验在 `target/trend-progress-audit.json`，明确保留 `full_goal_complete=false`。
完整交付仍包含千节点数据面、真实 TUN 规模、长期抖动/分区合并与性能等下述剩余项。

### 延迟趋势与过载排队（d418 阶段）

release `d4180ab2ad6421b82ae37644375db24f606da061f1782f65015a5538f0752503`：
fmt、Clippy（warnings 为错误）、118 项普通测试和 release 构建通过，
日志 `target/trend-seal-check-build.log`。新增完整趋势窗口、持续过载判据、时钟偏移/聚合内存界限，
并修正 Seal 比源片更晚过期导致的业务饥饿；详见 [传输说明](transport-implementation.md)。

- 100 ms 单次接收调度停顿：原来的差分 EWMA 触发一次误降速，新回归不再误判；
  持续排队增长仍降速，低速 ACK 恢复和没有新证据不重复降速的门槛仍保留。
- 64 kbps 链路持续超量入队：完整 Link 对照模型修复前仅交付 4 条业务消息，
  此后只消耗无用 Seal；修复后交付 81 条且始终不突破配置的线上预算。
  普通测试检查持续后半段交付和排空后的队列/源片回收，而不要求过载下无损。
- 10 → 2 → 10 Mbps 有限队列模型：Seal 修复前速率长期停在约 461 kbps；
  修复后容量恢复时重新升到 10 Mbps。模型使用虚拟时间，不是 Linux 吞吐验收。

仅趋势修正的中间构建 `5dab1083…` 千进程测试仍失败：180 s 后成员范围 124–805，
所有进程回收，1 份日志包含验签限流。它没有验证 Seal 修正，不能用于声称当前版千节点通过。
该版本千进程复测同样失败：180 s 后范围 297–1000，全部进程回收，日志中未观察到验签限流。
`target/daemon-scale-1000-trend-seal.json` 不是通过报告，也不能把最后一个采样没有最低速率链路
解读为整个过程没有降到最低速率。

该版本通过百节点 / 135 s 自然换钥复测：198 个有向世代变化、PMTU 全部恢复、
100 次换钥后回显与双向 trace 完整通过，进程全回收；
`target/daemon-scale-100-trend-seal-rekey.json`。
另通过真实双栈 TUN 的 4 种修复策略 × 8 种内核弱网条件，共 32 个组合；
`target/e2e-weaknet-trend-seal.json`。两套测试有时间重叠，不据此作隔离 CPU/吞吐结论。

### 传播调度与规模轮（历史构建）

本地 release SHA-256：`251c4bff40fd218f16ff790c1b362dde7fe7e1c299f0b5142816ee8e00be4421`。
107 项普通测试、fmt、Clippy 和 release 构建通过，日志 `target/gossip-lazy-check.log` / `-build.log`。
记录传播新增最多 200 份/s 的逐邻居节流、有界去重 FIFO；重复更新不插队，读取最新记录再发送。
接收侧每邻居每秒 256 次控制验签限制没有提高。稳定记录每 15 s 重签，实际变化即时发布，
候选来源到期由 100 ms 维护任务独立触发发布，不延迟撤回。
保留图按实际非保护空闲边的回收需求延迟计算，拓扑变化失效缓存；算法和跳数保护不变。

百进程复测通过：全体发现、99 条必要边、100 次加密交换、双向五跳 trace 与 65 s 稳态检查。
接口事件专项复测通过，17 次变化最大传播耗时约 0.257 s；快照超时/失败、周期恢复与双栈 TUN 均通过。
本轮九套基础 netns 回归全部通过，日志 `target/gossip-lazy-base-e2e.log`；
`target/gossip-progress-audit.json` 核对当前二进制、各报告已记录的脚本来源及源码摘要，
同时明确记录千进程尚未通过。旧版 VM、扩展矩阵和性能报告仍只证明其标注版本。

千进程仍未通过：本轮 180 s 结束时各节点可信成员数为 260–942；
1,000 份节点日志中没有控制验签限流错误，但全体发现门槛未达到。
全部自有进程已回收；`target/daemon-scale-1000.json` 保留 `ok=false`。
阶段失败、CPU 采样与余项见 [规模测试](scale-testing.md)，不降低节点数或放宽成功门槛来宣布完成。



### 接口事件驱动轮（历史已验收构建）

本地 release SHA-256 为 `33c0063aeda72958b887f96d9d269de929018fc1a703859c6ad9795ff9e10ee8`。
104 项普通测试、fmt、Clippy 已通过，日志 `target/interface-events-check.log`；
下面的 VM、扩展 NAT/弱网矩阵和性能数据属于各自标注的先前版本，不充当这个二进制的复测。
九套基础 netns 已全部在此二进制上复测通过；专项重复与来源核验保存在
`target/interface-events-final-audit.json`，日志 `target/interface-events-base-e2e.log`。

`make e2e-interfaces` 已两次独立通过：每轮 17 次真实 IPv4/IPv6 地址及接口变化均在 2 s 内传播；
401 次突发地址操作合并为一次快照，静默 16 s 仅一次周期查询。
快照卡死期间加密通信继续，2 s 超时后子进程回收；持续查询失败使动态来源按 TTL 到期，
显式配置保留，随后在没有接口事件的情况下通过周期对账恢复。
两轮最后都通过双向双栈 TUN、实际 trace 和 boot ID 不变检查。
报告为 `target/e2e-interfaces.json`、`target/interface-events-repeat.json`；
旧二进制运行相同测试在首个接口增加的 2 s 传播门槛失败，保留为 `target/interface-events-before.json` / `.log`。

另有 100 个真实进程的稀疏树验证：99 条必要边、全体成员发现、100 次 8192 字节加密交换、
双向五跳 trace 与 65 s 稳态检查均通过。关闭 TUN，范围与资源观测见 [规模测试](scale-testing.md)。
同轮千进程真实测试未通过：180 s 后各节点仅信任 121–575 个成员，375 份节点日志命中控制验签限流；
全部进程已回收。失败证据 `target/daemon-scale-1000.json`，下一步修复记录发送节流与队列公平性后复测。

普通回归：`nix develop --command make check`，104 项测试通过；fmt / Clippy warnings-as-errors 通过。
release 构建通过。新增的独立进程测试在 `tests/daemon.rs`，不是内存中的“节点对象”：

1. 四进程 A→C→D→B：成员发现、主动 trace 返回 C/D/B、16384 字节端到端加密 echo。
2. 三进程：通信前保持经 C 的路径，用户流量后有限直连升级为 A→B。
3. 两个真实派生 IPv4 相同的测试身份：冲突重选、持久化，SIGKILL / 重启后地址不回退，端到端会话恢复。
4. 四进程双路径：远端签名撤回、替代引荐、本地否定优先及 SIGKILL 后持续封禁；另有单进程保存失败不改活跃策略测试。

成员策略端到端：`make e2e-membership` 使用四个 namespace 和四条 veth 组成 A—C—B / A—D—B，
不启用跨底层链路的物理 IP 转发。当前已验证：

- A 封禁 C 后主动 trace 收敛到 D/B，双栈 TUN 仍通；C 的新握手被拒绝，包括其原有配置入口名额。
- A 封禁 B 后删除 B 的 `/32`、`/128`，真实双栈应用接收日志没有 B 的新请求；D 仍信任 B，但不覆盖 A 的策略。
- A SIGKILL 后重启仍保留封禁；allow B 恢复实际双栈通信，不顺带解除对 C 的封禁。
- 再切断最后一个本地信任起点后，缓存中的循环不维持其他节点资格。

报告为 `target/e2e-membership.json`；子网与出口测试另验证封禁已选发布者后的双栈防回落，
出口封禁还经过客户端 SIGKILL/重启。独立四进程撤回/恢复测试另连续运行五次通过。

Linux kernel 端到端：

```bash
nix develop --command make e2e
```

`tests/e2e/overlay_netns.py` 创建四个唯一命名的 namespace 和三条 veth 底层链路。
不启用跨底层链路的 IP forwarding；A 和 B 的通信确实依赖 C/D 用户态多跳。
在其中运行四个 release daemon，使用真实 TUN 和系统 ICMP：

- IPv4 / IPv6 各 3 包全部返回；实际 trace 为 C/D/B。
- `--collision` 使用公开测试身份令 A/B 初始 IPv4 都为 `33.168.136.153`；
  A 实际切换到 probe=1，并校验内核 TUN 地址已更新，而不是只改 status 字段。
- 16384 字节端到端 echo 通过。
- A→C 的真实接口添加 `tc netem loss 8%`；回显成功，接收端记录到实际 FEC 恢复。
- 本次创建的 daemon、namespace、veth 均清理；宿主机路由/防火墙不改动。

最近报告在 `target/e2e-overlay-collision.json`（测试产物，不提交密钥/运行状态）。
上述只证明本机隔离环境的功能，不是互联网 NAT 场景全集、千进程压力测试或吞吐验收。
原有 `topology_scale` 的千节点测试仍只覆盖内存图；新增独立进程百节点验证见 [规模测试](scale-testing.md)。

子网端到端：`nix develop --command make e2e-subnet`。
`tests/e2e/subnet_netns.py` 使用六个 namespace、三个真实 daemon（A→B→C），
以及三个使用完全相同 IPv4/IPv6 地址的物理 LAN 服务。已验证：

- 广告本身不改路由；手动接受后，双栈 TCP 返回所选 LAN 的标识和正确的 SNAT 地址。
- 每个响应验证 45056 字节应用负载；访问 C 的主动 trace 为 B/C，实际依赖多跳。
- 相同前缀的第二个发布者需要 `--replace`；最长前缀撤回不回落到健康的较宽前缀。
- 发布者 SIGKILL / 重启恢复；客户端 SIGKILL / TUN 消失后所选 LAN 不回落到本地 LAN。
- 重启保留所选公钥，包含 `/32` / `/128` 主机子网；显式 reject 才恢复本地 LAN。
- 再次 SIGKILL 后清空专用路由表，IPv4/IPv6 仍被独立 nft 规则阻断；恢复后所选 LAN 正常。

报告在 `target/e2e-subnet.json`；同样只操作本次创建的 namespace。

出口端到端：`nix develop --command make e2e-exit`。
`tests/e2e/exit_netns.py` 使用五个 namespace，构成客户端 A → 中继 R → 出口 B/C，外加双栈模拟互联网。
A 自身的双栈 WAN 始终可用；测试读取互联网端的请求日志，区分“没有泄漏请求”和“只丢掉回复”。已验证：

- 普通未标记应用的 IPv4/IPv6 TCP 实际源为所选出口，响应负载 40960 字节。
- UDP/TCP DNS、本地 stub、link-local resolver、上游 UDP 截断改 TCP 均使用所选出口。
- 显式 B→C 切换；B 失联不自动选择 C，B 恢复不覆盖已有的 C 选择。
- 单独移除 C 的 IPv6 外部路径时，IPv6 阻断、IPv4 仍走 C；不回落到 A 的 WAN。
- A SIGKILL、TUN 删除、清空专用路由表后仍阻断；冷启动 peer 主机名通过带标记的 UDP/TCP DNS 重新解析。
- 严格 RPF 下显式清空 A/R ARP 缓存，动态邻居恢复，不靠静态邻居或放宽 RPF。
- 不重启 daemon 地删除、替换 A 的物理 IPv4 地址，底层路径恢复后仍使用原选定出口。
- 通过加密组网访问 VIP TCP 服务成功，从物理 WAN 直接访问同一个 VIP 服务被阻断。
- 无 `src_valid_mark` 时拒绝启用并保持配置；TUN 创建失败前已安装持久保护。
- 离线关闭拒绝活跃身份锁和错误 namespace；在线及正确 namespace 的离线关闭恢复本地双栈出口。

报告在 `target/e2e-exit.json`，带测试时间、内核版本和实际二进制 SHA-256。
`make e2e` 包含成员策略、覆盖网络、子网、出口、NAT、候选生命周期、PMTU、邻居生命周期和 DHCP 策略九套测试。另有独立 VM 测试；这些结果仍不是互联网 NAT 全矩阵或性能验收。

NAT 端到端：`nix develop --command make e2e-nat`，详见 [Linux NAT 验收](linux-nat-testing.md)。
六个 namespace、三个真实 daemon；两端使用相同私有 IP，由实际 nft/conntrack NAT 隔开。
先用独立 UDP 探针测量映射和过滤，再检验九种同构组合的发现、有限直连、加密中继、trace 和双栈 TUN。
端点相关过滤场景还验证直连断开→中继→直连恢复、真实 NAT 端口重绑定，以及引导节点退出后继续双栈直连。
报告为 `target/e2e-nat.json`；不是仅改变内存里的“候选类型”或连接状态。

异构 NAT 端到端：`make e2e-nat-matrix` 的 81 个有序组合全部通过（9 同构、72 异构），
57 组实际直连、24 组实际中继，双方分别实测映射/过滤并清空探针状态后才启动 daemon。
每组核对双向主动 trace、加密回显、双栈 TUN、邻居上限与端点 boot ID 不变。
两个 `ADM/EIF ↔ APDM/APDF` 角色组合在 R 离线、发往 R 的重试被提前丢弃后，
仍持续双向加密通信超过 65 秒，再通过双栈 TUN；不是靠背景重试维持旧过滤权限。
候选调度变更后已再次全量通过，报告为 `target/e2e-nat-matrix.json`。
旧 NAT 夹具按预测而非实际 SNAT 端口刷新集合的问题已修正，
同一产品二进制的负向对照保留在 `target/nat-legacy-binding-expiry.json`。

扩展 NAT 拓扑：`make e2e-nat-topologies` 的四个真实内核场景已通过：
两端各有两层 NAT 时，EIM/APDF 外层直连、APDM/APDF 外层中继，并逐层核对实际 SNAT conntrack；
共享外部 IP、不同映射端口且私网互相隔离时，hairpin 开启可直连、关闭则保持中继。
独立 UDP 探针验证 hairpin 实际回送与线上源地址；四组都验证双向双栈 TUN、加密回显、trace 和邻居上限。
报告 `target/e2e-nat-topologies.json`。新的单请求触发测试也通过：hairpin 三次独立复测为 1.067 / 1.058 / 1.048 秒。
同样只发一次请求时，旧版本 35 秒内未升级；新版失败路径在需求过期后停止探测，第 20–22 秒计数不再增长。

IPv6 发现端到端：`make e2e-ipv6-discovery` 已通过。失效 IPv4 候选在前、可用 IPv6 在后，
两端只配置 R，真实有状态 IPv6 防火墙下单次请求约 0.73 秒升级；不是直接手工填写对方 IPv6。
还验证 IPv6 阻断后的中继回退与恢复，以及 R 离线后超过 65 秒业务空闲仍保留唯一必要连接。
全程使用双向双栈 TUN、加密回显和实际 trace，报告为 `target/e2e-ipv6-discovery.json`。
同一入口另验证较慢而未被丢弃的 IPv4：双向 UDP 各延迟 1500 ms，第二个 IPv6 候选约 0.73 秒胜出；
迟到握手不覆盖赢家，实际 IPv4 入站计数与双向 conntrack 已核对，报告 `target/e2e-ipv6-delayed-candidate.json`。

候选生命周期端到端：`nix develop --command make e2e-candidates`。
连续 20 次真实 SNAT 端口变更、每次删除对应 conntrack，确认远端签名记录撤回旧候选、使用新端点且加密回显正常。
还验证接口地址增加/替换/down/up、daemon boot ID 始终不变，以及解除 WAN 阻断后利用最新候选建立双栈直连。
首轮 release 实测每次变更至候选传播和回显完成约 1.97–2.15 s；这是本机无损功能测试，不是公网恢复 SLA。
报告为 `target/e2e-candidates.json`。TTL、共享观察来源和旧世代观察隔离另外有普通回归测试。

路径 MTU 端到端：`nix develop --command make e2e-pmtu`，详见 [逐跳路径 MTU](path-mtu.md)。
真实 A–路由器–B 链路已有以下验证，而不是只在内存里修改发送上限：

- 底层 MTU 从 1500 降到 900：A 方向实际产生 ICMP PTB，B 遇到本地发送错误，daemon 不退出。
- 反向静默丢弃超过 700 字节的 IP 包，两个方向分别收敛到不同的认证大小。
- IPv4 底层 MTU 降到 576 且过滤 PTB，仍通过满 TUN MTU 的双栈 ICMP 和 16384 字节加密回显。
- MTU 恢复到 1500 后重新提高到 UDP 上限 1232；整个过程 boot ID 不变。
- IPv6 底层 MTU 1280 同样承载双栈覆盖通信；每阶段核对 IPv4/IPv6 分片和重组计数没有增长。

报告为 `target/e2e-pmtu.json`，包含各阶段两个方向的 PMTU 状态、二进制及测试脚本 SHA-256。
普通回归另覆盖可变宽度 RS 丢包恢复、ACK 拆分、大小变化时旧队列回收、旧世代/未验证端点 ACK 拒绝。
这些结果尚不证明所有多跳/高时延/外部路由 ICMP 组合，具体余项继续保留如下。

邻居生命周期端到端：`nix develop --command make e2e-neighbors`，见 [邻居生命周期](neighbor-lifecycle.md)。
测试没有缩短生产 60 秒计时器，两个独立 kernel 场景已验证：

- A 的两个名额被配置 R 与自动 B 占满时，A→C 仍能多跳通信；B 空闲后回收，C 复用空位直连。
- R 仅被其他节点单向配置，R 自己没有反向配置；这些配置边仍被两端保留。
- 连续单向应用流量超过空闲阈值，接收方作为回收发起端也保持直连；控制面流量不冒充业务使用。
- 入口进程退出后，唯一剩余自动 A—C 边空闲超过阈值仍保留；双栈 TUN 和加密回显正常。
- 四节点自动完全图在入口离线后，由六条自动边回收到三条保留边；实际 trace 经保留中继，节点未重启。

报告为 `target/e2e-neighbors.json`，记录二进制/脚本 SHA-256。普通测试另穷举五节点所有图的并发回收，
并覆盖“每条备用路径都不超限，但一起删除后端到端变成 39 跳”的反例。
上述不是并发真实故障、延迟控制面与千节点长时间回收压力的完整验收。

开机端到端：`make e2e-boot`。`tests/nixos/boot.nix` 实际启动两个 Linux/systemd VM，
使用静态双栈 networkd，已验证：

- 在 networkd 主进程启动前安装 guard（本轮单调时间为 10.882693 s 与 11.436815 s）。
- 应用探针在 guard 前启动；daemon 因损坏的 state 失败，接收端没有双栈 TCP/UDP 请求。
- 清空策略路由表后，独立 nft 继续保护；重复 guard 不重写损坏的 state。
- 修复测试 state 后，交付的 daemon unit 可创建 TUN；活跃身份锁拒绝另一个 guard。
- SIGKILL 后 systemd 自动重启 daemon，持续探针没有直出。
- 显式离线关闭后，接收端确实记录到客户端本地 IPv4/IPv6 TCP/UDP 请求，作为正向对照。
- 损坏配置、关机再启动后，guard 失败，networkd 不执行，物理地址不配置，没有泄漏请求。

报告在 `target/boot-result/boot.json`，包含测试/模块/unit SHA-256 和实测二进制摘要。
候选调度轮的 Nix 包摘要为 `867ca8e4fb7e305107c4703fe014efcfa8f879bd2d4b39f355f4a6a0afe74158`；
其 release 普通测试也通过。同轮本地 Cargo release 摘要为
`cd3969fc14096e5e3a020cead7608cf159e31ac88dfd8faa5f84a3211d02472e`；两种构建产物分别记录，不混用摘要。
此次开机证据不包含 DHCP、NetworkManager 或 initrd 配网。

DHCP 端到端：`make e2e-dhcp` 使用三个真实 VM，networkd / dnsmasq / 双栈互联网服务。
此轮已通过以下独立于静态开机测试的验收：

- guard 先于网络配置，仍获取真实 IPv4/IPv6 租约和 RA 默认路由。
- 客户端访问网关另一张网卡的地址，通配 UDP 监听仍从正确地址回复；真实双栈 Exit TCP 和 UDP/TCP DNS 成功。
- IPv4 单播续租、IPv6 自然 T1 续租，pcap 与服务器日志交叉检查；IPv6 租期实际刷新。
- DHCP 地址从 `.100` 改为 `.101`、网关从 `.1` 改为 `.254`，移除旧网关地址后继续使用原出口，daemon boot ID 不变。
- daemon 停机、TUN 消失后两个地址族继续续租；应用 TCP/DNS 请求未到达互联网服务。
- 显式 `exit off --offline` 后应用真实源恢复为客户端物理地址，作为正向对照。

报告 `target/dhcp-result/dhcp.json` 与上面的 boot 报告使用相同 Nix 二进制摘要。
候选调度轮的九套 netns 报告曾核对为上面的本地 release 摘要（见该轮审计存档）；覆盖/子网测试也记录二进制与脚本来源。
DHCP 策略负向测试覆盖错误 UID/端口/协议、严格 RPF、路由表删除、UID 替换/移除与重复协调。
上述实测不等于任意网络管理器或所有动态前缀场景；详见 [DHCP 与底层更新](linux-dhcp.md)。

扩展弱网端到端：`make e2e-weaknet` 已通过四种 FEC/RTX 发送策略 × 八种内核故障的 32 组对照，
每组 IPv4/IPv6 各 400 个真实应用 UDP 包。包含随机/突发丢包、乱序、复制、反向反馈路径丢包、
限速与组合故障，并验证实际修复计数、零重复交付、有界缓存/队列、资源采样和移除故障后的双栈恢复。
不是仅给内存模型设置“丢包率”；原始数据在 `target/e2e-weaknet.json`，细节见 [弱网矩阵](weak-network-testing.md)。
已修复预算拒绝后的重传调度循环，以及乱序/旧梯度与低速采样门槛造成的恢复停滞；
默认双层加密、FEC、有限 RTX、35% 共享预算、1 秒源缓存和每源两次重传上限均保留。

上一轮候选调度的统一核验在 `target/candidate-race-final-audit.json`：102 项普通回归、九套基础 netns、
81 组 NAT、四个扩展拓扑、两种 IPv6 候选场景、32 组弱网、静态开机和 DHCP 两套 VM 均通过。
报告分别核对本地/Nix 二进制及各报告已记录的脚本来源，不把旧版本成功报告当作当前结果。

## 剩余完整交付

性能已有真实 TUN 初测入口 `make perf`：同机单 TCP 流、默认 FEC/RTX 与该构建的加密方式，
已增加逐项预热、重复测量、负载下 ICMP 分位数及限定 PID 的 perf 采样。
首处热点优化复用已验证成员身份，三轮同参数 IPv4 goodput 中位数从 122.2 提升至 138.1 Mbit/s，
接收端 CPU 中位数从 96.4% 降至 85.2%；见 [吞吐测量与热点优化](performance-baseline.md)。
这是单处优化的局部证据，不是完整吞吐验收或 IPv4/IPv6 性能比较结论。

1. **Exit Node 部署生命周期**：静态 networkd 开机及 DHCPv4/v6、IPv4 地址/网关更新已有 VM 验收；
   继续 NetworkManager、IPv6 动态前缀/多路由器、服务器长期离线租约到期、initrd 配网边界及更多主机策略组合。
   当前 `exit_state=active` 只表示覆盖网络路径和签名出口声明有效，尚无逐地址族外部健康诊断。
2. **NAT 和路径维护**：81 个同构/异构有序组合、双层 NAT 直连/中继与 hairpin 开关已有内核验收；
   原生 IPv6 状态过滤及有界候选切换也已有内核验收；接口事件驱动已接入；仍需更多双层/IPv6 拓扑、多失效候选调度、
   更大规模变更压力、连接回收与并发故障组合、跨分区恢复压力及外部网络验收。
3. **PMTU 扩展验收**：动态探测、IPv4 小 MTU、黑洞、方向不对称及恢复增大已实现；
   仍需多跳不同 MTU/高时延弱网组合、Subnet/Exit 外部 ICMP 错误传播及更多路径压力。
   当前支持 UDP payload 548–1232；不直接消费内核错误队列中的 PTB 数值。
4. **弱网和性能**：四种修复策略与八类基础内核故障已有双栈对照；仍需多 seed 重复、长时间持续限速、
   高时延/多跳与并发故障矩阵，以及限速过载下的修复效率与拥塞公平性调优。
   百进程基本控制面/加密路径已验证；千进程已有发现与换钥全通过的轮次，但也保留过初始回显超时；重复稳定性仍需验证。
   继续真实吞吐、PPS、CPU、尾延迟和大规模 TUN 运行，按测量优化热路径。
5. **健壮性**：更长时间的状态边界、握手洪泛/重放/畸形输入、重启与资源回收回归。
6. **完整需求复核**：成员撤销/本地封禁已接入 daemon；百节点实际分区合并地址收敛已验证；继续更大规模、反复分区及并发撤回/重放压力、
   relay 公平性与关闭收敛、重叠地址池的多实例隔离。不能以独立模型测试替代运行时与内核验收。

完成上述必要交付及对应验收之前，目标保持进行中。

### 稀疏反向反馈与空闲计时（d198 阶段）

该阶段 release 为 `d19834b409da734ff3fcd828bb18fa4b9067de2bd99c6594d25e174aa3c8ab13`。
修复完整 Link 层的稀疏反向流量退速：单个心跳不建立延迟趋势，FEC/RTX 不制造原始延迟置信度；
纯 ACK 队列没有反馈超时义务，空闲后的新源片重新开始等待计时。低速真实延迟趋势、
持续未确认数据的退速，以及原有 FEC/RTX/ACK/实例预算均有断言或保留回归。
增加降速原因计数和两类队列长度，不引入依赖、协议层或额外服务。

- fmt / Clippy / 111 项普通测试及 release 构建通过。
- 完整 Link 的 15 组虚拟时间诊断（三个 seed，0/30/100 ms 抖动、单向/稀疏反向/双向负载）
  排空后全部交付；`target/link-asymmetric-seeds.jsonl`。不是实际网络吞吐指标。
- 同版百进程通过：99 条必要边、全部发现/地址唯一、100 次端到端 8192 字节回显、双向 trace，
  约 65 s 稳态和全部进程回收；`target/daemon-scale-100-feedback-idle.json`。
  本轮合计 CPU 约 206.1%、RSS 约 732.8 MiB、最大 fd 12；和基础 netns 有并发，不做改动归因。
- 接口事件专项通过：17 个真实接口变化、合并/周期修复、子进程超时回收、双栈 TUN、无 daemon 重启；
  `target/e2e-feedback-interfaces.json`。
- 同版千进程仍未通过，180 s 后成员范围 276–999；全部进程已回收，零验签限流日志。
  原始负向证据和链路计数为 `target/daemon-scale-1000-feedback-idle.json`。
  不能宣称千节点支持、整体性能或完整目标已经验收。
- 九套基础 netns 同版复测全部完成并通过；报告为 `target/e2e-feedback-*.json`。
  `target/feedback-progress-audit.json` 核对阶段二进制、夹具及原始结果，保留千进程失败。
  阶段源码清单及归档为 `target/feedback-d198-source-sha256.json`、`target/feedback-source-snapshot/d198.tar.gz`；
  其后已继续修复 PMTU，因此此阶段证据不自动覆盖后续源码。

千节点失败及其诊断模型/CPU 采样的边界见 [规模测试](scale-testing.md)。

### 交叉换钥与空闲端到端密钥（ba256 阶段）

该阶段 release：`ba25617b338da1ecd68ac2f9833370e73117f4da5a5def95e46624d0b27ed3f9`。

- 修复交叉换钥时的 PMTU 探针误丢弃：回复有效保留接收世代的 Probe，旧世代 ACK 仍不改变当前路径。
  `status` 增加公开的 `key_epoch`，不暴露密钥材料。
- 修复端到端空闲后误清理对方仍使用的接收世代，以及空闲换钥时在途旧数据被提前拒绝。
  端到端保留到原有 300 s 硬期限，逐跳仍按 30 s 空闲回收；4/peer、8192/作用域、认证和防重放边界不变。
- fmt / Clippy / 114 项普通测试和 release 构建通过。
- 百进程经历 135 s 稳态与自然换钥：198 个有向世代全部变化、全部 PMTU 恢复到 1232；
  换钥前后各 100 次 8192 字节加密回显和各两条多跳 trace 均通过，全部进程回收。
- 四进程保持 315 s 应用空闲，跨过端到端密钥硬期限后再次完成全部加密回显、trace 及 PMTU 检查。
  两项报告分别为 `target/daemon-scale-100-end-idle.json`、`target/daemon-scale-4-hard-expiry.json`。
  它们是实际 daemon / UDP 检查，没有使用 TUN。
- 同版真实 Linux 双栈 TUN PMTU 专项通过，包括缩小/恢复、非对称黑洞、ICMP 过滤、完整隧道 MTU、
  16 KiB 加密回显、无 IP 分片及无重启；报告 `target/e2e-end-idle-pmtu.json`。
- 千进程仍失败：180 s 后成员范围 13–1000，全部进程回收；本轮有 3 份节点日志出现验签限流，
  不沿用此前零限流的结论。`target/daemon-scale-1000-crossed.json` 和只读检查点时间线
  `target/crossed-1000-discovery.jsonl` 保留证据。

`target/session-progress-audit.json` 校验该阶段构建、源码/夹具、换钥/硬期限/PMTU 正向证据及千进程负向证据，
明确 `thousand_processes_passed=false`。旧版百节点“世代变化但业务超时”的报告同样保留，未重写成成功。
九套基础 netns 的完整复测属于上一 d198 阶段；当前改动只引用明确对应本版的测试，不将历史结果改标为本版。
完整规模、性能和长期稳健性目标仍未完成。
