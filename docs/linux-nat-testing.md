# Linux NAT 验收

## 运行

```bash
nix develop --command make e2e-nat
# 9 × 9 有序组合；包括交换 A/B 角色后的异构 NAT
nix develop --command make e2e-nat-matrix
# 双层 NAT，以及共享外部地址的 hairpin 开启/关闭
nix develop --command make e2e-nat-topologies
# 仅运行端点相关过滤与恢复场景
nix develop --command python3 tests/e2e/nat_netns.py \
  --case eim-apdf --output target/e2e-nat-recovery.json
```

测试使用六个独立 namespace：终端 A/B、各自的 NAT 路由器 NA/NB、中继 R、路由核心 W。
A/B 使用**完全相同**的内网地址 `10.77.0.2:7331`；W 不路由这段内网。
A/B 只配置 R 的 UDP 地址和公钥，未配置对方公网候选，也没有固定中心发现服务。
实际候选来自已认证邻接的源地址观察和签名节点记录传播。

NAT 使用 Linux nftables / conntrack 实际转发，未在 daemon 中注入虚假的连接状态。
所有规则、conntrack 删除、转发 sysctl 和链路变化均限于本次创建的 namespace。
`conntrack-tools` 已加入 devShell；它仅供故障注入，不是 daemon 运行依赖。

## 映射与过滤分开验证

按 [RFC 4787](https://www.rfc-editor.org/rfc/rfc4787) 的术语分别构造：

- EIM：端点无关映射。
- ADM：地址相关映射。
- APDM：地址和端口相关映射。
- EIF / ADF / APDF：分别为端点无关、地址相关、地址和端口相关过滤。

先用普通 UDP 探针测量同源 socket 访问不同远端地址 / 端口时的实际映射，
再从原端点、同 IP 不同端口、不同 IP 发回数据，检查实际被允许的来源集合。
测试因此不只相信 nft 配置文本，也不会把端口保留误认为所有 NAT 都能穿透。
动态过滤集合有 30 s 有效期，只有内侧实际发包才刷新；没有永远打开的端口转发规则。
两端分别实测；探针结束后重建过滤集合并删除相应 UDP conntrack，再启动 daemon，
避免探针预先开放的权限使后续应用测试意外通过。

过滤集合在 postrouting / SNAT 之后按**实际线上源端口**刷新。回复由入站 DNAT 创建的连接时，
conntrack 的反向转换可以保留入站使用的端口，而不是新建出站流的分类端口。
之前夹具在 NAT 前按预测端口学习，在异构 EIF 场景中会维护错误的绑定；这次修正的是测试夹具，
不是给产品增加特殊 NAT 分支。

这是针对测试中有限远端地址/端口组合的确定性 NAT 模型，**不是所有商业 NAT 实现的模拟器**。
两端使用相同模型的九种组合已验证以下行为：

| 映射 | EIF | ADF | APDF |
|---|---|---|---|
| EIM | 直连 | 直连 | 直连 |
| ADM | 直连 | 中继 | 中继 |
| APDM | 直连 | 中继 | 中继 |

表中结果属于本测试拓扑，不代表任意同标签网络都保证相同结果。
每个场景先确认只有 A–R、B–R 邻接；发现信息本身不建立全连接。
产生实际端到端流量后，检查双方邻接状态与主动 trace：直连为 B，中继为 R/B。
同时验证双栈真实 TUN ICMP、2048 字节逐跳加密覆盖回显、合计邻居上限 2。
直连失败的组合持续尝试并保持多跳通信，不把失败当作 daemon 致命错误。

### 异构有序矩阵

`--case matrix` 枚举 81 组，包含 9 个同构和 72 个异构组合；也可以单独运行
`--case adm-eif+apdm-apdf`。两个模型的先后顺序分别对应 A、B。
预期路径在运行前由模型确定，不根据结果事后改写：

- 双方都是 EIM，或任一端采用 EIF，或任一端采用 EIM+ADF：预期直连。
- 其余组合：预期保留经过 R 的中继路径。

本轮 81 组全部通过：57 组实际直连，24 组保持实际中继；交换 A/B 角色后的结果一致。
候选调度变更后的完整复验仍为 57 组直连、24 组中继。
直连组首次观测为 89.2–782.9 ms，包含管理 RPC 与轮询开销；不是数据面时延。

这里的 EIF 入站请求可利用 conntrack 反向转换返回原公开端口；EIM+ADF 在联系对方 IP 后
可以接纳对方变化的源端口。该判定只适用于本夹具有限端点模型，不是公网 NAT 标签保证。
测试同时检查 A→B 与 B→A 的实际 trace、反向加密回显，以及 A/B 的 boot ID 未改变。
预期中继的场景持续通信至少 22 秒，覆盖多轮候选尝试；不把中继通信成功计作直连成功。

`ADM/EIF ↔ APDM/APDF` 两种角色顺序还会终止 R，在 NAT 学习之前丢弃后续发往 R 的重试，
然后持续双向加密回显 65 秒，超过 30 秒过滤集合与 60 秒签名记录有效期，再验证双栈 TUN。
这样排除“仍向离线 R 发包，顺带保活错误绑定”的测试假象；报告保留丢弃计数和实际存活端口。
完整矩阵中两种角色分别持续 65.16 / 65.21 秒，完成 113 / 114 轮双向加密回显。

保持产品二进制不变的夹具对照中，旧版本在 R 退出约 33.6 秒后回显超时：
conntrack 中 A 的实际入站端口仍为 40000，但过滤集合仅保留了错误的 40001。
修正后，同一角色组合在屏蔽 R 重试的条件下完成 65 秒持续双向回显与双栈 TUN 验证。
诊断原始记录为 `target/nat-legacy-binding-expiry.json`，正向对照为
`target/nat-binding-fixed-isolated.json`。这些是夹具回归证据，不是产品前后性能对比。

### 双层 NAT 与共享外部地址

`make e2e-nat-topologies` 使用独立拓扑，不以给单层模型换名字代替：

- `double-eim` / `double-apdm`：A/B 各自经过两台路由器，两个站点重复使用相同的终端及中间私网地址。
  内层按 conntrack 放行已联系端点，外层分别使用 EIM/APDF 或 APDM/APDF。
  测试预期前者直连、后者中继；逐层核对真实 daemon 会话的原始/回复 conntrack 元组，证明经过两次 SNAT。
- `hairpin-on` / `hairpin-off`：A/B 分处同一 NAT 的两个 LAN，外部地址相同、映射端口不同。
  普通 LAN 之间不转发；只有开启 hairpin 时才允许经过 DNAT 的跨 LAN 流量。
  独立 UDP 探针先测外部映射和回送能力，双方收到的源必须是外部映射而不是私网源，随后清空探针状态。
  开启时实际邻接端点必须是同一外部 IP 的不同端口；关闭时保留经 R 的路径。

四个场景都验证双向加密回显、双向双栈真实 TUN、主动 trace、邻居上限与 boot ID 不变。
报告为 `target/e2e-nat-topologies.json`，同样只在所有请求场景完成后置 `ok=true`。
这些测试不穷举两层每一级的全部映射组合，也不模拟 NAT64、任意商业 CGNAT 或互联网链路。

hairpin 的 LAN 地址互不相同，旧候选顺序先尝试被隔离的私网地址，持续 ping 时约 9 秒后才尝试外部地址。
当前采用有界交错尝试；单次请求也推进后续候选，三次 hairpin 复测约 1.05–1.07 秒。
失效路径不永久背景探测；更多失效候选与全局名额竞争仍待验收，见 [候选生命周期](candidate-lifecycle.md)。

### IPv6 底层发现与过滤

`make e2e-ipv6-discovery` 使用 A/B/R/W 四个 namespace。各节点公布本地 IPv4/IPv6，
但 W 实际丢弃所有跨网段 IPv4，A/B 的 IPv6 UDP 入站仅放行已经联系端点的 conntrack。
A/B 只填写 R 的 IPv6 地址与公钥；签名候选中的失效 IPv4 排在可用 IPv6 前面。

本轮已验证：单次加密请求后约 0.73 秒直连，实际邻接端点均为 IPv6；W 记录到 4 个失效 IPv4 尝试。
随后阻断 A/B 的 IPv6 直连，双向 trace 变为 R/B 与 R/A，双向双栈 TUN 和 8192 字节加密回显仍正常。
撤销阻断后恢复直接路径；终止 R 后无应用流量等待 65.07 秒，必要直连仍存在，再通过双向双栈业务与 trace。
所有阶段 A/B 的 boot ID 不变，邻居不超过 2。原始规则、路径及二进制/脚本摘要在
`target/e2e-ipv6-discovery.json`；这是原生 IPv6 有状态过滤，不将它称作 NAT66/NAT64 验收。

同一命令还运行 `--ipv4-mode delay`：IPv4 不丢弃，但两端 IPv4 UDP 各延迟 1500 ms，
IPv6 不附加延迟。单次请求约 0.73 秒选择 IPv6；随后保持两个候选路径开放 8 秒，
迟到的 IPv4 握手流量没有覆盖 IPv6 邻接。独立 IPv4 入站接受计数、双向 `ASSURED` conntrack
和零 netem 丢弃共同确认实际双向 UDP 交互，而不是把较慢候选偷偷变成黑洞。
之后才阻断 IPv4，隔离验证 IPv6 故障的中继回退/恢复以及 R 离线 65 秒后的必要连接保留。
报告为 `target/e2e-ipv6-delayed-candidate.json`；这不替代高 RTT 数据吞吐与所有并发候选组合的验收。

## 路径恢复

`eim-apdf` 另外覆盖：

1. WAN 阻断 A/B 间的底层流量，等待双方直连失效；trace 改为 R/B，8192 字节加密回显仍正常。
2. 撤去阻断，用户流量驱动直连重新建立。
3. NA 改变 SNAT 端口并删除本 namespace 中指定内侧源的 UDP conntrack；R 必须观察到经过认证的新端点。
   B 随后也必须通过新端点与 A 通信，不能只满足旧连接对象仍存在。
4. 终止引导中继 R，等待 A/B 的 R 邻接消失；A/B 保持直接加密通信、单跳 trace 和双栈 TUN ICMP。

删除连接状态的命令语义参考 [conntrack-tools 手册](https://conntrack-tools.netfilter.org/manual.html)。
NAT 规则使用 [nftables 原子事务和动态集合](https://netfilter.org/projects/nftables/manpage.html)。

## 证据与边界

`target/e2e-nat.json` 包含每个场景的实测映射、过滤集合、路径结果、回显次数和首次直连观测时间，
并记录二进制 / 测试脚本 SHA-256、内核版本及开始/结束时间。
失败不会保留上次运行的成功报告。
矩阵报告 `target/e2e-nat-matrix.json` 使用原子替换逐场景落盘；运行中与失败时 `ok=false`，
只有全部请求场景完成后才写入 `ok=true`。路径与预期不符时额外保存当前规则、conntrack 和节点状态。
首次直连时间包含测试轮询和管理 RPC 开销，不作为数据面延迟或公网性能指标。

本机对照发现：A/B 内网地址相同时，旧实现先向自身候选发起握手，三个 EIM 场景都等到约 9.3 s
才轮到有效公网候选。运行时现在过滤本机已知端点，且已直连时直接返回、不再复制候选列表；
同一测试的三种 EIM 首次直连观测分别为 87.1 / 88.7 / 98.1 ms。
测试设置宽松的 8 s 上限防止重新引入整轮自连接等待；这不是吞吐或互联网延迟 SLA。

候选替换/过期及连续 20 次真实 NAT 换端口另见 [候选生命周期](candidate-lifecycle.md)。
自动直连空闲回收与必要拓扑边保护另见 [邻居生命周期](neighbor-lifecycle.md)。

四个扩展拓扑、两种 IPv6 底层候选场景和异构 81 组均已在当前二进制上通过。
当前仍待补齐：更多双层/IPv6 拓扑、事件驱动、多失效候选调度和更大规模候选变更压力、
持续分区合并压力、回收与并发故障组合、真实外部网络验收。
这些工作和动态 PMTU、弱网/性能验收独立，当前 NAT 测试通过不等于完整产品交付。
