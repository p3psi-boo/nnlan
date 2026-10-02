# 吞吐测量与热点优化

本页保留历史构建的测量结果；当前 GGB3 已取消双层加密，
变更与新构建验证见 [单层逐跳加密](hop-encryption.md)。

最新同机 WireGuard / wireguard-go 及有延迟链路对照见 [数据面对照](performance-comparison.md)。

```bash
nix develop --command make perf
# 每项独立预热，轮换顺序重复测量：
nix develop --command python3 tests/perf/throughput.py --warmup 15 --seconds 30 --repeats 3
# 只采样本次两个 daemon，不修改宿主机 perf/sysctl 策略：
nix develop --command bash -c 'python3 tests/perf/throughput.py --case overlay_ipv4 --repeats 1 --seconds 20 --perf "$(command -v perf)" --output target/perf-profile.json'
```

两个独立 daemon、真实 Linux TUN 和 veth，单条 TCP 流；覆盖物理直连、覆盖 IPv4、IPv6 与反向 IPv4。
默认每项预热 15 秒、测量 10 秒，重复三轮并轮换顺序；各项仍共享会话状态，预热不是冷启动测试。
需要 root 或无交互 sudo，仅修改本次创建的 namespace，不修改宿主机路由或防火墙。
不关闭 FEC、有限 RTX 或该构建默认的加密；历史双层与当前 GGB3 单层按二进制区分。
保存 iperf 原始 JSON、应用接收吞吐、两端 daemon 的
进程 CPU 时间增量，以及各阶段前后的链路统计、boot ID、源码和二进制摘要。
测量期间同步发送 50 包/秒 ICMP，保存原始回复/丢包统计及成功回复的 RTT p50/p99/p99.9；
短测量的 p99.9 接近最大样本，只作描述，不代表可靠的尾延迟 SLA。
报告先写 `complete=false`，每项原子保存，全部结束及清理后才标记 `complete=true`。

`target/perf-throughput.json` 是测量结果，不是 pass/fail 门槛。CPU 百分比以一个逻辑核为 100%，
不是整台主机 CPU 百分比；不把线上冗余、反馈或重复发送的字节计入应用 goodput。

## 第一组实测

2026-09-20，Xeon Gold 5218 @ 2.30 GHz、Linux 6.18.46，同机隔离 namespace，每项 10 秒：

| 顺序 | 接收 goodput | daemon A CPU | daemon B CPU |
|---|---:|---:|---:|
| 物理 IPv4 | 21.86 Gbit/s | 1.6% | 1.6% |
| 覆盖 IPv4 | 50.6 Mbit/s | 39.5% | 38.9% |
| 覆盖 IPv6 | 126.0 Mbit/s | 95.2% | 95.4% |
| 覆盖 IPv4 反向 | 126.0 Mbit/s | 95.6% | 95.2% |

本次 release：`aee21a4ca92177a0467f4b92242602ecedea1ee0afd22707e6e8d506d9438f32`。
第三项发送侧逐跳 UDP 约 33 kpacket/s、209 Mbit/s；这是协议统计，不是接口抓包的独立测量。
其控制器速率上限已达到配置的 1 Gbit/s，而两端 CPU 接近一个核。下一步先做 CPU 热点剖析，
再测批处理、分片/FEC 和加密热路径，不能只提高带宽配置就声称解决吞吐限制。

这几项共享同一组会话和控制器，没有独立预热、CPU 绑定或随机化试验顺序；第一项覆盖流与后续热状态不同，
所以不能将 50.6 对 126.0 的差异归因于 IPv4/IPv6。主机同时运行邻居生命周期功能测试，结果不是独占机器验收。
物理测试可使用内核卸载，不能将其吞吐直接作为当前用户态封包方案的同成本目标。

已有预热、重复测量和负载下 ICMP 分位数；仍需 CPU 绑定/独占环境、冷启动分组、
更充分的尾延迟样本、PPS/UDP、内存、长流/短流、公平性、
多跳/并发节点与弱网矩阵，以及 FEC/RTX 逐项开关对照。当前测量只建立可复现起点，未满足完整性能要求。

## 第一处证据驱动优化：身份解析

`perf` 仅采样本次两个 daemon 的 PID（`cpu-clock` / 199 Hz / DWARF 4096），
修改前 Envelope 解码及其子调用约占 CPU 样本 15.15%，其中 Ed25519 点解压的 `pow2k`
自身约占 9.93%。已验证成员公钥原本在每个数据包中重复解压。

现按完整字节在既有成员集合查询已验证 `NodeId`，未命中仍进行严格校验，不引入无界缓存、
不跳过成员资格或密码认证。优化后同范围采样未再观察到该点解压热点；
主要成本仍包括逐包 socket 系统调用、链路轮询、加密与 FEC，仍需继续优化。

### 同参数前后对照

2026-09-20，沿用上述 CPU/内核；构建完成后依次运行旧/新二进制，每个版本三个 IPv4 单 TCP 流试验，
每项预热 15 秒、正式测量 15 秒。对照测量不启用 perf，采样另跑；没有同时运行本项目编译、
netns 回归或 VM，但主机未独占、未绑核，不能推断所有机器和网络都提升相同比例。

| 三轮结果 | 优化前 | 优化后 |
|---|---:|---:|
| goodput 中位数 | 122.22 Mbit/s | 138.13 Mbit/s |
| goodput 范围 | 119.68–126.41 Mbit/s | 137.87–139.34 Mbit/s |
| daemon A CPU 中位数 | 92.90% | 92.55% |
| daemon B CPU 中位数 | 96.39% | 85.17% |
| 各轮 RTT p50 的中位数 | 10.80 ms | 9.65 ms |
| 各轮 RTT p99 的中位数 | 17.30 ms | 14.80 ms |
| 各轮 RTT p99.9 的中位数 | 19.90 ms | 16.70 ms |

本组 goodput 中位数提高约 13.0%。每轮收到 750 个 ICMP 回复；表中分位数是**各轮分位数的中位数**，
不是合并全部样本后的分位数。六轮均有实际 FEC 发送，测量窗口内 RTX 和发送队列丢弃增量均为 0；
无损链路没有触发 RTX 不等于关闭重传。加密、FEC、重传、速率参数均未变化。

证据文件：

- `target/perf-ab-before-clean.json`：旧二进制 `aee21a4ca92177a0467f4b92242602ecedea1ee0afd22707e6e8d506d9438f32`。
- `target/perf-ab-after.json`：新二进制 `8c785b9b447d1fa90310c93172c9ab5ba0e5e5039c450abd6bca9fd7ec57796f`。
- 两者测试脚本摘要均为 `e038ddbf9832752a9cb085e112849f29c0f8b93fe1409a5ec40a8d6eec8c2b4a`。
- `target/perf-profile-before.json` / `target/perf-profile-after.json` 及各自 `.perf.data` 为独立的 20 秒采样试验。
- `target/perf-opt-check.log`：fmt、Clippy、92 项普通测试及 release 构建通过。
- `target/perf-opt-e2e.log`：九套真实 netns 回归通过；`target/perf-opt-boot.log`、
  `target/perf-opt-dhcp.log`：静态开机与 DHCP 两套真实 VM 回归通过。
  `target/perf-opt-audit.json` 核对本地/Nix 两种二进制与报告来源，未将旧产物当作此次验收。

这是单处热点优化的实测收益，不是完整吞吐、低延迟或弱网性能验收。

## 弱网控制器修复后的复测

增加独立修复策略，并修复重试调度和低速恢复后，在所有网络/VM 回归结束后重新运行：

```bash
nix develop --command python3 tests/perf/throughput.py --case overlay_ipv4 --repeats 3 --seconds 15 --output target/repair-perf.json
```

本次默认双开修复、每项预热 15 秒；二进制摘要为
`f96a7889395ed72c58e50e9d4511b98cc765026b2cd1d45bddb0fccbd5445d02`。
三轮 goodput 为 138.80 / 137.85 / 134.30 Mbit/s，中位数 137.85 Mbit/s；
A / B CPU 中位数为 93.21% / 83.64%。各轮 RTT 分位数的中位数为 p50 9.07 ms、p99 13.70 ms、p99.9 17.00 ms，
各有 750 个 ICMP 回复。三轮都有实际 FEC 发送，测量窗口内 RTX 和发送队列丢弃增量均为零。

此轮热状态吞吐仍约 138 Mbit/s；不是宣称吞吐进一步提高，亦不把三次短测当作所有场景的性能验收。
弱网问题、32 组结果及限制见 [弱网矩阵](weak-network-testing.md)。

## 有界候选调度后的数据面复测

候选建立改为有界交错尝试后，待所有 netns / VM 回归结束，再以相同预热和采样参数运行：

```bash
nix develop --command python3 tests/perf/throughput.py --case overlay_ipv4 --repeats 3 --seconds 15 --output target/candidate-race-perf.json
```

当前二进制 `cd3969fc14096e5e3a020cead7608cf159e31ac88dfd8faa5f84a3211d02472e`，
三轮 goodput 为 136.65 / 134.14 / 140.65 Mbit/s，中位数 136.65 Mbit/s。
A / B CPU 中位数为 94.01% / 81.37%；各轮 RTT 分位数的中位数为 p50 10.10 ms、p99 14.30 ms、p99.9 19.10 ms。
每轮有 750 个 ICMP 回复；FEC 实际启用，测量窗口内 RTX 与发送队列丢弃增量均为零。

此次收益是候选建立与自动推进，不宣称稳态吞吐提升；三次短测也不构成所有数据面场景的性能验收。


## 反馈轮转版本的完整轮换采样

二进制 `353e1107fa3a85d4629a7bfdfefafd9fc1a5cc1decd5be7933aab100e6249510`：

```bash
nix develop --command python3 tests/perf/throughput.py --binary target/ggbond-fair-feedback --case all --seconds 10 --warmup 15 --repeats 3 --output target/perf-fair-feedback.json
```

同一对真实 daemon/TUN 持续运行，四种路径按轮次交错测量，不在每个试验前重启。
每项预热 15 s、测量 10 s，默认 FEC+RTX，单 TCP 流并发 50 ICMP/s；共 12 项完成。
原始 `iperf3`、测量前后状态与 ICMP 回复保存在 `target/perf-fair-feedback.json`，
统计摘要在 `target/perf-fair-feedback-summary.json`。
测量与基础 netns、弱网功能回归重叠，千节点进程已结束；没有绑核或独占主机，
没有同条件旧版 A/B，不把它写成单项优化的因果收益。

| 路径 | 三轮 goodput（Mbit/s） | 三轮 ICMP 回复 / 每轮发送 500 |
|---|---|---|
| 底层 IPv4 veth | 21926.79 / 21856.93 / 21869.74 | 500 / 500 / 500 |
| 隧道 IPv4 | 181.05 / 64.66 / 180.96 | 500 / 490 / 500 |
| 隧道 IPv6 | 177.41 / 11.11 / 11.95 | 500 / 460 / 462 |
| 隧道 IPv4 反向 | 182.75 / 12.06 / 137.99 | 500 / 462 / 500 |

底层是同机 veth，不是物理网卡测速。**整个性能目标仍未完成**；
报告的 `complete=true` 只表示采样执行完毕，不表示延迟、吞吐或丢包达到验收标准。
不从这些数据只摘取首轮约 180 Mbit/s 的结果，也不将低吞吐归因为 IPv6：反向 IPv4 同样受影响。

首轮隧道试验双方使用相同活动世代。第二轮 IPv4 测量期间发生自然换钥；
之后低速窗口中两端使用不同活动世代，PMTU 均为 1232、BWE 报告 1 Gbit/s，
发送侧的 Engine 丢弃和源片缓存过期计数持续增加，实际 goodput 仅约 11–12 Mbit/s。
下一次双方活动世代相同后业务恢复到约 138–181 Mbit/s。
这是状态与吞吐退化的相关证据，还需要高负载交叉换钥专项复现和逐方向反馈计量。
少量换钥后 echo 通过，并不能证明持续大流量换钥没有问题。


## 接收额度修正与强制交叉换钥回归

release `cd25cb49ad69d1a897aaf165f9df57276686dfc243193c05e5070fd27f189abc`。
先用完整 Link 模型确认：反向只有反馈、没有可获得 ACK 的业务源片时，
旧的发送 BWE 比例限制会使反馈排队、源缓存占满。保持发送/接收/缓存期限和总 pacer 不变，
加入已认证数据接收产生的有界反馈额度后，31,000 条消息全交付、零拒绝、零缓存过期；
未修正时拒绝 10,288 条、368 个源片过期。这不是仅靠 echo 成功推断高吞吐可用。

### 真实 TUN 的确定性交叉场景

```bash
nix develop --command make perf-crossed-rekey
```

新增 `tests/perf/crossed_rekey.py` 复用既有 netns 和吞吐测量器。
初始握手、PMTU 与高负载基线建立后，只对 LINK 的 HS1/HS2/HS3 延迟 100 ms，
业务密文不进入延迟队列；实际等待原有 120 s 自动换钥，不新增 daemon 测试后门或修改计时常量。
选择器显式检查 IPv4 IHL、UDP 端口、GGB1、kind 和 scope；
语法依据 [tc-u32](https://man7.org/linux/man-pages/man8/tc-u32.8.html) 与
[tc-prio](https://man7.org/linux/man-pages/man8/tc-prio.8.html)。

夹具要求双方使用不同的新活动世代、PMTU 1232、无进程重启；
随后 IPv4、IPv6、反向 IPv4 各预热 15 s、测量 10 s，整个测量保持这两个交叉世代。
每项 goodput 至少保留本机基线的一半，并收到全部 500 个负载中 ICMP 回复；
这是防止持续崩塌的回归门槛，不是整个产品性能目标。

| 同一夹具 | 353e 修正前 | cd25 修正后 |
|---|---:|---:|
| 换钥前 IPv4 基线 | 180.06 Mbit/s | 183.11 Mbit/s |
| 交叉世代 IPv4 | 11.8 Mbit/s，464/500 回复，失败 | 174.4 Mbit/s，500/500 回复 |
| 交叉世代 IPv6 | 前一项失败，未执行 | 171.5 Mbit/s，500/500 回复 |
| 交叉世代 IPv4 反向 | 前一项失败，未执行 | 175.0 Mbit/s，500/500 回复 |

报告 `target/crossed-load-fair-feedback-before.json`、`target/crossed-load-receive-credit.json`
包含相同夹具摘要、基线、世代观测及实际应用流量。新版两个方向的 netem 队列各计数 3 包，
验证延迟确实作用于握手而非大流量数据。旧版报告保留原始断言失败，不改写为通过。
两轮时间有重叠，另有基础功能回归运行；未绑核或独占主机，不声称统计意义上的吞吐提升百分比。

### 普通连续采样仍揭示换钥瞬态

另完成同一对 daemon 的 12 项轮换采样（每项预热 15 s、测量 10 s，三轮），
`target/perf-receive-credit.json` 与 `target/perf-receive-credit-summary.json`：

| 路径 | 三轮 goodput（Mbit/s） | ICMP 回复 / 每轮 500 |
|---|---|---|
| 底层 IPv4 veth | 21853.35 / 21889.96 / 21829.04 | 500 / 500 / 500 |
| 隧道 IPv4 | 182.28 / 74.49 / 175.44 | 500 / 497 / 500 |
| 隧道 IPv6 | 178.18 / 177.34 / 178.79 | 500 / 500 / 500 |
| 隧道 IPv4 反向 | 183.90 / 184.74 / 131.59 | 500 / 500 / 500 |

第二轮 IPv4 跨过一次换钥，RTT p99 249 ms 且少 3 个回复。
最后一轮反向 IPv4 与 IPv4 结束时实际已使用不同活动世代，未重现上一版持续约 12 Mbit/s 的状态，
但不把专项中的换钥后预热窗口用来掩盖切换瞬间的损失。瞬态、尾延迟和千节点排队问题仍需修复，
完整吞吐/延迟/CPU/PPS、公平性与长期稳定性目标尚未完成。

## 同路径 PMTU 保留与换钥瞬态采样

release `79ad056ec8188a81663a935ec06e221ef2038a24b8769fa7a2e28731f4ff6d44`。
运行 `make perf-rekey-transition`，在高负载基线之后保持 TCP 和 50 ICMP/s 连续 120 s，
实际跨过生产环境 120 s 换钥。每约 0.2 s 读取两端状态，保存完整 iperf 每秒区间、
带时间戳的 ping 输出和所有状态；没有把切换后的恢复期计入排除窗口。
随后仍执行 IPv4、IPv6、反向 IPv4 三项稳定交叉世代回归。

| 指标 | cd25：修正前 | 79ad：保留 PMTU |
|---|---:|---:|
| 连续负载中观测到的最小 UDP payload | 548 | 1232 |
| 连续负载 ICMP 回复 | 6000/6000 | **5998/6000** |
| RTT p99 / p99.9（ms） | 20.5 / 202 | 25.1 / 243 |
| 120 s TCP goodput（Mbit/s） | 164.55 | 164.90 |
| TCP 重传 | 151 | 289 |
| 后续 IPv4 / IPv6 / 反向 IPv4（Mbit/s） | 175.51 / 172.57 / 175.10 | 175.31 / 172.04 / 177.41 |

三项后续测量两版均收到每项全部 500 个回复，且保持不同的活动发送世代。
两个完整专项报告均为失败：旧版因 PMTU 退回，新版因切换负载中缺失回复，未放宽门槛。
报告 `target/crossed-transition-before-mtu-retention.json`、`target/crossed-transition-mtu-retention.json`。
两轮顺序执行、未并发本项目的其他网络测试；旧版前段与 release 构建有重叠，
没有绑核、重复统计或物理链路，不根据一次测量声称吞吐/丢包改善或恶化的因果关系。

新版换钥采样提供下一步诊断依据：A 在切换前 BWE 为 1 Gbit/s、burst 64000；
新活动世代立即变成 8.1 Mbit/s、burst 2400。随后同一新世代排队 417221 字节，
未首次发送源片丢弃从 0 增至 117，而 PMTU 始终为 1232。
详见 `target/mtu-retention-transition-summary.json`，不跨世代相减 Link 累计计数。
路径带宽/整形状态与密钥世代的隔离方式仍需修复；不能靠提高初始速率、放大队列寿命、
复制多份路径预算或删除 FEC 来掩盖。千节点与整体性能验收仍未通过。

## 单路径控制器，独立密钥时钟

release `1687a132645fa7662127ad827ac160ef22d88bbf43a7ae738554d4d7e283dab3`。
将 BWE、pacer 和修复账本移至相邻路径后，再用同一 `--transition` 夹具运行：

- 基线 181.18 Mbit/s；连续 120 s TCP 为 174.27 Mbit/s，108 次 TCP 重传。
- 连续 ICMP **5997/6000**，RTT p50 / p99 / p99.9 为 10.4 / 14.9 / 17.4 ms。
- 换钥后 IPv4 / IPv6 / 反向 IPv4 为 177.17 / 172.83 / 176.58 Mbit/s，各 500 个回复全部收到。
- 两端仍保持不同的新活动世代；PMTU 最小采样值 1232，两个 netem 队列均仅延迟 3 个握手包。
- 换钥前后实际状态均为 BWE 1 Gbit/s、burst 64000；所有连续状态采样的未首次发送源片丢弃为 0。
  这不等于实际吞吐达到 1 Gbit/s，也不证明采样之间和非活动世代绝无丢弃。

原始报告 `target/crossed-transition-shared-path.json`；摘要
`target/shared-path-transition-summary.json`。本轮没有其他项目网络压测或编译同时运行，
仍为同机 veth/TUN、未绑核的一次采样，不外推物理网卡、多跳吞吐或长期尾延迟。

专项整体仍失败，没有降低全部回复的门槛。缺失序号 4677–4679 位于实际换钥窗口；
同期两端 invalid UDP 从 0 分别增至 128 / 718，详见
`target/shared-path-transition-rejections.json`。继续使用真实 UDP 暂存最后一趟 HS3：
旧密钥在双方仍有效，新世代在对端尚处于 pending；暂存期间业务交付 0，释放后新业务交付 1，
暂存期间拒绝 4 个报文。`target/late-hs3-before.log` 保留失败断言与恢复检查。
这为下一步的远端密钥就绪确认提供独立复现，不把路径估计修正等同于无损换钥。


## GGB2 远端就绪确认后的连续换钥

release `28e5b50b2d0cd0140bbf0b2ea2ea50c91da83eed88fdd88798a568a6ead9e71e`。
`target/crossed-transition-key-ready.json` 完整专项通过：

| 指标 | 本次结果 |
|---|---:|
| 基线 TCP（Mbit/s） | 182.21 |
| 连续 120 s TCP（Mbit/s） | 172.77 |
| 连续 ICMP | 6000/6000 |
| RTT p50 / p99 / p99.9（ms） | 9.95 / 14.6 / 16.1 |
| TCP 重传 | 0 |
| 换钥后 IPv4 / IPv6 / 反向 IPv4（Mbit/s） | 175.64 / 170.89 / 176.58 |

后三项分别 500/500 回复，全程保持不同的新发送世代；两端各恰有 3 个握手报文进入
100 ms 延迟队列。状态采样中 PMTU 最小值 1232；摘要见 `target/key-ready-transition-summary.json`。

该历史轮次夹具新增 `--wire-version {1,2}`，当时默认 2，让 tc 选择器匹配实际 GGB2。
当前夹具已支持 `{1,2,3}`，默认 3；测 GGB2 存档须显式传 `--wire-version 2`。
运行旧 GGB1 存档时必须显式传 `--wire-version 1`；kind/scope/端口/IHL 的匹配、
仅延迟 HS1/HS2/HS3、全部回复、吞吐比例、PMTU 和交叉世代门槛均未放宽。
当前夹具和二进制 SHA 随报告记录，不声称与旧报告的夹具字节完全相同。

本次没有其他本项目网络负载或编译并发，仍只是未绑核的同机 veth/TUN 单轮，
不外推物理网卡、多跳、拥塞公平性、PPS、规模或长期尾延迟。
旧版 5997/6000 失败证据保留；本次通过与确定性 HS3 暂存回归共同验证就绪修正，
不据此宣称所有丢包、退速和换钥场景已解决。

## nnlan：1000 Mbit/s Underlay 整形对照

2026-09-22，当前 release `f6351f9d6f7e628e8871f78afdfc0fb64c9f2eace58ee2b207b6f75d37223355`。
两台隔离 namespace 中的真实 daemon/TUN，Xeon Gold 5218 @ 2.30 GHz、Linux 6.18.46。
两端 veth WAN egress 都使用 TBF 1000 Mbit/s、625000 字节 burst、20 ms latency，
原始报告保存安装参数及每项测量前后 `tc -s -j` 计数，不修改宿主机接口或全局参数。

```bash
nix develop --command make perf-gigabit
# 等价的测量命令，不重新编译：
nix develop --command python3 tests/perf/throughput.py \
  --binary target/release/nnlan --underlay-mbps 1000 \
  --warmup 10 --seconds 15 --repeats 3 \
  --output target/perf-nnlan-underlay-1000.json
```

保持默认端到端/逐跳加密、FEC 和有限 RTX；单 TCP 流，并发 50 ICMP/s。
各项先预热 10 s、正式测量 15 s，三轮交错顺序；同一对 daemon 不在每轮重新启动。
没有并行运行本项目编译或其他网络压测；主机未独占、未绑核。
这是同机虚拟链路整形，不是两台物理千兆网卡的验收，也不代表多跳、百节点并发或公网弱网结果。

| 路径 | 三轮接收 goodput（Mbit/s） | 中位数（Mbit/s） | 各轮 RTT p99 的中位数（ms） |
|---|---|---:|---:|
| Underlay IPv4 | 956.61 / 956.55 / 956.63 | 956.61 | 1.10 |
| nnlan IPv4 | 178.45 / 176.74 / 178.43 | 178.43 | 14.90 |
| nnlan IPv6 | 173.24 / 171.94 / 173.04 | 173.04 | 15.40 |
| nnlan IPv4 反向 | 181.40 / 181.47 / 179.72 | 181.40 | 14.60 |

IPv4 goodput 为底层 IPv4 对照的 **18.65%**，约 **22.30 MB/s**，尚未接近千兆满速。
12 项各收到 750/750 个 ICMP 回复；iperf 的 TCP 重传计数和双端 TBF drop 增量均为 0。
不能据此推广到长期或所有网络无丢包。

IPv4 正向两端 daemon CPU 中位数为 80.53% / 70.80%，100% 代表一个逻辑核，
不包括 iperf 或系统整体 CPU。对应正向 WAN 的 qdisc 字节计数约 289.22 Mbit/s，反向约 42.08 Mbit/s；
底层对照正向计数约 998.90 Mbit/s。这些是内核 qdisc 计数，不是物理线上独立抓包。
覆盖网络没有耗尽 1000 Mbit/s 的整形预算，但本次未采 perf，不将限速之外的瓶颈进一步归因到某个函数。
下一步需要针对数据面处理、调度和反馈进行剖析，不能把差额全部解释成加密/FEC 的带宽开销。

原始报告：`target/perf-nnlan-underlay-1000.json`；
统计摘要：`target/perf-nnlan-underlay-1000-summary.json`；
日志：`target/perf-nnlan-underlay-1000.log`。
报告含二进制/夹具/helper SHA、完整 iperf、逐轮状态、CPU 与 ping 原始输出；`complete=true` 在 namespace 清理后写入。

## nnlan：加密 / 发送热路径优化首轮（PMTU 回归暴露问题）

2026-09-22，release `365eb68dfbb6d7d9666b7d24134c472e744c3e4f887fca6e2773d438aad0fc65`。
相对上一节 `f6351f9…`，没有改变握手协议、身份、密钥格式、nonce、防重放、
端到端/逐跳加密、FEC / 有限 RTX、1280 TUN MTU 或 1232 最大 UDP payload。

### 改动与边界

- 启用 Snow 的 `ring-accelerated`，保留相同 ChaChaPoly 算法和字节格式；
  默认 provider 与 ring 的多长度/nonce/AAD 互解及篡改拒绝测试验证兼容。
  该 feature 在可用时选取 ring 实现，未自行实现加密算法。
  参见 [Snow 0.10 文档](https://docs.rs/snow/0.10.0/snow/)。
- 密文直接写入最终发送缓冲区，移除每次加密后的额外分配和复制；
  公平轮询改用 `poll_one`，不再为一个返回包创建临时 `Vec<Vec<u8>>`。
- 只合并已经通过全局/路径 pacer 的连续 UDP 包，最多 32 包。
  用 `sendmsg` + `UDP_SEGMENT`，保留端点、源地址 affinity、独立密文和 nonce；
  不填充、不重排，不改变接收方格式。同批只能同端点/源地址、等长分段，最后一段可较短。
  GSO 不支持时退回普通逐包发送，PMTU/DHCP 错误仍按原路径处理，不重复扣费或重发成功前缀。
  这是分成独立 UDP 数据报，不是 IP 分片；见 [Linux 分段卸载文档](https://docs.kernel.org/networking/segmentation-offloads.html)。
  未添加 `unsafe`，没有启用 GRO，也没有增大 socket 接收报文上限。
- 在 I/O 进展后按至少 250 µs 间隔排空已就绪数据，保留原有 1 ms 维护 tick，空闲时不忙轮询。
  链路缓存维护最多每毫秒一次，发送仍检查队列截止时间。
  全局 64000 字节 burst、逐路径限制、有限队列和每次最多 256 轮公平调度不变；
  新测试验证同一时刻重复 flush 不产生额外令牌。

### 同条件三轮测量

```bash
nix develop --command python3 tests/perf/throughput.py \
  --binary target/release/nnlan --underlay-mbps 1000 \
  --warmup 10 --seconds 15 --repeats 3 \
  --output target/perf-nnlan-optimized-1000.json
```

与上一节使用相同硬件、夹具、双端 TBF、默认配置、预热/测量时长及轮换顺序。
测量期间没有本项目并行编译或其他压测；仍是未绑核、未独占主机的同机 veth/TUN。

| 路径 | 优化后三轮 goodput（Mbit/s） | 优化前中位数 | 优化后中位数 | 各轮 RTT p99 中位数：前 → 后（ms） |
|---|---|---:|---:|---:|
| Underlay IPv4 | 956.63 / 956.55 / 956.63 | 956.61 | 956.63 | 1.10 → 1.10 |
| nnlan IPv4 | 287.58 / 286.11 / 287.30 | 178.43 | 287.30 | 14.90 → 9.77 |
| nnlan IPv6 | 280.99 / 277.32 / 280.69 | 173.04 | 280.69 | 15.40 → 9.67 |
| nnlan IPv4 反向 | 283.53 / 284.02 / 282.90 | 181.40 | 283.53 | 14.60 → 9.22 |

IPv4 相对原基线提升 **61.0%**，约 **35.9 MB/s**，是本次底层对照 goodput 的 **30.0%**。
两端 daemon CPU 中位数 76.02% / 71.70%（一个逻辑核为 100%）。
12 项均为 750/750 ICMP 回复，TCP 重传计数及双端 TBF drop 增量均为零。
这是一次组合优化的前后测量，不把总收益归因于某一个改动，也不声称千兆性能目标完成。

原始报告 `target/perf-nnlan-optimized-1000.json`，摘要
`target/perf-nnlan-optimized-1000-summary.json`，日志 `target/perf-nnlan-optimized-1000.log`。
开发过程中 `batch` / `ring` / `pump` 原型的短测量不作为该轮矩阵证据；矩阵对应的发送实现是 UDP GSO，
不是早期 `sendmmsg` 原型。后续应继续测量逐包接收/TUN 处理、分片和反馈成本，
而不是关闭 FEC 或取消一层加密来提高数字。

随后重跑归档旧版 `target/nnlan-perf-before`，IPv4 同参数三轮为 181.42 / 180.20 / 181.29 Mbit/s，
中位数 181.29 Mbit/s，RTT p99 中位数 15.2 ms；相对此次旧版复查，新版提升约 58.5%。
三轮各 750/750 回复，原始报告 `target/perf-nnlan-before-recheck.json`，摘要一并保存。
复查只跑 IPv4，未把它当成完整四路径轮换矩阵；它与主测试串行执行。

### 首轮版本热点复查

首轮 release 单独做 15 s 预热、20 s 测量，`perf cpu-clock` 199 Hz，仅采样两个 fixture daemon，
没有与编译或其他网络回归并发。该采样轮 goodput 288.13 Mbit/s，只用于定位，不混入上表。
约 6K 样本、lost samples 0；累计调用栈中 `sendmsg` 约 26.4%、TUN 写入约 15.8%、
加密/解密分别约 8.1% / 9.2%，FEC 编码自身约 3.9%。这些栈比例有包含关系，需避免逐项相加。
样本中确实出现 ring 的 AVX2 ChaCha20-Poly1305 seal/open，而非仅从配置推断加速已生效。

发送与 TUN 的逐包处理仍有显著成本；当前没有实现 TUN GSO/GRO 或批量 UDP 接收。
这只是下一轮优化的测量依据，不把同机内核栈占比外推为所有物理网络的瓶颈。
报告与原始采样为 `target/perf-nnlan-profile-final.json`、
`target/perf-nnlan-profile-final.0.overlay_ipv4.perf.data`；
`target/perf-nnlan-profile-final-{flat,callers}.txt` 保存函数及调用链报告。

### PMTU 回归与修正边界

上述 `365eb68…` 在真实 PMTU 回归的 `asymmetric_silent_blackhole` 阶段失败：
双向单包探测已收敛到约 868 / 666 字节，但 16 KiB 加密回显超时。
失败日志和状态保留在 `target/perf-gso-stage-regression/pmtu.log` 和
`target/perf-gso-stage-regression/pmtu-failure.json`；没有把该轮性能数字当成功能验收。
虚拟路由器的 `meta length` 规则能在 GSO 分段前看到聚合 skb，单包探测成功并不验证这个聚合路径。

修正为仅在该发送方向的 PMTU 达到实现上限 1232 时允许 GSO；小 MTU 方向逐包发送，
不牵连其他已验证方向、不修改协议、不放宽 fixture 的长度限制或回显门槛。
新增发送测试覆盖同一批中不允许 GSO 的边界，确保不会被前一包合并带入。
该修正版为 `175837ff851aed5362b5a7b49ce779abae4fbf002dbaaaa95f2aa27568a2fa45`，
需要以其独立回归和复测结果判断交付状态。

### 修正版回归（175837f 阶段）

- fmt、Clippy（`-D warnings`）、158 项 Rust 普通测试和 9 项 Python 测试通过。
  默认忽略的真实内核路由测试另在隔离 namespace 内通过；Nix 包构建及其测试通过。
- 完整重跑 PMTU、多跳/IPv4 碰撞、成员信任/封禁、Subnet Router、Exit Node、
  原生 IPv6 发现和 DHCP 策略七套内核场景，均通过。PMTU 同时覆盖最小 IPv4/IPv6 MTU、
  非对称黑洞、ICMP 过滤、增长恢复、双向完整 TUN MTU 和 16 KiB 加密回显，未放宽断言。
- 4 种 FEC/RTX 策略 × 8 种弱网，共 32 组均通过既定门槛。
  默认 FEC+RTX 的限速过载场景仍有丢包：IPv4 308/400、IPv6 133/400；
  其余七种默认策略场景均为每族 400/400。这是有限队列/修复的功能回归，不是任意负载下无损。
- 自然 120 s 换钥时持续 TCP+ICMP：6000/6000 回复，观测 PMTU 最低 1232；
  强制双向不同活动世代后，IPv4/IPv6/反向 IPv4 各 500/500 回复，吞吐分别
  280.93 / 275.72 / 278.69 Mbit/s。该专项不使用千兆 TBF，不混入千兆对照统计。
- 与归档旧版双向 16 KiB 加密回显、trace、身份与地址一致性通过。

日志及原始报告位于 `target/perf-regression/`，总日志为 `target/perf-regression.log`；
普通测试日志 `target/perf-pmtu-check.log`，补充测试 `target/perf-final-extra-check.log`，
Nix 日志 `target/perf-nix-build.log`。基础内核场景与 Nix 构建并行；
弱网、换钥和随后千兆复测时 Nix 构建已结束，没有其他本项目压测并发。
首轮失败与中止的旧版弱网结果保留于 `target/perf-gso-stage-regression/`，未改标成通过。
本轮未重跑百/千节点或开机 VM；此次吞吐提升不替代规模和长期稳定性验收。

## nnlan：修正版千兆复测（本轮交付）

最终 release：`175837ff851aed5362b5a7b49ce779abae4fbf002dbaaaa95f2aa27568a2fa45`。
上面的 PMTU 修正、七套内核场景、32 组弱网、持续换钥及兼容性回归全部结束后，
再串行运行相同千兆对照：双端 TBF 1000 Mbit/s，单 TCP 流与 50 ICMP/s，
每项预热 10 s / 测量 15 s，四路径轮换三轮；默认双层加密、FEC 和有限 RTX 均保留。
没有并行编译或其他本项目网络负载，仍是同机 veth/TUN、未绑核、未独占主机。

| 路径 | 修正版三轮 goodput（Mbit/s） | 原基线中位数 | 修正版中位数 | RTT p99 中位数：前 → 后（ms） |
|---|---|---:|---:|---:|
| Underlay IPv4 | 956.59 / 956.58 / 956.65 | 956.61 | 956.59 | 1.10 → 1.10 |
| nnlan IPv4 | 285.63 / 284.72 / 284.16 | 178.43 | 284.72 | 14.90 → 9.53 |
| nnlan IPv6 | 278.87 / 278.11 / 278.61 | 173.04 | 278.61 | 15.40 → 8.76 |
| nnlan IPv4 反向 | 283.74 / 284.16 / 280.10 | 181.40 | 283.74 | 14.60 → 9.04 |

IPv4 提升 **59.6%**，约 **35.59 MB/s**，达到实测 Underlay goodput 的 **29.76%**；
相对另行复查的旧版 IPv4 181.29 Mbit/s，提升约 57.1%。
12 项各有 750/750 ICMP 回复，TCP 重传和 TBF 丢包增量均为 0。
IPv4 两端 daemon CPU 中位数为 76.29% / 72.10%，100% 代表一个逻辑核。

结果仍未接近千兆；先前定位到的系统调用、TUN 逐包处理与分片成本仍有优化空间。
保留已发现的首轮 PMTU 失败，修正后重跑完整矩阵，不用较快的首轮 287.30 代替修正版 284.72。
该结论不外推物理网卡、多跳吞吐、百/千节点并发或长期尾延迟。

```bash
nix develop --command python3 tests/perf/throughput.py \
  --binary target/release/nnlan --underlay-mbps 1000 \
  --warmup 10 --seconds 15 --repeats 3 \
  --output target/perf-nnlan-final-1000.json
```

原始报告：`target/perf-nnlan-final-1000.json`；摘要：`target/perf-nnlan-final-1000-summary.json`；
日志：`target/perf-nnlan-final-1000.log`。源文件清单、源码归档和证据校验分别为
`target/perf-final-source-sha256.json`、`target/perf-final-source.tar.gz`、`target/perf-final-audit.json`。
