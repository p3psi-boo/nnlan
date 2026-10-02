# Linux 开机保护

## 生命周期

`nnlan --config /var/lib/nnlan/nnlan.toml guard` 是独立、同步、幂等的内核保护安装命令。
它读取身份及持久的出口/子网选择，在创建 TUN、解析 DNS、绑定 UDP 或启动 daemon 之前，
安装同一套 nft 和 blackhole 策略；不要求底层接口已有地址、网关或可达 peer。

- 与 daemon / 离线关闭共用身份排他锁；活跃 daemon 存在时直接返回错误。
- 不读取、重写或预留签名序号，损坏的 runtime state 不妨碍安装保护。
- 不做 forwarding / RPF 的运行前置检查：这些检查仍在 `run` 进行。
- guard 成功不表示网络在线，也不表示出口健康。JSON 的 `network_running` 始终为 false。
- guard / daemon 停止均不撤销保护；只有显式 `exit off` 才解除出口选择。
- 配置或身份缺失、nft/ip 执行失败均返回失败，服务依赖必须使物理网络保持未启动。

## systemd 安装

文件在 `packaging/systemd/`。实例使用 `/var/lib/nnlan/nnlan.toml`，二进制默认
`/usr/local/bin/nnlan`，ip/nft 需要位于 unit 指定的 PATH。

```bash
sudo install -m 755 target/release/nnlan /usr/local/bin/nnlan
sudo /usr/local/bin/nnlan --config /var/lib/nnlan/nnlan.toml init
# 编辑配置，填写 peers 以及需要跨重启保留的路由选择。
sudo install -m 644 packaging/systemd/nnlan*.service /etc/systemd/system/

# 下面以 systemd-networkd 为例；对每个负责物理网络配置的服务安装此依赖。
sudo install -d /etc/systemd/system/systemd-networkd.service.d
sudo install -m 644 packaging/systemd/require-nnlan-guard.conf \
  /etc/systemd/system/systemd-networkd.service.d/nnlan-guard.conf
sudo systemctl daemon-reload
sudo systemctl enable nnlan-guard.service nnlan.service
sudo systemctl start nnlan-guard.service nnlan.service
```

采用 NetworkManager 时 drop-in 的目录改为 `NetworkManager.service.d`；实际验收范围见下文。
已有手动启动的 daemon 应先停机，再让 systemd 接管同一份身份和配置。
不要添加 `ConditionPathExists` 来跳过缺失配置：跳过不等于启动失败。

`nnlan-guard` 使用 `DefaultDependencies=no`、本地文件系统依赖与 `Before=network-pre.target`。
网络配置服务同时使用 **Requires + After**；仅 `Before` 或 `Wants` 并不传播 guard 的失败。
详见 [systemd 的 network-pre 说明](https://systemd.io/NETWORK_ONLINE/)
及 [unit 依赖语义](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Requires=)。

两项服务都没有清理保护的 `ExecStop`。daemon 重启不重装早期 guard 服务，
而由自身正常启动流程核验并更新同一个内核策略。改变配置不需要重启 guard。
管理员主动停止 guard 会经 Requires 停止网络配置服务；恢复时启动网络服务即可重新拉起 guard。

本地路由选择通过 CLI 原子修改，配置应放在可写的 `/var/lib/nnlan`，不是只读 store 或只读 `/etc`。
服务仅开放此目录写入；TUN 和内核策略所需能力仍由 root 服务提供。
这套服务用于 TUN 实例；`--no-tun` 测试模式不使用早期内核 guard。
日志：`journalctl -u nnlan-guard -u nnlan`。

## NixOS

flake 同时提供 `packages.<system>.default` 和 `nixosModules.default`：

```nix
{
  imports = [ inputs.nnlan.nixosModules.default ];
  services.nnlan = {
    enable = true;
    networkServices = [ "systemd-networkd" ];
  };
}
```

启用前，在本机 `/var/lib/nnlan` 预置身份与配置，不将私钥放入 Nix store。
模块使用上面相同的 unit 文件，替换二进制/IP/nft 的 store 路径，
并对列出的每一个网络服务添加强依赖；不会开启其他网络管理器或修改主机 sysctl。

## 验收边界

```bash
make e2e-boot
cat target/boot-result/boot.json
```

`tests/nixos/boot.nix` 使用两个真正启动 Linux/systemd 的隔离 VM，不是宿主机 transient unit 模拟。
本轮已通过：双栈静态 networkd、启动前应用探针、daemon state 损坏、策略表清空、
交付的 daemon unit 实际启动及 SIGKILL 后自动重启、
显式关闭的双栈 TCP/UDP 正向对照，以及损坏配置后再次开机。结果以本次生成的 `boot.json` 为准。
接收端请求日志验证请求没有到达，并比较 guard 完成与 networkd 启动的单调时间戳。
测试不修改宿主机的网络配置或 systemd 服务。

此部署链覆盖本地根文件系统、未在 initrd 配网、所有物理地址配置服务都依赖 guard 的场景。
networkd 的 DHCPv4/v6 冷启动、续租、IPv4 地址/网关更新和停机保护另由三台 VM 验证，
配置与证据见 [DHCP 与底层更新](linux-dhcp.md)。例外绑定显式系统 UID 与精确端口对，没有宽泛 DHCP 放行。
initrd 网络/NFS 根、管理员在 guard 前手动拉起接口、另一个服务清空 nft、NetworkManager
以及 IPv6 动态前缀/多路由器切换仍需要各自集成测试。
