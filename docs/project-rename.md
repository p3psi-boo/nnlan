# 项目更名为 nnlan

本文记录更名时的 GGB2 历史构建；后续协议变更见 [GGB3 单层加密](hop-encryption.md)。

2026-09-22：按用户决定暂缓 `cp`，撤下未完成的文件传输代码、CLI/config/admin 接口及仅为其添加的依赖 feature。
本次只调整项目命名，不增加文件传输功能，不调整已有网络协议与拥塞参数。

## 当前名称

| 项目 | 名称 |
|---|---|
| Cargo package / Rust crate / CLI | `nnlan` |
| release 二进制 | `target/release/nnlan` |
| 默认配置 / 控制 socket | `nnlan.toml` / `nnlan.sock` |
| 默认节点名 / TUN | `nnlan` / `nnlan0` |
| systemd | `nnlan.service`、`nnlan-guard.service` |
| 安装路径 / 状态目录 | `/usr/local/bin/nnlan` / `/var/lib/nnlan` |
| NixOS option | `services.nnlan` |
| nft 表 / ownership 前缀 | `nnlan` / `nnlan:subnet:v1:` |
| 内核路由测试环境变量 | `NNLAN_ROUTE_TEST_NETNS` |

示例、测试入口、Nix 包与服务依赖一起更名。工作区目录名称不影响包名和构建；本次不搬动正在使用的工作目录。

## 刻意保留的协议常量和历史证据

`GGB2` 报文 magic、`GGBKEY1` 身份文件头及 `ggbond.*` 密码学域分隔字符串保持原值。
这些是协议/持久格式，不是产品展示名：机械替换会改变虚拟地址，或者破坏签名、Noise 握手与既有身份文件读取。
地址池、端口、策略路由表编号和 mark 也不变。历史 `target/ggbond-*` 二进制和报告名称/hash 不重写，
此前的测试记录仍属于此前的构建，不自动算作更名版本的验收。

## 既有部署

- 既有配置可以通过 `nnlan --config <原配置路径>` 读取；没有自动迁移/重新生成密钥。
- 搬动配置时须一同保留身份文件及相邻的 `identity.state.json`，其中保存序号和地址碰撞 probe。
- 显式配置的节点名、TUN 名保持配置值；只有未填写时使用新默认值。
- systemd unit、网络管理服务的 guard 依赖、状态路径和 nft 表名称都变化。
  本次没有为已有主机执行热迁移，也不自动删除旧持久保护。
  已部署 Exit/Subnet 的机器需在受控维护窗口迁移服务与内核策略，避免旧 guard 与新 guard 混用；
  新配置安装步骤见 [Linux 开机保护](linux-boot-guard.md)。
- 不同时运行新旧实例管理同一个网络 namespace；更名不改变每个 namespace 单实例的约束。

## 验证入口

```bash
nix develop --command make check
nix develop --command make build
./target/release/nnlan --version
nix build
nix develop --command python3 tests/e2e/overlay_netns.py --collision --output target/nnlan-rename-overlay.json
```

## 本次实测结果

release SHA-256：`f6351f9d6f7e628e8871f78afdfc0fb64c9f2eace58ee2b207b6f75d37223355`。

- fmt、Clippy、152 项普通 Rust 测试、9 项 Python 测试通过；新 CLI 回归覆盖版本、默认配置/TUN 和 `cp` 未开放。
- release 构建及 `nix build`（含包内测试）通过，产物提供 `bin/nnlan`。
- 四套同版真实内核回归通过：双栈多跳/地址碰撞/FEC、成员策略、Subnet、Exit；
  报告为 `target/nnlan-rename-{overlay,membership,subnet,exit}.json`。
- 内核路由专项通过：同步与后台工作线程分别完成 2000 条双栈主机路由增删及 ACK 核验。
- 与更名前存档版本的既有身份/地址派生一致，双向 16 KiB 加密回显、签名 trace 和成员收敛通过；
  `target/nnlan-rename-compat.json`。该兼容测试使用 `--no-tun`，不表示旧部署内核策略自动迁移。
- 两套 NixOS VM 测试 derivation 求值通过；本次没有重新启动 VM，也没有重跑百/千节点或性能验收。

日志：`target/nnlan-rename-validation.log`、`target/nnlan-rename-nix-build.log`。
