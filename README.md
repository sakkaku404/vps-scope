# VPS Scope

> 面向自建代理、隧道和隐私网络 VPS 的安全与运行状态审计工具。

VPS Scope 运行在 Ubuntu 或 Debian VPS 上。它把代理配置、实际监听、进程归属、Docker 网络、反向代理和主机防火墙放在一起看，尽量回答一个比“这个端口开着吗”更有用的问题：

**这个端口是谁开的、用来做什么、是否按预期工作，以及是否把不该公开的管理面暴露到了公网。**

```bash
curl -fsSL https://sakkaku404.github.io/vps-scope/run.sh | sudo bash
```

上面这条命令会下载当前 Release、核对 SHA-256、运行审计并删除临时程序。VPS Scope 没有修复功能，只负责把情况和证据讲清楚。

[![CI](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/sakkaku404/vps-scope)](https://github.com/sakkaku404/vps-scope/releases)
[![License](https://img.shields.io/github/license/sakkaku404/vps-scope)](LICENSE)

[English](docs/README.en.md) · [代理兼容性](docs/PROXY-COMPATIBILITY.md) · [检查项目](docs/CHECKS.md) · [隐私说明](docs/PRIVACY.md) · [设计说明](docs/DESIGN.md) · [测试说明](docs/TESTING.md)

## 它和普通端口扫描有什么不同

普通检查可能只会告诉你：

```text
2095/tcp 正在公网监听
```

VPS Scope 会尽量把它还原成能行动的判断：

```text
2095/tcp  公网监听
进程：x-ui
用途：管理面板
防火墙：允许任意来源
判断：代理入口可以公开；管理面不应默认向整个互联网开放
状态：RISK/HIGH
```

反过来，公网监听不必然是风险：

```text
443/tcp   公网监听
进程：sing-box
用途：Reality 入站
防火墙：允许任意来源
判断：符合 proxy 配置档案，属于预期代理入口
状态：PASS
```

这也是 VPS Scope 的核心：不靠端口或服务数量的阈值给服务器打分，而是尽量将**配置、运行状态和网络暴露关系**对应起来。

## 它实际解决哪些代理服务器问题

VPS Scope 不只是列出“检测到 S-UI、sing-box、Reality”。这些名称只有在能解释运行关系时才有价值。当前检查会继续追问：

- S-UI 或 3x-ui 管理面是直接监听公网，还是只监听回环后经 Nginx、Caddy、HAProxy 暴露；根/默认路径和未启用 TLS 会写进判断，但随机路径不会被当作安全边界
- 面板管理、订阅和代理入站是否错误共用端口；面板里已经禁用的入口是否仍在监听；是否出现面板或核心拥有、却无法由数据库和生成配置解释的公网端口
- Reality、Hysteria2、TUIC、Trojan、Shadowsocks 等配置入口，是否由正确进程按 TCP/UDP 实际监听，并被 IPv4/IPv6 主机防火墙正确放行或阻断
- Clash/V2Ray API、面板 API 和订阅相关异常是否暴露；日志只输出分类计数，不复制地址、Token 或原始请求
- Docker Compose 中哪个服务承载面板或核心，是否使用 privileged、host namespace、危险 capabilities 或 Docker socket；官方 host-network 部署会保留上下文，不会掩盖同机的危险容器
- 当前每个 TCP 代理入口有多少已建立连接，供多次报告和基线比较；不会因为某个通用数量阈值就武断判定攻击

因此，“识别协议”不是最终功能。真正的结果是把面板数据库或配置、systemd/Docker、实际监听、反向代理和主机防火墙连接成一条可以复核的证据链。证据不足时仍然是 `UNKNOWN`，不会因为识别到产品名就显示 `PASS`。

## 为什么做 VPS Scope

VPS Scope 起于我对 [vernu/vps-audit](https://github.com/vernu/vps-audit) 的一次实际复核。它让我意识到，VPS 自查应该尽量依据真正生效的状态，而不是只读取某一份配置文件，或根据端口和服务数量判断风险。

但代理服务器有自己的问题。一个公网端口可能是预期的 Reality、Hysteria2 或 Shadowsocks 入口；也可能是暴露给整个互联网的面板、订阅接口或内部 API。只统计端口，无法区分这两种情况。

所以 VPS Scope 选择了另一个重点：面向自建代理、隧道和隐私网络 VPS，尝试把配置、实际监听、进程、反向代理、容器网络和主机防火墙关联起来，再给出可复核的判断。

VPS Scope 不是 vps-audit 的分支，代码与检测实现均为独立实现。检查失败显示 `UNKNOWN`，不会冒充 `PASS`；公网、私网、回环和 Docker 发布端口也会分开解释。

感谢 OpenAI Codex 编写了绝大多数 Go——它目前写过的 Go 比维护者本人多得多，维护者目前正在努力看懂它。

## 它重点审计什么

### 代理入口与管理面

- sing-box、Xray、Hysteria2、TUIC、Trojan、Shadowsocks、WireGuard、OpenVPN 的配置、进程和入口
- S-UI、3x-ui/x-ui、Hiddify、Marzban、Outline 的面板、订阅、控制 API 与代理入口关系
- Clash API、V2Ray API 等控制接口是否监听公网、是否受到主机防火墙限制
- Nginx、Caddy、HAProxy 的公网前端到面板或代理核心的反向代理链
- 公开反代管理路由、监听过宽的后端，以及面板停止后遗留的开放端口

### 配置、运行态与防火墙

- 将配置入口、TCP/UDP 传输、实际监听进程、监听地址和防火墙规则关联起来
- 区分公网、私网、回环、IPv4、IPv6 和 Docker 发布端口
- 合并 UFW 与实际 nftables INPUT 路径，避免只看 UFW 状态造成误判
- 检查面板数据库、生成配置和实际监听之间是否一致；动态入站不会重复计数
- 对 Reality 仅检查关键语义是否齐全，不导出私钥、SNI、target 或 short ID

### 权限、隔离与敏感材料

- 面板数据库、代理配置、WireGuard/Reality 等敏感材料相关文件的权限
- 代理 systemd 服务的运行用户、capabilities、隔离选项和文件描述符限制
- Docker 的 privileged、host network、Docker socket 挂载和端口发布情况
- 已删除但仍在运行的代理核心或临时目录程序

### 可用性、异常与系统底座

- sing-box 与 Xray 的原生只读配置自检
- TLS 证书有效期、续期线索、OOM、core dump、磁盘、inode 与日志持久性
- Hysteria2、TUIC 等 UDP 场景的缓冲区和错误计数上下文
- SSH、账户、sudo、Fail2ban/CrowdSec、更新、服务失败与可疑持久化线索
- 认证、握手、DNS、TLS、路由和致命错误的日志分类计数；不导出原始日志内容

“识别到了软件”和“可以可靠判断它的管理面”是两回事。遇到未知面板结构、容器网络或无法验证的反代链时，VPS Scope 会保留 `UNKNOWN`。已在真实环境验证过的范围见[代理兼容性](docs/PROXY-COMPATIBILITY.md)。

## 如何理解结果

报告没有安全分数，只有四种结果：

- `PASS`：检查完成，当前证据符合预期
- `RISK`：当前证据表明这项需要处理或复核
- `INFO`：有用的状态或清单，本身不代表问题
- `UNKNOWN`：缺少权限、命令或可靠证据，暂时无法判断

终端、Markdown 和 HTML 报告会先给出行动摘要，按“优先处理、可能影响可用性、例行维护、证据不足”整理；这只是阅读辅助，不会改变原始检查结论。JSON 始终保留完整、机器可读的证据。

VPS Scope 可以帮助你更快地审计服务器，但不能证明服务器一定没有被入侵，也不能从 VPS 内部读取云厂商安全组，更不能替代从外部网络进行的连通性测试。

## 快速开始

### 临时运行

只检查一次，不安装任何东西：

```bash
curl -fsSL https://sakkaku404.github.io/vps-scope/run.sh | sudo bash
```

### 安装后重复使用

```bash
curl -fsSL https://raw.githubusercontent.com/sakkaku404/vps-scope/main/install.sh | sudo bash
sudo vps-scope
```

安装脚本会识别 amd64 或 arm64，并在安装前核对 Release 文件的 SHA-256。这是校验和验证，不是独立数字签名。

如果不想使用 `curl | bash`，可以先下载脚本阅读，或使用下面的手动方式。

### 手动下载

从 [Releases](https://github.com/sakkaku404/vps-scope/releases) 下载对应架构的二进制。amd64 示例：

```bash
curl -LO https://github.com/sakkaku404/vps-scope/releases/latest/download/vps-scope_linux_amd64
curl -LO https://github.com/sakkaku404/vps-scope/releases/latest/download/SHA256SUMS
grep 'vps-scope_linux_amd64$' SHA256SUMS | sha256sum -c -
chmod +x vps-scope_linux_amd64
sudo ./vps-scope_linux_amd64
```

arm64 服务器把文件名改成 `vps-scope_linux_arm64`。

## 常用用法

不带参数会进入简短引导，可选择中文或英文；也可以直接运行：

```bash
sudo vps-scope audit --lang zh-CN --profile proxy
sudo vps-scope audit --profile custom --expect-public 22/tcp,443/tcp
sudo vps-scope audit --profile proxy --external-domain panel.example.com --expect-cdn
sudo vps-scope audit --deep
```

内置 profile 包括 `general`、`web`、`proxy`、`docker` 和 `mixed`。`--expect-public` 用于声明你明确需要公开的端口；它只影响暴露是否符合用途预期，不会跳过其他检查。

外部 DNS/TLS 观察默认关闭。只有显式传入 `--external-domain` 时才会访问网络；`--expect-cdn` 用于声明这些域名预期位于 CDN 后。它能比较 DNS 地址、本机全局地址和 443 TLS，但历史 DNS、云防火墙和真实异地可达性仍需要另一台主机复核。

默认检查适合日常运行，不会递归扫描整块磁盘。`--deep` 会额外核对 SUID/SGID、文件 capabilities 和系统包完整性；未运行的深度项目会明确显示为未执行，而不是 `PASS`。

## 报告、比较与基线

交互模式会在终端显示结果，并保存完整报告到：

```text
~/vps-scope-reports/主机名/时间/
```

`~/vps-scope-reports/latest` 始终指向最近一次报告。每次运行使用独立目录，不会覆盖已有报告。

```bash
sudo vps-scope report show  # 再次显示最近一次报告
sudo vps-scope report list  # 列出历史报告
sudo vps-scope report path  # 显示最近报告目录
```

也可以写到明确位置：

```bash
sudo vps-scope audit --format bundle --output ./reports/sgp
```

完整报告包包含 JSON、文本、Markdown、HTML 和 SHA-256 清单。HTML 是不加载外部脚本或字体的离线单文件页面，支持筛选和搜索。已有 JSON 不必重新连接服务器，也可以重新渲染为其他语言或格式：

```bash
vps-scope render --lang zh-CN --format html --output report.zh-CN.html report.json
vps-scope render --lang en --format markdown --output report.en.md report.json
```

准备公开报告前，可以生成脱敏版：

```bash
vps-scope redact --format markdown --output public.md report.json
```

同一地址或用户名会保留同一个代号，方便看懂关系。密码、token、私钥、订阅路径、SSH key 注释和完整进程参数不会写进报告；可能同时装有证书和私钥的应用数据也不会为了检查而导出。完整边界见[隐私说明](docs/PRIVACY.md)。

对比同一服务器的两次检查，或集中查看多台服务器：

```bash
vps-scope diff old.json new.json
vps-scope fleet west.json sgp.json tw.json japan.json
```

长期运行的服务器可以建立基线，观察新增或消失的公网监听、SSH key、防火墙规则、面板/代理入口、容器和代理服务：

```bash
vps-scope baseline create report.json baseline.json
vps-scope baseline check baseline.json report-new.json
```

## 支持范围与边界

当前支持 Ubuntu、Debian，以及 Linux `amd64`、`arm64`。部分检查会使用 `ss`、`journalctl`、`ufw`、`firewall-cmd`、`nft`、`iptables`、`fail2ban-client`、`cscli`、`dpkg`、`docker` 或 `coredumpctl`；缺少某个命令只会影响对应检查，并会明确显示出来。

工具优先读取实际生效状态。例如 SSH 使用 `sshd -T`，不会只搜索一遍配置文件；`127.0.0.1:3001` 这类回环服务也不会被算成公网端口。

## 开发与参与

从源码构建只需要 Go：

```bash
go build -trimpath -o vps-scope ./cmd/vps-scope
go test ./...
go vet ./...
```

欢迎提交问题、代码和可复现的 Ubuntu/Debian 测试样本。公开 issue 不要附上未经脱敏的服务器报告；如果发现 VPS Scope 本身的安全问题，请使用 GitHub 私密漏洞报告，具体方式见 [SECURITY.md](SECURITY.md)。

## 许可证

[MIT](LICENSE)
