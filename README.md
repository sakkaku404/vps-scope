# VPS Scope

VPS Scope 是一个给 Ubuntu、Debian VPS 用的只读安全检查工具，尤其关注 sing-box、Xray、Reality、Hysteria2、代理面板和 Docker 常见的部署方式。它负责把服务器现在的状态查清楚，指出值得留意的地方，但不会替你修改任何配置。

[![CI](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/sakkaku404/vps-scope)](https://github.com/sakkaku404/vps-scope/releases)
[![License](https://img.shields.io/github/license/sakkaku404/vps-scope)](LICENSE)

[English](docs/README.en.md) · [代理兼容性](docs/PROXY-COMPATIBILITY.md) · [隐私说明](docs/PRIVACY.md) · [检查项目](docs/CHECKS.md) · [设计说明](docs/DESIGN.md) · [测试说明](docs/TESTING.md)

## 为什么做 VPS Scope

这个项目起于一次对 [vernu/vps-audit](https://github.com/vernu/vps-audit) 的实际复核。那份脚本让 VPS 自查变得很容易，但在真实服务器上，直接读取配置文件、按端口或服务数量设阈值，以及把取证失败当成安全，都可能产生误报或漏报。

VPS Scope 不是该项目的分支，代码与检测实现均为独立实现。VPS Scope 以实际生效状态和可复核证据为基础，重新设计并实现了检查流程：检查失败显示 `UNKNOWN`，监听地址按公网、私网、回环和容器发布分类，并根据服务器用途解释结果。项目最初对照的版本是提交 [`e39115f`](https://github.com/vernu/vps-audit/tree/e39115f85414073ee5cf96bea5e3b1b811375a2a)，对应脚本 SHA-256 为 `db1134574f3c8df30bc9ac10821d207dda13ae22b0905964e2c0bc7cc71192e6`。

感谢 OpenAI Codex 编写了绝大多数 Go——它目前写过的 Go 比维护者本人多得多，维护者目前正在努力看懂它。

## 它会检查什么

一台小型 VPS 最容易出问题的地方，基本都在检查范围内：系统资源、账户与密码上下文、SSH、防火墙、监听端口、活动连接、登录日志、Fail2ban/CrowdSec、系统更新、systemd 服务、Docker、TLS 证书、文件权限和常见启动项。

代理服务器会额外检查：

- sing-box、Xray、Hysteria2、TUIC、Trojan、Shadowsocks 等核心与入口
- S-UI、3x-ui/x-ui、Marzban、Hiddify、Outline 的管理面与代理入口关系
- 对原生 S-UI、3x-ui 的面板数据库做内置只读解析；无需在目标 VPS 安装 `sqlite3`
- sing-box 与 Xray 配置解析和原生只读自检
- Clash API、V2Ray API 等控制接口是否公开监听、是否被主机防火墙限制
- 面板数据库、代理配置和私钥相关文件的权限
- 代理 systemd 服务的运行用户、capabilities、隔离选项和文件描述符限制
- Hysteria2、TUIC 等 UDP 场景的缓冲区和错误计数上下文
- 把配置入口、TCP/UDP 传输、实际监听进程、暴露范围和主机防火墙规则关联到一起；合并 UFW 与实际 nftables INPUT 规则，并识别服务停止后遗留的开放端口
- 面板数据库、生成配置和实际监听三者的角色/运行态一致性；同一动态入站不会重复计数
- Reality 关键字段是否齐全（只记录存在性和数量，不导出私钥、SNI、target 或 short ID）
- 认证、握手、DNS、TLS、路由和致命错误的日志分类计数（不导出原始日志内容）
- WireGuard 接口、UDP 监听、防火墙和近期握手数量（不导出 peer 公钥或 endpoint）
- Nginx、Caddy、HAProxy 公网前端到面板或代理核心的反向代理链；能够指出公开反代管理面和监听过宽的后端
- 可选的外部 DNS/TLS 观察；默认完全关闭，只有显式传入域名时才联网，并可检查声明使用 CDN 的域名是否仍直接发布源站地址

“识别到了软件”和“可以可靠判断管理端口”是两回事。遇到容器网络、反向代理或未知面板结构时，VPS Scope 会保留 `UNKNOWN`，不会为了显得支持得多而给出 `PASS`。当前实测范围见[代理兼容性](docs/PROXY-COMPATIBILITY.md)。

工具会尽量读取真正生效的状态。SSH 使用 `sshd -T`，不会只搜一遍配置文件；网络部分会把公网、私网、回环、IPv4、IPv6 和 Docker 发布端口分开，不会把 `127.0.0.1:3001` 之类的本地服务算成公网暴露。

报告里有四种结果：

- `PASS`：检查正常完成，结果符合预期
- `RISK`：有明确证据表明这项值得处理
- `INFO`：有用的状态或清单，本身不代表有问题
- `UNKNOWN`：缺少权限、命令或可靠证据，暂时无法判断

VPS Scope 不打安全分，也没有自动修复功能。

## 安装

只检查一次、不安装任何东西，运行这一行就够了：

```bash
curl -fsSL https://sakkaku404.github.io/vps-scope/run.sh | sudo bash
```

这一行会下载当前 Release、核对 SHA-256、执行审计，然后删除临时程序，不需要再输入第二条命令。

如果准备经常使用，并希望保留 `vps-scope` 命令，再执行安装：

```bash
curl -fsSL https://raw.githubusercontent.com/sakkaku404/vps-scope/main/install.sh | sudo bash
```

装好后运行 `sudo vps-scope`。安装脚本会自动识别 amd64 或 arm64，并在安装前核对 Release 文件的 SHA-256；这是校验和验证，不是独立数字签名。

对 `curl | bash` 不放心的话，可以先把脚本下载下来查看；下面的手动安装方式也会保留。

### 手动安装

从 [Releases](https://github.com/sakkaku404/vps-scope/releases) 下载服务器架构对应的文件。amd64 服务器可以直接运行：

```bash
curl -LO https://github.com/sakkaku404/vps-scope/releases/latest/download/vps-scope_linux_amd64
curl -LO https://github.com/sakkaku404/vps-scope/releases/latest/download/SHA256SUMS
grep 'vps-scope_linux_amd64$' SHA256SUMS | sha256sum -c -
chmod +x vps-scope_linux_amd64
sudo ./vps-scope_linux_amd64
```

arm64 服务器把文件名换成 `vps-scope_linux_arm64`。

## 从源码编译

项目只使用 Go 标准库：

```bash
go build -trimpath -o vps-scope ./cmd/vps-scope
sudo ./vps-scope
```

直接运行会进入简短的引导，可以选择中文或英文。熟悉参数后也可以直接执行：

```bash
sudo ./vps-scope audit --lang zh-CN --profile general
sudo ./vps-scope audit --lang zh-CN --profile proxy
sudo ./vps-scope audit --profile custom --expect-public 22/tcp,443/tcp
sudo ./vps-scope audit --profile proxy --external-domain panel.example.com --expect-cdn
```

`profile` 用来告诉工具这台服务器大致是做什么的，目前有 `general`、`web`、`proxy`、`docker` 和 `mixed`。如果某个公网端口是你明确需要的，可以用 `--expect-public` 声明；这只影响端口是否符合用途预期，不会跳过其他安全检查。

外部 DNS/TLS 观察默认关闭。`--external-domain` 会明确启用网络访问，`--expect-cdn` 表示这些域名预期位于 CDN 后；工具会比较 DNS 地址与本机全局地址并检查 443 TLS，但历史 DNS、云防火墙和真正的异地可达性仍需要从另一台主机复核。

默认检查适合日常运行，不会递归扫描整块磁盘。需要核对 SUID/SGID、文件 capabilities 和已安装软件包完整性时，使用 `sudo vps-scope audit --deep`；未运行的深度项目会明确标成未执行，不会冒充 `PASS`。

## 报告

交互模式默认会在终端显示结果，同时保存一份完整报告。报告统一放在 `~/vps-scope-reports/主机名/时间/`，其中 `~/vps-scope-reports/latest` 始终指向最近一次报告。每次运行使用独立目录，拒绝覆盖已有报告；生成完成后会解释每个文件的用途，并给出可以复制的下载命令。

```bash
sudo vps-scope report show  # 再次显示最近一次报告
sudo vps-scope report list  # 列出保存过的报告
sudo vps-scope report path  # 显示最近报告的目录
```

也可以用参数把 JSON、纯文本、Markdown、HTML 或完整报告包写到指定位置：

```bash
sudo ./vps-scope audit --format bundle --output ./reports/sgp
```

完整报告包里包含一份 JSON 原始报告、几种阅读格式和 SHA-256 清单。HTML 报告是一个完全离线的单文件页面，可以按状态筛选、搜索检查和折叠证据，不会加载外部脚本或字体。Linux 下生成的报告默认使用较严格的文件权限。

有了 JSON 以后，不用再次连接服务器就能切换语言或格式：

```bash
vps-scope render report.json --lang zh-CN --format html --output report.zh-CN.html
vps-scope render report.json --lang en --format markdown --output report.en.md
```

准备把报告发到公开场合时，可以先脱敏：

```bash
vps-scope redact report.json --format markdown --output public.md
```

脱敏后的同一地址或用户名会一直使用同一个代号，方便看懂它们之间的关系。密码、token、私钥、订阅路径、SSH key 注释和完整进程参数不会写进报告；可能同时装有证书和私钥的应用数据也不会为了检查而导出。完整边界见[隐私说明](docs/PRIVACY.md)。

## 对比服务器状态

`diff` 用来比较同一台服务器的两次检查，`fleet` 可以把多台服务器放在一起看：

```bash
vps-scope diff old.json new.json
vps-scope fleet west.json sgp.json tw.json japan.json
```

长期运行的服务器可以建立基线，重点观察新增或消失的公网监听、SSH key、防火墙规则、面板/代理入口、容器和代理服务。baseline v2 使用主机 StableID，监听身份不会因为服务重启后 PID 改变而产生噪声；旧 v1 文件仍可读取，但会提示主机身份保证较弱：

```bash
vps-scope baseline create report.json baseline.json
vps-scope baseline check baseline.json report-new.json
```

检查 ID 不随语言变化，所以中文报告和英文报告也能正常比较。

## 其他命令

```text
doctor      看当前系统能执行哪些检查
checks      列出检查项目和 ID
explain     查看某项检查的说明
render      重新生成语言或格式
redact      生成适合分享的脱敏报告
report      查看和管理已保存的报告
verify      校验报告包有没有被改动
version     显示版本和构建信息
```

## 当前支持范围

当前支持 Ubuntu、Debian，以及 Linux `amd64`、`arm64`。部分检查会调用系统里的 `ss`、`journalctl`、`ufw`、`firewall-cmd`、`nft`、`iptables`、`fail2ban-client`、`cscli`、`dpkg`、`docker`、`coredumpctl` 或 `sqlite3`；缺少某个命令时，只会影响相关项目，并在报告中明确显示，不会被当成安全。

它能帮你更快地检查服务器，但不能证明服务器一定没有被入侵，也无法从 VPS 内部读取云厂商的安全组。更具体的边界见[设计说明](docs/DESIGN.md)。

## 参与开发

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/vps-scope
```

欢迎提交问题、代码和可复现的 Ubuntu/Debian 测试样本。公开 issue 里请不要附上未经脱敏的服务器报告。

如果发现 VPS Scope 本身存在安全问题，请使用 GitHub 的私密漏洞报告，不要公开提交 issue。具体方式见 [SECURITY.md](SECURITY.md)。

## 许可证

MIT
