# VPS Scope

> 面向自建代理、隧道和隐私网络 VPS 的安全与运行状态审计工具。

VPS Scope 是一款运行在 Ubuntu 和 Debian 上的 VPS 审计工具。它会先完成一套较完整的主机安全基线检查：账户与 SSH、sudo、防火墙、入侵防护、系统更新、软件包、systemd 服务、Docker、TLS 证书、日志、资源可靠性和可疑持久化。即使服务器没有运行代理服务，这些结果也可以用来了解它当前的安全与运行状态。

在这套通用审计之上，VPS Scope 进一步面向自建代理、隧道和隐私网络服务器。通用 VPS 审计主要关心谁能登录、哪些服务正在运行、端口是否开放，以及系统有没有明显的配置风险；这些检查仍然是必要的基础。但在代理服务器上，还需要知道一个公网端口究竟是正常的节点入口，还是不该暴露给整个互联网的管理面板、订阅端点或内部 API。

因此，VPS Scope 会把 Linux 主机状态与代理工作负载放在同一份证据链中：面板数据库和代理配置说明“本来应该怎样”，systemd、Docker、进程与实际监听说明“现在正在怎样运行”，主机防火墙和反向代理则说明“外部可能怎样访问它”。报告最后尽量给出几个直接的答案：

- SSH、账户、防火墙、更新和系统服务是否存在明确风险；
- Reality、Hysteria2、Shadowsocks 等节点入口是否实际监听，并被防火墙正确处理；
- S-UI、3x-ui 等管理面板是否意外向整个公网开放；
- 配置、面板数据库、运行进程和监听关系是否一致；
- 核心服务、TLS 证书、日志和系统资源是否存在影响持续运行的问题。

它不是只识别代理软件名称，也不是把通用 Linux 审计简单附在端口扫描后面。对于普通 VPS，报告会保留完整的主机安全基线；对于代理 VPS，则会额外解释节点入口、管理面、订阅、控制 API、Docker 和反向代理之间的用途关系。

```bash
curl -fsSL https://github.com/sakkaku404/vps-scope/releases/latest/download/run.sh | sudo bash
```

这条命令会自动校验下载文件的 SHA-256，然后直接运行。服务器没有安装 `cosign` 时会显示一行“发布者签名未验证”的警告，但不会再要求输入 `continue`。

运行后可以选择简体中文、English、Русский 或 فارسی。非交互运行可使用 `--lang zh-CN`、`--lang en`、`--lang ru-RU` 或 `--lang fa-IR`。

需要跳过交互并直接指定参数时，把参数放在 `bash -s --` 后面；以 `--` 开头的参数会自动作为 `audit` 参数处理：

```bash
curl -fsSL https://github.com/sakkaku404/vps-scope/releases/latest/download/run.sh | sudo bash -s -- --lang zh-CN --profile proxy
```

默认只在终端显示结论，不写入报告文件；需要保存 HTML、Markdown 和 JSON 时可在输出方式中选择 2 或 3。VPS Scope 没有修复功能，不会更改 SSH、防火墙、服务、账户或软件包。

默认审计也不会执行 S-UI、3x-ui、sing-box、Xray、Nginx 等被审计工作负载自带的二进制，只读取配置、数据库和系统运行态。只有明确使用 `--native-self-test` 时，才会在所有权和权限检查通过后执行这些本地程序；该模式会以审计进程的权限运行服务器上的第三方代码，使用 `sudo` 审计时即为 root 权限。

[![CI](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/sakkaku404/vps-scope)](https://github.com/sakkaku404/vps-scope/releases)
[![License](https://img.shields.io/github/license/sakkaku404/vps-scope)](LICENSE)

[简体中文](README.md) · [English](docs/README.en.md) · [Русский](docs/README.ru.md) · [فارسی](docs/README.fa.md)

[代理兼容性](docs/PROXY-COMPATIBILITY.md) · [检查项目](docs/CHECKS.md) · [策略与外部观察](docs/POLICY-AND-PROBE.md) · [隐私说明](docs/PRIVACY.md)

## 一个真实例子

下面来自一台运行 S-UI 1.5.3 和 sing-box 的测试 VPS，地址和无关信息已经省略：

```text
代理 VPS 结论
────────────────────────────────────────────────────────────────────
识别到: S-UI, sing-box
节点入口       PASS
  已确认 4 个代理入口；配置、实际监听和主机防火墙关系一致。
管理面         RISK/HIGH
  S-UI 56709/tcp · 公网通配 · 防火墙允许 · TLS启用 · 非默认路径
  判断：管理面仍可由整个公网访问
配置与运行     INFO
  配置已完成静态解析；默认未执行代理核心或面板程序。

代理入口:
  443/tcp    sing-box/vless (reality)       公网通配 · 防火墙允许 · PASS
  443/udp    sing-box/hysteria2             公网通配 · 防火墙允许 · PASS
  32003/tcp  sing-box/shadowsocks           公网通配 · 防火墙允许 · PASS
  32003/udp  sing-box/shadowsocks           公网通配 · 防火墙允许 · PASS
```

同一个面板和核心进程可以打开多个公网端口。普通 VPS 体检容易把它们全部当作“开放端口”，或者全部当作“代理服务”。VPS Scope 会结合面板数据库、代理配置、实际监听进程和防火墙，只挑出真正不该向整个公网开放的管理面。

这就是它与通用 VPS 审计的主要区别：保留必要的 SSH、账户、更新和持久化检查，同时进一步理解代理服务器上每个入口的用途。

## 保存完整报告时会得到什么

默认运行只在终端显示结果，不会创建报告目录。选择输出方式 2 或 3，或者使用 `--format bundle` 时，一次审计会把同一组结果保存成四种格式：

```text
report.zh-CN.html   推荐，下载到电脑后用浏览器打开
report.zh-CN.txt    终端文字版
report.zh-CN.md     完整 Markdown 报告
report.json         完整机器可读数据，用于对比和基线
manifest.json       上面四份报告的 SHA-256 校验清单
```

也就是说，目录里共有 **4 份相同检测结果的不同格式，加 1 份校验清单**，不是进行了四次检测。

其中 `report.json` 是所有格式共同使用的审计底稿。它不仅保存 55 个稳定检查 ID、状态、严重度和原因代码，还包含结构化的部署视图：识别到的组件、服务端点、代理/反代关系以及各类证据的覆盖程度。HTML、Markdown、历史对比和基线检查都读取这份结构化数据，而不是反过来解析终端文案。旧版 `schema 1.0` 报告仍可读取。`vps-scope verify report.json` 检查报告的语义契约；对完整报告目录执行 `verify` 时，还会根据 `manifest.json` 核对文件集合和 SHA-256。

保存完成后，程序会先显示固定的 `latest` HTML 路径。最简单的下载方法是在 SSH 软件中打开 SFTP，进入 `/root/vps-scope-reports/latest/`（非 root 用户以程序显示的实际路径为准），下载 `report.zh-CN.html`。也可以在自己的电脑运行：

```bash
scp <SSH_HOST>:'/root/vps-scope-reports/latest/report.zh-CN.html' .
```

`<SSH_HOST>` 应替换成平时连接这台 VPS 使用的 IP、域名或 SSH 别名。如果登录时指定了端口、`-i` 私钥或使用 `ssh-agent`，下载时也要沿用相同设置。VPS 端无法知道客户端保存私钥的位置，因此不会再打印一条可能认证失败的 `root@IP` 命令。带时间戳的历史目录和五个文件名仍会显示在后面。

一行临时运行结束后，报告文件仍会保留，但临时下载的程序会被删除。只有已经安装 VPS Scope 的服务器才能使用下面这些命令：

```bash
sudo vps-scope report show  # 在终端重新显示最近结果
sudo vps-scope report path  # 显示最近报告目录
sudo vps-scope report list  # 列出历史报告
```

HTML 报告会先回答“节点入口、管理面、配置与运行、服务可用性、Linux 安全底座”五个问题，然后才展示处理建议和技术明细。页面支持搜索、按状态筛选和展开全部证据，不加载外部脚本或字体。

## VPS Scope 重点检查什么

### 节点入口和管理面

- 区分代理入口、面板、订阅端点和控制 API
- 将协议配置、TCP/UDP 监听、进程归属和 IPv4/IPv6 防火墙关联起来
- 找出已配置但未监听、被防火墙阻断、进程不匹配或禁用后仍在监听的入口
- 判断面板是直接监听公网、只监听回环，还是通过 Nginx、Caddy、HAProxy 暴露
- 检查根/默认路径和 TLS 状态，但不会把随机路径当成访问控制

### 配置和运行状态

- 默认静态解析 sing-box、Xray 配置；可显式启用原生配置自检
- 对照 S-UI、3x-ui/x-ui 数据库、生成配置与实际监听
- 检查 Reality、Hysteria2、TUIC、Trojan、Shadowsocks、WireGuard 和 OpenVPN 的关键运行关系
- 分类统计认证、握手、DNS、TLS、路由和面板登录错误，不复制原始日志和用户数据
- 检查证书有效期、续期计划、近期执行结果和 reload 链路

### Docker 和系统底座

- 检查 privileged、host network、危险 capabilities、Docker socket 和发布端口
- 关联 INPUT、FORWARD、DOCKER-USER 与容器实际暴露
- 检查 SSH、账户、sudo、Fail2ban/CrowdSec、更新和 systemd 服务
- 检查 OOM、core dump、磁盘、inode、日志持久性和可疑启动项
- 查找额外 UID 0、异常 SSH key、临时目录程序和已删除但仍在运行的程序

## 支持程度

“能识别”不等于“所有版本和部署方式都完全支持”。当前适配分为三层：

### 验证最充分

- S-UI
- 3x-ui / x-ui
- sing-box
- Xray-core

这些组件已经用真实 VPS、面板数据库、配置、监听、防火墙和协议入口做过组合测试。

### 已有专项适配

- Hiddify
- Marzban
- Outline
- WireGuard
- OpenVPN
- Hysteria2、TUIC、Trojan、Shadowsocks

### 部署关系识别

- Docker 与 Docker Compose
- Nginx
- Caddy
- HAProxy

具体版本、部署方式和已经验证的语义见[代理兼容性](docs/PROXY-COMPATIBILITY.md)和[兼容矩阵](docs/COMPATIBILITY-MATRIX.md)。遇到未知数据库结构、动态反代目标或无法完整读取的证据时，结果会显示 `UNKNOWN`，不会假装已经确认安全。

### 已完成的实验室验证

v1.1.0 发布前曾在五台一次性实验 VPS 上连续完成两轮标准审计、深度审计、报告包验证、脱敏支持包和跨机 TCP/UDP 探测。每台机器都生成完整的 55 项结果，检查状态、严重度、原因代码和端点关系在两轮之间没有漂移；512 MB 内存的测试机也完成了深度审计。测试结束后 VPS、临时规则和辅助进程均已清理。

这是一次受控实验的历史记录，不代表所有发行版、面板版本和云网络都已经验证。主机角色、性能范围和可重复测试契约见[测试说明](docs/TESTING.md)与[发布准备度](docs/READINESS.md)。

## 如何理解结果

报告不提供一个看似精确但无法解释的安全分数，只使用四种状态：

- `PASS`：证据支持当前判断，不代表服务器永远安全
- `RISK`：已经发现需要处理或人工复核的问题
- `INFO`：状态、清单或上下文，通常不需要单独处理
- `UNKNOWN`：证据不足或读取失败，不能当作 `PASS`

阅读时先看：

1. **代理 VPS 结论**：节点入口和管理面是否正常
2. **现在优先处理**：最值得马上处理的问题
3. **可能影响可用性**：入口、防火墙、证书或服务恢复问题
4. **证据不足**：工具无法可靠判断的部分

最后的“检查结果索引”只是 55 项检查的状态目录。选择保存完整报告后，HTML、Markdown 和 JSON 中会保留完整证据。

## 安装和常用命令

如果需要定期检查，可以安装：

```bash
curl -fsSL https://github.com/sakkaku404/vps-scope/releases/latest/download/install.sh | sudo bash
sudo vps-scope
```

不带参数会进入简体中文、English、Русский、فارسی 四种语言的交互引导。也可以直接指定：

```bash
sudo vps-scope audit --lang zh-CN --profile proxy
sudo vps-scope audit --profile custom --expect-public 22/tcp,443/tcp
sudo vps-scope audit --deep
# 可选：在信任检查通过后执行本地工作负载程序进行原生自检
sudo vps-scope audit --native-self-test
```

### “服务器用途”会改变什么

服务器用途也叫 `profile`。它不会减少主机安全基线检查，也不会修改服务器；账户、SSH、sudo、防火墙、更新、systemd、Docker、TLS、日志和持久化等项目始终会检查。它提供的是判断上下文，主要帮助程序解释“这个公网监听是不是这台机器预期提供的服务”。

| 选择 | 适用场景 | 判断上的作用 |
|---|---|---|
| `auto` | 不确定时选择，默认推荐 | 根据进程、systemd、Docker 和常见配置路径识别 `general`、`proxy`、`web`、`docker` 或 `mixed` |
| `general` | 普通 Linux VPS | 不预设代理、Web 或容器公网入口 |
| `proxy` | sing-box、Xray、S-UI、3x-ui、Hysteria2 等代理 VPS | 将有配置和运行证据支持的代理入口视为预期候选；管理面、订阅和控制 API 仍单独审计 |
| `web` | Nginx、Caddy、HAProxy、Apache 等 Web 入口 | 为常见 Web 前端提供用途上下文 |
| `docker` | 主要通过 Docker 发布服务 | 结合容器发布端口和 FORWARD / DOCKER-USER 链解释暴露关系 |
| `mixed` | 同时承担代理、Web、Docker 等多种用途 | 合并相应场景的预期入口 |
| `custom` | 已经明确知道哪些公网端口应该开放 | 配合 `--expect-public PORT/tcp,PORT/udp` 声明预期入口 |

例如选择 `proxy` 后，有配置、监听和防火墙证据的 Reality 或 Hysteria2 入口可以判为符合用途；同一台机器上向公网开放的 S-UI 管理面不会因此自动变成 `PASS`。如果用途选错，程序不会改动任何配置，但可能把正常公网入口列为需要复核，或者缺少最合适的场景解释。不确定时选 `auto` 即可，报告头部会同时显示“选择的用途”和“实际检测到的用途”。

交互模式和一行临时运行命令默认只显示终端报告。需要同时显示并保存完整报告时选择输出方式 2，或手动指定位置：

```bash
sudo vps-scope audit --lang zh-CN --profile proxy \
  --format bundle --also-terminal --output ./reports/my-vps
```

已有 JSON 可以离线重新生成报告，不需要再次连接服务器：

```bash
vps-scope render --lang zh-CN --format html --output report.html report.json
vps-scope verify report.json
vps-scope verify ./reports/my-vps
```

对比同一台服务器的两次结果：

```bash
vps-scope diff old.json new.json
vps-scope baseline create report.json baseline.json
vps-scope baseline check baseline.json report-new.json
```

### 命令速查

| 命令 | 用途 |
|---|---|
| `audit` | 在当前 VPS 上执行审计 |
| `doctor` | 查看当前主机上哪些取证来源可用 |
| `checks` / `explain` | 列出 55 项检查，或解释某个检查 ID |
| `report` / `render` / `verify` | 查看已保存报告、离线重新渲染、验证报告或报告包 |
| `diff` / `baseline` / `fleet` | 对比同一主机的变化、建立基线、汇总多台主机 |
| `redact` / `support` | 生成脱敏报告或兼容性支持包；分享前仍需人工检查 |
| `policy` / `probe` | 声明部署预期，并从另一台受控主机复核公网 TCP 可达性 |

### 把“我的部署意图”写进审计

自动识别可以解释常见面板和代理入口，但它不知道你是否特意把某个端口限制给 VPN、某个订阅是否必须使用 TLS，或 IPv4/IPv6 应该从哪张网卡出去。策略文件用来声明这些预期，不包含节点凭据，也不会修改系统：

```bash
vps-scope policy init policy.json
# 编辑 policy.json，填写实际端口、角色、暴露范围和出口要求
vps-scope policy validate policy.json
sudo vps-scope audit --profile proxy --policy policy.json
```

有策略时，报告会明确比较管理面、订阅、控制 API、代理入口、来源限制、TLS/路径和出口 DNS；没有策略时仍会运行原有识别，但不会把工具的推断伪装成你的部署要求。

### 从另一台机器复核公网可达性

本机的 `ss` 和防火墙无法证明云防火墙及公网路由的最终效果。可以在被审计 VPS 生成一个不含凭据的探测计划，复制到另一台受控机器执行，再把结果导回报告：

```bash
# 被审计 VPS
vps-scope probe plan --target 203.0.113.10 --output plan.json report.json

# 另一台 VPS
vps-scope probe run --output observation.json plan.json

# 把 observation.json 复制回来后
vps-scope probe import --output report-observed.json report.json observation.json
vps-scope render --lang zh-CN --format html --output report-observed.html report-observed.json
```

TCP 会得到外部可达/不可达证据，并与策略中的预期暴露范围比较。UDP 不会因为“成功发送了一个任意数据包”就宣称节点可用，而是明确保留为 `UNKNOWN`，需要真正懂协议的客户端测试。

### 离线版本安全公告

报告会把检测到的 3x-ui、sing-box 和 Xray 版本与随程序发布的官方安全公告快照进行匹配。这个过程不联网；命中已知受影响范围会给出 `RISK` 和公告链接，版本读不到或公告库过旧会是 `UNKNOWN`。没有命中只表示“当前内置公告中没有匹配项”，不等于软件不存在其他漏洞。

公开报告前先生成脱敏版：

```bash
vps-scope redact --format markdown --output public.md report.json
```

报告仍可能包含敏感的部署关系，分享前请自行检查。完整规则见[隐私说明](docs/PRIVACY.md)。

## 支持范围和限制

当前支持：

- Ubuntu、Debian
- Linux `amd64`、`arm64`
- 使用 systemd 的常见原生或 Docker 部署

VPS Scope 能检查 VPS 内部看到的配置和运行状态，但不能：

- 证明服务器一定没有被入侵
- 从 VPS 内部读取云厂商安全组
- 代替真实客户端协议握手；外部 TCP 探针也不能证明代理协议本身可用
- 保证尚未适配的新面板 schema 一定能被正确理解

默认检查适合日常运行。`--deep` 会额外检查 SUID/SGID、文件 capabilities 和系统包完整性，耗时更长。未运行的深度项目会显示为未执行，不会显示 `PASS`。

## 下载与安全验证

临时运行和安装脚本本身也是带 Sigstore bundle 的 Release 产物；启动后，它们会核对所下载二进制的 SHA-256，并在系统已有 `cosign` 时验证 GitHub Actions 无密钥签名。临时运行器在没有 `cosign` 时会显示简短警告并直接运行；设置 `VPS_SCOPE_REQUIRE_SIGNATURE=1` 可以要求必须完成签名验证，否则停止。永久安装器仍要求交互确认，自动安装只有在明确接受这一取舍后才应使用 `--allow-unsigned` 或设置 `VPS_SCOPE_ALLOW_UNSIGNED=1`。

一行 `curl | bash` 无法在执行前验证引导脚本本身。需要完整验证时，请从固定标签下载脚本和 bundle，先验证脚本，再让脚本验证二进制；完整命令、provenance 和第三方许可证说明见[供应链文档](docs/SUPPLY-CHAIN.md)。

## 为什么做 VPS Scope

VPS Scope 起于我对 [vernu/vps-audit](https://github.com/vernu/vps-audit) 的一次实际复核。那份脚本让 VPS 自查变得很容易，也让我意识到：只读取某一份配置文件、按端口或服务数量设阈值，或者把取证失败当成安全，都会产生误报和漏报。

后来项目的重点逐渐转向代理服务器。一个公网端口可能是正常的 Reality 或 Hysteria2 入口，也可能是暴露给整个互联网的面板、订阅接口或内部 API。通用 Linux 基线仍然必要，但它不足以解释这些用途关系。

VPS Scope 不是 vps-audit 的分支，代码与检测实现均为独立实现。

感谢 OpenAI Codex 编写了绝大多数 Go——它目前写过的 Go 比维护者本人多得多，维护者目前正在努力看懂它。

## 开发和参与

```bash
go build -trimpath -o vps-scope ./cmd/vps-scope
go test -count=1 ./...
go vet ./...
staticcheck ./...
gosec -quiet ./...
govulncheck ./...
```

欢迎提交可复现的 Ubuntu、Debian 和代理部署样本。公开 issue 不要附上未经脱敏的服务器报告；安全问题请使用 GitHub 私密漏洞报告，详见 [SECURITY.md](SECURITY.md)。

v1.1.0 发布前的安全边界与修复验证记录见 [2026-08-07 安全审计](docs/SECURITY-AUDIT-2026-08-07.md)。后续代码变化仍以当前测试和发布检查为准。

## 许可证

[MIT](LICENSE)
