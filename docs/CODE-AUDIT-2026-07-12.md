# VPS Scope v0.6.0 代码与功能审计

审计日期：2026-07-12

> 状态：AUD-001 至 AUD-005 已在 v0.6.1 加固工作中修复；本文保留发现和决策记录，作为后续回归依据。

## v0.6.1 发布后复审

- main、v0.6.1 与远端一致；`go test`、`go vet`、Linux race、CodeQL、双架构发布和 `govulncheck` 均通过。
- `govulncheck` 当前报告 0 个实际调用路径漏洞。
- 总语句覆盖率从 v0.6.0 的 24.7% 提升到 36.2%；新增的可复用策略场景覆盖了 SSH、生效防火墙、认证日志、面板/代理关系、Docker 和截断证据。`report` 为 77.1%，`redact` 为 81.4%；检查策略编排仍值得继续扩大覆盖面。
- 命令输出、报告 manifest、sudo 证据、Go 标准库版本和发布措辞问题已解决；本轮未发现新的 Critical、High 或 Medium 安全问题。
- 最大剩余工程债务是 `checks_proxy.go` 仍有 1200 行、`app.go` 仍有 679 行，以及面板数据库 schema 和防火墙关系模型尚未形成版本化适配层。
- 结论：当前版本达到可稳定公开使用的早期成熟阶段；下一阶段应以测试架构和模块化为主，功能上只优先做统一防火墙模型、baseline 变更检测和真实面板适配。

## 执行摘要

VPS Scope 已经具备可公开使用的产品形态，不是简单的端口统计脚本。它的核心原则——只读、证据优先、失败为 `UNKNOWN`、按用途解释、隐私字段不进入证据——在代码中基本落实。标准审计在四台 1 vCPU / 1 GB 实验 VPS 上耗时 3.2–4.8 秒，当前发布包约 9–10 MB；对单文件 Go 工具而言效率良好。

代码尚不能称为“足够优雅”。主要债务是代理域文件过大、系统命令输出没有统一字节上限、事实快照仍有重复采集、关键策略的自动化覆盖不足。当前语句覆盖率为 24.7%，其中解析器和渲染器覆盖较好，但多数真实检查编排仍是 0%。

未发现 Critical 或 High 级代码漏洞，也未发现硬编码凭据、私钥、测试报告或 VPS 数据被提交。未使用 shell 拼接、`unsafe` 或 cgo；所有外部命令通过参数数组执行并设置超时。

## 安全与隐私发现

### AUD-001：外部命令输出没有字节上限

- 严重度：Medium
- 位置：`internal/audit/command.go:30-38`，`OSCommander.Run`
- 证据：stdout 和 stderr 使用无上限的 `strings.Builder`；`journalctl`、`nft list ruleset`、`dpkg --verify` 等命令可能产生大量输出。
- 影响：日志或规则异常庞大时，root 审计进程可能消耗过多内存甚至被 OOM 杀死。超时只能限制时间，不能限制已读取字节。
- 修复：实现有明确上限并记录截断状态的 writer；按命令类型设置合理上限。日志类检查最好流式计数，不把全文保存在内存。
- 缓解：当前标准审计实测耗时短，普通 VPS 上输出规模通常有限；深度模式风险更高。
- 误报说明：这不是远程命令注入，攻击者通常需要先影响本机日志或规则规模。

### AUD-002：报告包校验未限制 manifest 文件名

- 严重度：Low
- 位置：`internal/report/report.go:424-435`，`VerifyBundle`
- 证据：`item.Name` 直接传给 `filepath.Join(dir, item.Name)`，没有拒绝绝对路径、`..`、目录分隔符或重复名称。
- 影响：校验不受信任的报告包时，可以让程序读取报告目录外的本地文件并形成大小/SHA-256 匹配 oracle；当前不会输出文件内容。
- 修复：只接受 `filepath.Base(name) == name` 的预期文件名，解析后验证目标仍位于 bundle 根目录，并限制文件数量和 manifest 大小。
- 缓解：`verify` 是本地显式命令，正常报告包的文件名均由程序固定生成。
- 误报说明：如果项目明确规定只校验自己刚生成的可信目录，实际风险较低，但 CLI 目前没有强制这一前提。

### AUD-003：sudo NOPASSWD 证据可能保留敏感命令参数

- 严重度：Medium
- 位置：`internal/audit/checks_core.go:395-403`，`checkPrivileges`
- 证据：匹配到 `NOPASSWD:` 后把整条规则截断到 300 字符写入报告。
- 影响：sudoers 规则若含环境赋值、私有路径或带 token 的命令参数，会违反“敏感值不进入证据”的隐私边界；脱敏器也不保证识别所有任意 token。
- 修复：只保留主体、run-as、标签和允许命令数量/命令 basename；参数内容统一省略。增加带假 token 的隐私回归夹具。
- 缓解：完整报告默认保存在本机 0600 文件中，公开分享前可运行 `redact`，但这里应在采集层就避免保留。
- 误报说明：多数 sudoers 规则不包含秘密，但项目承诺的是结构性不收集，而不是依赖使用者习惯。

### AUD-004：CI 缺少调用路径感知的依赖漏洞扫描

- 严重度：Low
- 位置：`.github/workflows/ci.yml:29-47`
- 证据：已有 `go mod verify`、race、vet、CodeQL 和 Dependabot，但没有 `govulncheck`。
- 影响：新增的纯 Go SQLite 驱动带来较大的间接依赖树，已知漏洞可能只能等 Dependabot 或人工发现。
- 修复：在 CI 和发布工作流加入官方 `govulncheck ./...`，并固定 action/工具版本或记录更新策略。
- 缓解：`go.sum` 已提交，模块校验未关闭，GitHub Actions 均固定到 commit SHA。
- 误报说明：本次环境无法联网完成实时漏洞数据库扫描，因此不能据此断言当前依赖存在已知漏洞。

### AUD-005：安装器把校验和资产称为“signed”

- 严重度：Low
- 位置：`install.sh:10`
- 证据：安装器下载二进制和同一 Release 中的 `SHA256SUMS` 并校验，但没有独立数字签名或 provenance 验证。
- 影响：措辞会让使用者误以为已经验证发布者签名；SHA-256 主要防传输损坏，不能单独抵御 Release 账户或流水线被接管。
- 修复：改为“checksummed release artifacts”，或增加 GitHub artifact attestation / cosign 验证后再使用 signed。
- 缓解：下载强制 HTTPS，Release 构建在 GitHub Actions 中完成。

## 架构与效率

### 做得好的部分

- `model.Report`、稳定检查 ID、i18n 和 renderer 分离，JSON 可以跨语言重新渲染。
- `FactStore` 对进程、监听、UFW、Docker、面板事实做了缓存，减少了部分重复取证。
- `Commander` 使用 `exec.CommandContext` 和参数数组，没有 shell 注入面；每个命令都有超时。
- 单文件、无目标机运行时依赖；内置 SQLite 以 `mode=ro` 打开数据库，并有只读测试。
- 标准/深度模式边界合理。标准模式不会递归扫描整个磁盘，适合日常使用。
- 分类检查串行执行，虽然不是理论最快，但对 1 GB VPS 更稳定，也保证输出顺序和快照行为更容易理解。

### 需要重构的部分

- `internal/audit/checks_proxy.go` 为 1246 行，同时承担策略、发现、解析、关系计算和工具函数；应拆成 `proxy_types.go`、`proxy_discovery.go`、`proxy_parsers_*.go`、`checks_proxy.go`。
- `internal/app/app.go` 为 677 行，命令路由、交互、报告管理、diff/fleet 混在一起；应按子命令拆分。
- UFW、`sshd -T`、Docker 和 journal 仍存在直接重复调用。应把所有昂贵事实纳入 FactStore，并记录采集错误/截断状态，保证同一次报告使用同一快照。
- S-UI/3x-ui 依赖固定数据库 schema；适配器需要 schema 探测和版本化查询，否则面板升级后容易整组 `UNKNOWN`。
- Bundle 默认目录精确到秒，极端情况下同一主机同一秒运行两次会覆盖固定文件；应拒绝已有目录或追加短随机后缀。

## 测试质量

- 共 25 个 Go 文件、约 6927 行；4 个测试文件、约 696 行。
- 总语句覆盖率 24.7%。`redact` 81.4%，`report` 75.7%，解析器多在 75–100%；真实检查编排、FactStore、Commander 和大部分 CLI 子命令接近 0%。
- CI 已运行格式检查、脚本语法、vet、race、amd64/arm64 交叉构建和 CodeQL。
- 四台真实 VPS 正反场景很有价值，但目前是人工测试，无法阻止未来 PR 悄悄改变状态判断。

建议引入 `FakeCommander`/fixture-driven 集成测试，把每个检查的 PASS/RISK/INFO/UNKNOWN 路径固定下来；第一阶段目标不是追求 100%，而是把审计策略层提升到 55–65%。对地址、manifest、sudoers、监听解析和配置解析增加 fuzz 测试。

## 当前功能清单

项目包含 16 类、48 个稳定检查项：

- 系统与资源：权限覆盖、时间同步、CPU/内存/swap/磁盘/load/uptime、BBR/拥塞控制/qdisc。
- 账户与 SSH：额外 UID 0、登录账户、密码策略上下文、`sshd -T` 生效配置、密钥指纹/弱算法、目录和文件权限。
- 权限与完整性：NOPASSWD、SUID/SGID、capabilities、APT 来源、`dpkg --verify`。
- 网络与防火墙：监听/连接分类、公网预期、UFW、firewalld、nftables、iptables。
- 认证与更新：SSH 失败活动、sudo journald、Fail2ban/CrowdSec、安全/普通/phased 更新线索、自动更新与重启提示。
- systemd、Docker 与可靠性：失败服务、已删除可执行文件、容器隔离/挂载/发布端口、OOM、core dump、inode、journald 和 Docker 空间。
- TLS：文件证书有效期、续期 timer/service、S-UI 内嵌材料的隐私安全可见性。
- 持久化：systemd、timer、cron、rc.local、`ld.so.preload`、临时目录执行和可疑下载/解码执行模式。
- 代理专项：sing-box、Xray、Reality、Hysteria2、TUIC、Trojan、Shadowsocks、OpenVPN、WireGuard；S-UI 与 3x-ui 深度数据库适配；Hiddify/Marzban/Outline 容器线索；控制 API、管理/订阅/代理角色、TCP/UDP、进程、监听和 UFW 关系、原生配置自检、服务隔离和隐私安全日志计数。

产品能力还包括：中英双语、auto/general/proxy/web/docker/mixed/custom profile、文本/JSON/Markdown/离线 HTML、完整报告包、SHA-256 manifest、脱敏、历史 diff、fleet 汇总、重新渲染、doctor/checks/explain、标准/深度模式、一行临时运行和带校验和的 amd64/arm64 Release。

## 下一步路线

### 第一优先：v0.6.1 质量加固

修复 AUD-001 至 AUD-005；拆分大文件；补 FakeCommander、策略集成测试、fuzz 和 govulncheck。此阶段不增加新检查 ID。

### 第二优先：统一防火墙事实模型

目前代理端口关系最懂 UFW。下一版应把 UFW、firewalld、nftables、iptables/ip6tables 统一成 `(family, protocol, port, source, action)`，明确覆盖 IPv4、IPv6、TCP、UDP，并在无法解析时给 `UNKNOWN`。这是减少代理 VPS 误报最有价值的功能增量。

### 第三优先：面板适配器框架与更多真实面板

建立版本化 `PanelAdapter`，再对 Marzban、Hiddify 做真实 Docker/Compose、配置、反向代理和监听关系适配；Outline 保持较窄范围。新增适配必须有匿名 fixture 和至少一台真实实验机验证。

### 第四优先：基线与变更检测

在已有 `diff` 上增加本地 baseline：允许用户声明预期面板、服务、端口和授权密钥指纹，并突出“新增公网端口、SSH key、systemd unit、容器或防火墙变化”。这比继续堆静态阈值更适合长期运维。

### 第五优先：反向代理与源站暴露关系

解析 Nginx/Caddy/HAProxy 的生效监听、upstream 和证书关系；结合本机 IPv4/IPv6 与防火墙证据判断源站是否可直接访问。外部 DNS/CDN 探测必须保持显式 opt-in，不能破坏默认离线、只读边界。

不建议加入自动修复、主观安全评分、默认主动网络探测或“客户端一定可用”的承诺。

## 最终判断

- 功能成熟度：较高，已形成有差异化的代理 VPS 审计产品。
- 正确性方向：好，证据链和 UNKNOWN 语义明显优于常见 Bash 体检脚本。
- 运行效率：好，标准模式无需为了速度重写或并发化。
- 代码优雅度：中等；边界设计不错，但文件职责和事实采集还需要一轮工程化重构。
- 安全与隐私：总体好，没有发现高危漏洞；存在三个应尽快修的小而真实的边界问题。
- 是否继续：值得继续，但应从“继续加功能”切换为“先加固，再做少数代理专项杀手功能”。
