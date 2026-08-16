# VPS Scope v0.7.0 代码与产品审计

> 历史快照：本文只描述当时的版本、测试环境和结论，不代表当前代码或最新 Release。当前状态以 README、CHANGELOG 和发布准备度文档为准。

## 执行摘要

VPS Scope 已达到“可公开使用的早期成熟版本”：发布流程完整，默认只读，证据不足不会冒充 `PASS`，核心命令有超时和输出上限，报告默认以 0600 权限写入，安装资产经过 SHA-256 校验，并且已经在四台 Debian/Ubuntu 实验 VPS 上反复读取真实报告验证。

本轮未发现 Critical 或 High 级代码安全漏洞。代码仍不能称为完全优雅：审计策略、证据采集和产品适配仍有耦合，测试覆盖率不足以支持快速扩张，v0.7.0 新增的 baseline 与统一防火墙模型各有一个需要优先修复的正确性边界。

## 发现

### AUD-101 — Medium — baseline 只用 hostname 识别主机

- 位置：`internal/app/baseline.go:15-19, 58-61, 76-77`
- 证据：baseline 保存 `Host string`，创建时使用 `r.Host.Hostname`，检查时只比较 hostname；报告模型已经提供 `Host.StableID`，但 baseline 没有保存它。
- 影响：云镜像常使用相同 hostname。用户可能把一台服务器的 baseline 用到另一台同名服务器，并在稳定项目碰巧一致时得到错误的 `PASS`。
- 修复：baseline v2 同时保存 `stable_id`；检查时优先比较 StableID，旧 v1 文件继续兼容但明确提示身份保证较弱。
- 缓解：目前为不同服务器使用唯一 hostname，并把 baseline 与对应报告放在同一主机目录。
- 误报说明：若所有主机 hostname 都由用户保证全局唯一，风险下降，但工具本身无法证明这一前提。

### AUD-102 — Medium — iptables 默认策略没有按地址族保存

- 位置：`internal/audit/checks_host.go:214-217`，`internal/audit/firewall_facts.go:43-54, 164-194, 201-233`
- 证据：IPv4 与 IPv6 规则带有 `Family`，但默认策略只有一个 `defaultDeny bool`；收集时使用逻辑 OR 合并两个地址族。
- 影响：例如 IPv4 INPUT 为 DROP、IPv6 INPUT 为 ACCEPT 时，IPv6 监听可能被解释为 `blocked-by-default`。这会造成防火墙/监听关系误判，并可能掩盖 IPv6 暴露。
- 修复：将默认策略改为按 `ipv4`、`ipv6`、`inet` 保存的映射，`firewallDispositionFamily` 只读取对应地址族；为四种组合增加策略场景。
- 缓解：v0.7.0 用户应结合 `FW-001/FW-002` 原始证据复核只使用 iptables/ip6tables 且启用 IPv6 的主机。
- 误报说明：UFW 和 `inet` nftables 同时覆盖双栈时通常不受此问题影响。

### AUD-103 — Low — baseline 公网监听项目可能包含 PID

- 位置：`internal/audit/helpers.go:135-153`，`internal/app/baseline.go:88-92`
- 证据：监听解析把 `ss` 的进程尾部原样保存，baseline 又把完整 NET-001 evidence 当作稳定项目。
- 影响：服务仅仅正常重启、PID 改变，也可能产生 baseline `ADDED/REMOVED`，形成噪声并降低用户对变更检测的信任。
- 修复：建立结构化 `ListenerIdentity`，baseline 只保留协议、地址/范围、端口和规范化进程名，不保存 PID、fd 或瞬时队列信息。
- 缓解：出现只有 PID 变化的漂移时人工核对，不要把它当作新增端口。

### AUD-104 — Low — 本地报告与 baseline JSON 没有统一大小上限

- 位置：`internal/app/compare_commands.go:82-94`，`internal/app/baseline.go:125-139`
- 证据：`json.Decoder` 直接读取用户指定的文件；bundle manifest 已限制为 1 MiB，但独立的 `diff`、`fleet`、`render`、`redact` 和 baseline 输入没有同等级上限。
- 影响：打开恶意或意外超大的本地 JSON 可能导致较高内存占用。这不是远程攻击面，但属于 CLI 资源边界不一致。
- 修复：统一使用有文件大小检查和 `io.LimitReader` 的报告读取函数，并为超限输入增加测试。
- 缓解：只处理本工具生成且来源可信的报告。

## 代码质量

优点：

- `OSCommander` 使用 `exec.CommandContext` 和参数数组，不通过 shell；每个命令有超时，每个 stdout/stderr 最大 8 MiB。
- `FactStore` 缓存进程、监听、防火墙、Docker 和面板事实，减少重复采集和同一次审计中的时间漂移。
- 状态模型明确区分 `PASS / RISK / INFO / UNKNOWN`，panic 被转换为内部 `UNKNOWN`。
- HTML 使用静态 `html/template`，报告 bundle 限制文件名、数量和 manifest 大小，写入采用临时文件、0600 权限和原子重命名。
- CGO-free SQLite 以只读模式打开面板数据库；不导出 UUID、密码、Reality/WireGuard 私钥或完整日志。
- CI 固定 Actions commit，执行 module verify、govulncheck、gofmt、shell 语法、vet、race 和 amd64/arm64 构建。

债务：

- `checks_proxy.go` 约 790 行、`checks_network_auth.go` 约 623 行、`app.go` 约 564 行；职责虽已拆出一部分，仍偏大。
- 检查函数仍同时负责采集、解析、策略和证据渲染，新增后端容易复制分支逻辑。
- `audit` 语句覆盖率约 36.5%，`app` 约 28.6%；对安全审计工具而言仍偏低，尤其是错误路径和多后端组合。
- UFW/firewalld 的基础检查仍会重复执行部分命令，没有完全消费统一事实快照。

## 产品能力盘点

- 16 个领域、48 项检查，覆盖系统、账户、SSH、提权、网络、防火墙、认证日志、更新、软件包、进程、Docker、TLS、代理/Web、文件权限、持久化和可靠性。
- 代理语义覆盖 sing-box、Xray、Reality、Hysteria2、TUIC、Trojan、Shadowsocks、WireGuard、OpenVPN，以及 Nginx/Caddy/HAProxy 和 Docker/Compose 线索。
- S-UI 与 3x-ui/x-ui 有原生版本化适配器、数据库 schema 探测、管理/订阅/代理入口角色、配置/监听/进程/防火墙关系。
- 输出支持中英文终端、JSON、Markdown、离线 HTML 和带 manifest 的完整报告包。
- 产品命令包括交互审计、`doctor`、`checks`、`explain`、`diff`、`fleet`、`render`、`redact`、`verify`、报告管理和 baseline。
- 默认标准审计保持轻量，递归特权文件和包完整性检查放在 `--deep`；不提供自动修复。
- GitHub Release 提供 Linux amd64/arm64 单文件二进制、SHA256SUMS 和一行运行入口。

## 建议路线

1. v0.7.1 正确性加固：修复 AUD-101 至 AUD-104，优先处理双栈防火墙默认策略和 baseline 身份/规范化。
2. 测试与架构：把各领域逐步拆成 collector、parser、policy 三层；将关键策略场景扩展到 nftables set、firewalld rich rules、双栈 iptables、未知面板 schema 和 baseline 迁移。
3. v0.8.0 真实面板扩展：在有真实实验环境和匿名 fixture 的前提下，优先做 Marzban、Hiddify 的 Docker/Compose、反向代理、管理 API 和源站暴露关系；Outline 保持较窄范围。
4. 稳定产品接口：为 report/baseline schema 增加迁移与兼容性测试，并建立匿名 golden report，防止文案或证据格式变化导致 baseline 噪声。

结论：项目值得继续完善，但不应马上继续堆检查数量。先完成 v0.7.1 的正确性和结构化事实加固，再扩展新面板，收益最高。

## 后续处理结果

本审计列出的 AUD-101 至 AUD-104 已在后续开发中修复并加入回归测试：baseline v2 使用 StableID、监听身份去除 PID/fd、iptables/nftables 默认策略按地址族保存，独立 JSON 输入统一限制为 64 MiB 并拒绝尾随文档。旧 baseline v1 仍可读取，但会明确提示身份保证较弱。

建议路线中的面板与兼容性工作也已落地：新增 Marzban 与 Hiddify 版本化托管安装适配器、匿名 golden report、report v1 与 baseline v1/v2 兼容测试。适配器已在官方 Marzban Docker 部署和 Hiddify Manager 12.3.3 实机上回归，配置端点与实际 TCP/UDP 监听没有缺失关系。
