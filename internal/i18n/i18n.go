package i18n

import (
	"os"
	"strings"
)

type Text struct {
	ZH string
	EN string
}

type Rule struct {
	Title          Text
	Why            Text
	Recommendation Text
}

func newRule(titleZH, titleEN, whyZH, whyEN, recommendationZH, recommendationEN string) Rule {
	return Rule{
		Title:          Text{ZH: titleZH, EN: titleEN},
		Why:            Text{ZH: whyZH, EN: whyEN},
		Recommendation: Text{ZH: recommendationZH, EN: recommendationEN},
	}
}

func Locale(requested string) string {
	switch strings.ToLower(requested) {
	case "zh", "zh-cn", "cn":
		return "zh-CN"
	case "en", "en-us", "en-gb":
		return "en"
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if strings.HasPrefix(strings.ToLower(os.Getenv(key)), "zh") {
			return "zh-CN"
		}
	}
	return "en"
}

func Pick(t Text, locale string) string {
	if locale == "zh-CN" {
		return t.ZH
	}
	return t.EN
}

var Categories = map[string]Text{
	"system":      {"系统与审计上下文", "System and audit context"},
	"accounts":    {"用户与账户", "Users and accounts"},
	"ssh":         {"SSH", "SSH"},
	"privileges":  {"权限与提权面", "Privileges and elevation"},
	"network":     {"网络与监听端口", "Network and listeners"},
	"firewall":    {"防火墙", "Firewall"},
	"auth":        {"认证、入侵防护与 sudo 日志", "Authentication, intrusion prevention, and sudo logs"},
	"updates":     {"系统更新", "System updates"},
	"packages":    {"软件包与供应链", "Packages and supply chain"},
	"processes":   {"进程与 systemd 服务", "Processes and systemd services"},
	"docker":      {"Docker 隔离", "Docker isolation"},
	"tls":         {"TLS 与证书", "TLS and certificates"},
	"workloads":   {"Web 与代理工作负载", "Web and proxy workloads"},
	"filesystem":  {"文件系统与敏感信息", "Filesystem and secrets"},
	"persistence": {"可疑持久化线索", "Suspicious persistence indicators"},
	"reliability": {"可靠性与日志", "Reliability and logging"},
}

var Rules = map[string]Rule{
	"WORK-014":    newRule("可选外部 DNS 与 TLS 观察", "Optional external DNS and TLS observation", "VPS 内部状态无法独自证明域名、IPv6 和 CDN 回源是否按预期隐藏；外部 DNS 与 TLS 证据可以补充判断。", "Internal VPS state cannot by itself prove whether domains, IPv6, and CDN origin routing are hidden as intended; external DNS and TLS evidence adds context.", "仅在明确需要时启用网络观察；若声明使用 CDN，应核对域名是否仍直接发布源站地址，并从另一台主机复核实际可达性。", "Enable network observation only when explicitly needed; when CDN use is declared, review whether DNS still publishes the origin and verify reachability from another host."),
	"WORK-013":    newRule("反向代理暴露链", "Reverse-proxy exposure chain", "反向代理链路缺失、后端监听过宽，或公网路由能够到达管理面，都会扩大故障或攻击范围。", "Missing reverse-proxy links, over-broad backend listeners, or public routes reaching a management plane can expand outage or attack impact.", "核对前后端监听与防火墙；管理路由至少应有可靠认证和非默认路径，条件允许时再限制到 VPN 或可信来源。", "Review frontend/backend listeners and firewall policy; management routes need strong authentication and a non-default path, and should be limited to a VPN or trusted sources when practical."),
	"WORK-012":    newRule("代理面板角色与运行态一致性", "Proxy panel roles and runtime consistency", "管理、订阅和代理入口应有明确角色，面板数据库、生成配置和实际监听不一致可能表示遗留配置、未生效变更或错误暴露；公网订阅链接还应使用 TLS，避免其中的访问凭据被明文传输。", "Management, subscription, and proxy ingress need explicit roles; disagreement between the panel database, generated configuration, and live listeners can indicate stale state, unapplied changes, or unintended exposure. Public subscription links should also use TLS so their access credentials are not sent in plaintext.", "核对角色冲突、已启用但未监听的入口和未分类面板端口；不要把订阅端口误判为管理端口，并为公网订阅端点启用 TLS。", "Review role collisions, enabled-but-not-listening ingress, and unclassified panel-owned ports; do not mistake subscription endpoints for management ports, and enable TLS for public subscription endpoints."),
	"WORK-011":    newRule("WireGuard 接口与监听关系", "WireGuard interface and listener relation", "活动接口、UDP 监听和防火墙策略不一致会导致不可用或意外暴露。", "An active interface, UDP listener, and firewall policy that disagree can cause an outage or unintended exposure.", "核对接口监听端口、主机防火墙和近期握手；报告不会导出 peer 公钥或 endpoint。", "Review the interface port, host firewall, and recent handshakes; the report never exports peer public keys or endpoints."),
	"WORK-010":    newRule("代理服务日志信号", "Proxy service log signals", "认证、握手、DNS、TLS 和路由错误有助于定位攻击活动与可用性故障，但单纯计数不能证明漏洞。", "Authentication, handshake, DNS, TLS, and routing errors help locate attacks and outages, but counts alone do not prove a vulnerability.", "结合服务状态、时间趋势和客户端反馈调查；报告仅保留分类计数，不导出原始日志中的地址或凭据。", "Investigate with service state, trends, and client reports; the audit retains category counts rather than raw addresses or credentials."),
	"SYS-004":     newRule("网络内核实际状态", "Network kernel runtime state", "拥塞控制与队列算法应作为运行事实展示，不能脱离线路与负载武断评分。", "Congestion control and queue discipline are runtime facts and should not be scored without workload and path context.", "结合实际吞吐、延迟和丢包评估；不要仅因算法名称修改内核参数。", "Evaluate with observed throughput, latency, and loss; do not change kernel settings based only on an algorithm name."),
	"PERSIST-002": newRule("临时目录中的运行程序", "Executables running from temporary directories", "从 /tmp、/var/tmp 或 /dev/shm 直接运行的程序常见于投放器、挖矿程序和无文件持久化。", "Programs executing from temporary directories are common in droppers, miners, and fileless persistence.", "核对进程来源、父进程、文件哈希和启动方式；确认前不要直接删除取证材料。", "Review process origin, parent, file hash, and startup path; preserve evidence before removal."),
	"REL-002":     newRule("日志与 inode 占用", "Log and inode pressure", "磁盘仍有容量并不代表 inode 或日志配额仍然充足。", "Free disk bytes do not guarantee sufficient inodes or log quota.", "结合增长趋势检查 inode、journald 和 Docker 存储占用，并为异常增长设置外部监控。", "Review inode, journald, and Docker storage growth and add external monitoring for abnormal growth."),
	"SYS-001":     newRule("审计权限与覆盖范围", "Audit privilege and coverage", "权限不足可能使部分证据不可见。", "Insufficient privileges can hide relevant evidence.", "需要完整报告时以 root 运行；工具不会自动提权。", "Run as root for full coverage; the tool never elevates itself."),
	"SYS-002":     newRule("系统时间同步", "System time synchronization", "错误时间会破坏日志顺序、证书验证和事件关联。", "Incorrect time breaks log ordering, certificate validation, and event correlation.", "检查 systemd-timesyncd、chrony 或其他时间同步服务。", "Check systemd-timesyncd, chrony, or another time synchronization service."),
	"SYS-003":     newRule("系统资源概览", "System resource overview", "CPU、内存、磁盘、负载和运行时间有助于解释可靠性事件，但单次快照不应被当成安全漏洞。", "CPU, memory, disk, load, and uptime help explain reliability events, but a single snapshot is not a security vulnerability.", "结合历史趋势和 OOM、core dump 等事件判断资源问题，不要只凭一次百分比读数告警。", "Use trends and events such as OOM kills and core dumps; do not alert on one percentage snapshot alone."),
	"ACC-001":     newRule("额外 UID 0 账户", "Additional UID 0 accounts", "任何 UID 0 账户都拥有 root 权限。", "Every UID 0 account has root privileges.", "确认每个 UID 0 账户均为明确授权。", "Confirm every UID 0 account is explicitly authorized."),
	"ACC-002":     newRule("具备登录 shell 的账户", "Accounts with login shells", "交互账户扩大凭据和持久化攻击面。", "Interactive accounts expand credential and persistence exposure.", "核对账户清单并锁定不再需要的账户。", "Review the account inventory and lock accounts that are no longer needed."),
	"ACC-003":     newRule("上下文密码策略", "Contextual password policy", "只有在 SSH 密码路径可用且存在本地密码账户时，缺少密码质量机制才会直接扩大远程凭据攻击面。", "Missing password-quality enforcement directly expands remote credential exposure only when SSH passwords are usable and password-bearing accounts exist.", "优先关闭 SSH 密码和键盘交互认证；确需密码时启用 PAM 密码质量模块并核对实际账户。", "Prefer disabling SSH password and keyboard-interactive authentication; when passwords are required, enable a PAM quality module and review actual accounts."),
	"SSH-001":     newRule("SSH 密码认证", "SSH password authentication", "公网密码认证会暴露于撞库和暴力破解。", "Internet-facing password authentication is exposed to credential attacks.", "确认密钥登录可用后，再在 sshd 配置中关闭密码和键盘交互认证。", "After verifying key access, disable password and keyboard-interactive authentication in sshd."),
	"SSH-002":     newRule("SSH root 登录", "SSH root login", "直接 root 登录会放大凭据失陷后的影响。", "Direct root login increases the impact of credential compromise.", "优先使用普通管理用户和 sudo；如需 root 密钥登录，应明确记录该例外。", "Prefer an administrative user with sudo; document any required root key-login exception."),
	"SSH-003":     newRule("SSH 公钥认证", "SSH public-key authentication", "关闭公钥认证可能迫使管理员使用较弱认证方式。", "Disabling public-key authentication can force weaker authentication paths.", "确保 PubkeyAuthentication 在实际生效配置中启用。", "Ensure PubkeyAuthentication is enabled in the effective configuration."),
	"SSH-004":     newRule("SSH 密钥与目录权限", "SSH key and directory permissions", "可被其他用户修改的 SSH 文件可能导致未授权登录。", "SSH files writable by other users can permit unauthorized access.", "修复所有者和权限，并核对 authorized_keys 指纹。", "Correct ownership and modes, then review authorized_keys fingerprints."),
	"SSH-005":     newRule("SSH 授权密钥指纹", "SSH authorized-key fingerprints", "未知、重复或弱算法的授权密钥可能代表遗留访问或不安全凭据。", "Unknown, duplicated, or weak authorized keys may represent stale access or unsafe credentials.", "按用户核对 SHA-256 指纹；移除未知密钥，并替换 DSA 或不足 2048 位的 RSA 密钥。", "Review SHA-256 fingerprints per user; remove unknown keys and replace DSA or RSA keys shorter than 2048 bits."),
	"PRIV-001":    newRule("sudo NOPASSWD 授权", "sudo NOPASSWD grants", "无密码 sudo 会扩大已入侵账户的提权能力。", "Passwordless sudo expands privilege escalation after account compromise.", "确认每条 NOPASSWD 规则必要且命令范围足够窄。", "Confirm every NOPASSWD rule is necessary and narrowly scoped."),
	"PRIV-002":    newRule("SUID/SGID 与文件 capabilities", "SUID/SGID and file capabilities", "来源不明的特权可执行文件可成为提权路径。", "Untrusted privileged executables can become escalation paths.", "核对文件的软件包归属、哈希和修改时间。", "Review package ownership, hashes, and modification times."),
	"NET-001":     newRule("监听端口与地址分类", "Listening ports and address classification", "监听地址决定服务可能暴露给哪些网络。", "Listener addresses determine which networks may reach a service.", "将不需要公网访问的服务绑定到回环或私网地址。", "Bind services that do not require public access to loopback or private addresses."),
	"NET-002":     newRule("非预期公网监听", "Unexpected public listeners", "用途 profile 和显式预期清单之外的公网监听需要确认。", "Public listeners outside the workload profile and explicit expectation list require review.", "确认进程用途；需要保留时用 --expect-public 声明端口，否则限制监听地址或防火墙。", "Confirm the process purpose; declare required ports with --expect-public, otherwise restrict the listener or firewall."),
	"NET-003":     newRule("活动网络连接", "Active network connections", "活动连接可以帮助发现未知对端和进程，但连接数量本身不能证明存在漏洞。", "Active connections help reveal unknown peers and processes, but connection count alone does not prove a vulnerability.", "核对不熟悉的公网对端、进程和持续时间，并结合服务用途与日志调查。", "Review unfamiliar public peers, processes, and duration together with workload purpose and logs."),
	"FW-001":      newRule("主机防火墙策略", "Host firewall policy", "仅有 active 状态不能证明入站策略和规则安全。", "An active state alone does not prove that inbound policy and rules are safe.", "核对默认入站策略、IPv4/IPv6 规则和实际监听端口。", "Review default inbound policy, IPv4/IPv6 rules, and actual listeners."),
	"FW-002":      newRule("防火墙规则暴露范围", "Firewall rule exposure", "允许全部端口、IPv4/IPv6 策略不一致，或服务停止后遗留放行规则，都会扩大未来的意外暴露面。", "All-port rules, inconsistent IPv4/IPv6 policy, or stale allows left after a service stops can expand future accidental exposure.", "收窄任意来源规则，删除确认无用的遗留端口，并确保 IPv6 与实际监听采用一致策略。", "Narrow unrestricted rules, remove confirmed stale ports, and ensure IPv6 policy matches active listeners."),
	"AUTH-001":    newRule("SSH 失败登录活动", "SSH failed-login activity", "失败次数是攻击活动证据，但本身不等同于配置漏洞。", "Failure counts show attack activity but are not themselves a configuration vulnerability.", "结合认证方式、来源分布和成功登录记录调查。", "Investigate together with authentication methods, source distribution, and successful logins."),
	"AUTH-002":    newRule("sudo 审计证据", "sudo audit evidence", "没有可读取的 sudo 事件会降低特权操作的可追溯性。", "Unreadable sudo events reduce traceability of privileged actions.", "确认 journald 或日志文件能保留 sudo 事件。", "Confirm journald or log files retain sudo events."),
	"AUTH-003":    newRule("入侵防护运行状态", "Intrusion-prevention operational status", "只安装但未运行、Fail2ban 缺少 sshd jail，或 CrowdSec 没有执行封禁的 bouncer，都不会产生预期防护。", "An inactive installation, Fail2ban without an sshd jail, or CrowdSec without an enforcing bouncer does not provide expected protection.", "核对 Fail2ban jail，或 CrowdSec 服务、采集器和 bouncer 的实际状态。", "Review Fail2ban jails or the actual CrowdSec service, acquisition, and bouncer state."),
	"UPD-001":     newRule("待安装更新分类", "Pending update classification", "安全更新、普通更新和 phased update 的风险不同。", "Security, regular, and phased updates have different risk implications.", "优先评估并安装安全更新，正常 phased update 不应视为漏洞。", "Prioritize security updates; normal phased updates should not be treated as vulnerabilities."),
	"UPD-002":     newRule("自动安全更新", "Automatic security updates", "安装软件包不代表定时任务已启用并成功执行。", "An installed package does not prove scheduling is enabled or successful.", "核对 APT 周期配置、timer 和最近运行日志。", "Review APT periodic settings, timers, and recent execution logs."),
	"PKG-001":     newRule("APT 软件源与签名配置", "APT repositories and signing configuration", "第三方或未签名软件源会扩大供应链风险。", "Third-party or unsigned repositories increase supply-chain risk.", "核对每个第三方源的所有者、用途和 signed-by 密钥。", "Review the owner, purpose, and signed-by key for every third-party source."),
	"PKG-002":     newRule("系统包文件完整性", "Installed package file integrity", "关键包文件变化可能来自正常配置，也可能来自篡改。", "Package file changes may be legitimate configuration or tampering.", "对 dpkg 验证差异逐项确认，不要盲目恢复配置文件。", "Review dpkg verification differences individually; do not blindly restore configuration files."),
	"PROC-001":    newRule("失败或反复重启的 systemd 服务", "Failed or repeatedly restarting systemd services", "异常服务可能表示攻击、错误配置或可靠性问题。", "Abnormal services may indicate compromise, misconfiguration, or reliability issues.", "检查 unit 状态、退出码和对应 journal。", "Inspect unit state, exit codes, and the corresponding journal."),
	"PROC-002":    newRule("已删除可执行文件仍在运行", "Deleted executables still running", "已删除二进制仍运行可能是正常升级，也可能隐藏真实文件。", "Deleted binaries may remain after upgrades or conceal the running file.", "核对进程来源、启动时间、软件包和服务重启计划。", "Review process origin, start time, package, and planned service restart."),
	"DOCKER-001":  newRule("Docker 容器隔离与发布端口", "Docker isolation and published ports", "特权、host namespace、Docker socket 和宽泛挂载可能突破容器边界。", "Privileged mode, host namespaces, Docker socket, and broad mounts can break container isolation.", "逐个核对高权限选项，并确认发布端口与防火墙路径。", "Review elevated options per container and confirm published ports and firewall paths."),
	"DOCKER-002":  newRule("Docker 发布端口转发链路", "Docker published-port forwarding path", "Docker 发布端口通常经过 DNAT、FORWARD 和 DOCKER-USER，而不是主机 INPUT；只看 UFW 或 INPUT 可能误判端口已经被阻断。", "Docker-published ports commonly traverse DNAT, FORWARD, and DOCKER-USER rather than host INPUT; inspecting only UFW or INPUT can falsely imply that a port is blocked.", "核对每个公网发布端口的地址族、DOCKER-USER 规则与云防火墙；不要把 INPUT 默认拒绝当成容器端口不可达的证明。", "Review address family, DOCKER-USER policy, and the provider firewall for every public publication; do not treat an INPUT default deny as proof that a container port is unreachable."),
	"TLS-001":     newRule("TLS 证书有效期与续期", "TLS certificate validity and renewal", "即将过期或没有续期机制的证书会导致服务中断。", "Expiring certificates or missing renewal mechanisms can interrupt service.", "核对磁盘证书、实际服务证书和 ACME timer。", "Review on-disk certificates, served certificates, and ACME timers."),
	"TLS-002":     newRule("内嵌 TLS 材料可见性", "Embedded TLS material visibility", "证书与私钥共同存储在数据库 BLOB 时，安全审计不能为检查有效期而泄露私钥材料。", "When certificates and private keys share a database BLOB, an audit must not expose private material merely to inspect validity.", "在不导出私钥的前提下，从应用提供的安全接口核验证书有效期；当前结果保持 UNKNOWN。", "Verify certificate validity through a safe application interface that does not export private keys; keep the result UNKNOWN meanwhile."),
	"WORK-001":    newRule("Web 与代理工作负载识别", "Web and proxy workload detection", "用途上下文决定哪些暴露是预期的，但不会消除真实风险。", "Workload context determines expected exposure but does not erase real risk.", "确认自动识别结果，必要时显式指定 profile。", "Confirm automatic detection and explicitly select a profile when needed."),
	"WORK-002":    newRule("代理面板管理面暴露", "Proxy panel management-plane exposure", "公网监听且允许任意来源访问的管理面会扩大凭据攻击和漏洞利用面。", "A management panel bound publicly and allowed from any source expands credential and exploit exposure.", "将管理面限制到回环、VPN 或可信来源地址；订阅和代理入站应与管理端口分开处理。", "Restrict the management panel to loopback, a VPN, or trusted source addresses; treat subscription and proxy ingress separately."),
	"WORK-003":    newRule("代理核心与入口清单", "Proxy cores and ingress inventory", "只有把进程、配置入口和监听端口关联起来，才能区分预期代理流量与未知暴露。", "Correlating processes, configured ingress, and listeners is necessary to distinguish intended proxy traffic from unknown exposure.", "核对每个核心、协议和入口端口是否仍在使用；清理遗留实例与配置。", "Review whether every core, protocol, and ingress port is still required; remove stale instances and configuration."),
	"WORK-004":    newRule("代理配置解析与原生自检", "Proxy configuration parsing and native self-test", "无法解析或无法通过核心自检的活动配置可能在重启后导致服务中断。", "An active configuration that cannot be parsed or pass the core's self-test may fail after restart.", "先使用对应核心的只读检查命令确认错误，再修正配置并安排受控重启。", "Confirm the error with the core's read-only validation command, then correct the configuration and schedule a controlled restart."),
	"WORK-005":    newRule("代理控制 API 暴露", "Proxy control API exposure", "Clash、V2Ray 等控制接口通常不应直接向互联网开放，其中可能包含运行信息或管理能力。", "Clash, V2Ray, and similar control endpoints normally should not be directly internet-accessible because they may expose runtime data or administrative control.", "将控制接口绑定到回环或管理网络，并通过主机防火墙限制可信来源。", "Bind control endpoints to loopback or a management network and restrict trusted sources with the host firewall."),
	"WORK-006":    newRule("代理配置与数据库权限", "Proxy configuration and database permissions", "代理配置和面板数据库经常包含密码、UUID、私钥或订阅信息。", "Proxy configuration and panel databases commonly contain passwords, UUIDs, private keys, or subscription data.", "仅向运行服务所需的用户或组授予读取权限，禁止其他用户读取或修改。", "Grant read access only to the service user or group that needs it, and prevent access or modification by other users."),
	"WORK-007":    newRule("代理服务运行身份与隔离", "Proxy service identity and isolation", "root、capabilities、systemd 隔离和文件描述符限制决定代理核心被利用后的影响与稳定性。", "Root identity, capabilities, systemd isolation, and file-descriptor limits shape both exploit impact and reliability.", "结合协议端口、TUN 和透明代理需求收窄权限；不要仅凭通用评分盲目修改。", "Reduce privileges according to low-port, TUN, and transparent-proxy requirements; do not apply a generic hardening score blindly."),
	"WORK-008":    newRule("UDP 代理运行上下文", "UDP proxy runtime context", "Hysteria2、TUIC 和 UDP 转发对内核缓冲区、丢包计数和文件描述符限制较敏感。", "Hysteria2, TUIC, and UDP forwarding are sensitive to kernel buffers, drop counters, and file-descriptor limits.", "结合实际吞吐、丢包和日志调整参数；单个 sysctl 数值本身不应被当成漏洞。", "Tune values using observed throughput, loss, and logs; a single sysctl value is not itself a vulnerability."),
	"WORK-009":    newRule("代理入口配置与实际监听关系", "Proxy ingress configuration and live-listener relation", "配置、传输层、实际监听进程和防火墙必须相互吻合；公开的代理入口本身不等于风险。", "Configuration, transport, live listener, and firewall evidence must agree; a public proxy ingress is not inherently a risk.", "核对未监听或语义不完整的入口；对预期公开的代理入口保留明确的防火墙规则。", "Review non-listening or semantically incomplete ingress; keep explicit firewall policy for proxy ingress intended to be public."),
	"FS-001":      newRule("敏感文件和临时目录权限", "Sensitive files and temporary-directory permissions", "错误权限可能泄露凭据或允许替换高权限执行内容。", "Incorrect modes can expose credentials or allow replacement of privileged content.", "核对敏感文件所有者、mode 和临时目录 sticky bit。", "Review ownership and modes of sensitive files and sticky bits on temporary directories."),
	"PERSIST-001": newRule("可疑持久化线索", "Suspicious persistence indicators", "启动项指向临时目录、远程下载执行或未知文件需要调查。", "Startup entries using temporary paths, remote download execution, or unknown files require investigation.", "关联检查 systemd、cron、authorized_keys、rc.local 和文件来源。", "Correlate systemd, cron, authorized_keys, rc.local, and file provenance."),
	"REL-001":     newRule("OOM、core dump 与日志持久性", "OOM, core dumps, and log persistence", "资源终止、崩溃和短暂日志会掩盖安全与可靠性事件。", "Resource kills, crashes, and volatile logs can hide security and reliability events.", "核对 OOM、coredump、journal 存储和磁盘空间。", "Review OOM events, coredumps, journal storage, and disk space."),
}

func RuleFor(id string) Rule {
	if r, ok := Rules[id]; ok {
		return r
	}
	return Rule{Title: Text{ZH: id, EN: id}}
}
