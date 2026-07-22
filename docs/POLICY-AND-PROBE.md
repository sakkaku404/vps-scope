# Deployment policy and external observation / 部署策略与外部观察

Automatic discovery answers what the host appears to be doing. A policy answers what the operator intended it to do. VPS Scope keeps those concepts separate so an inferred process name cannot silently become an approved exposure rule.

自动识别回答“主机看起来正在做什么”，策略文件回答“维护者原本要求它做什么”。两者分开后，进程名称或常见端口不会悄悄变成已经获准的暴露规则。

## Policy file / 策略文件

Create a credential-free template and validate it before an audit:

```bash
vps-scope policy init policy.json
vps-scope policy validate policy.json
sudo vps-scope audit --profile proxy --policy policy.json
```

An endpoint declaration contains:

- `port` and `protocol`: live endpoint identity;
- `role`: `proxy-ingress`, `management`, `subscription`, `control-api`, `web`, `ssh`, or `other`;
- `exposure`: `public`, `restricted`, `private`, `loopback`, or `blocked`;
- optional `families`, `allowed_sources`, `require_tls`, and `require_non_default_path`;
- optional `workload` and `transport` labels used to select matching panel evidence.

Egress policy can declare accepted IPv4/IPv6 interfaces, require the same path for both families, and require `system`, `private-only`, or `loopback-only` DNS. `system` records the resolver state without restricting its scope.

策略文件不是 sing-box、Xray 或面板配置，也不保存 UUID、密码、私钥、订阅地址和域名。它只声明端口角色、暴露范围、来源限制、TLS/路径要求，以及 IPv4、IPv6 和 DNS 出口预期。完整机器约束见 [`schemas/policy-v1.schema.json`](../schemas/policy-v1.schema.json)。

`WORK-015` compares endpoint policy with configuration, listeners, panel metadata, and host firewall evidence. `WORK-016` compares egress policy with kernel routes, policy rules, and resolver scope. A missing policy is not a pass: endpoint policy is not applicable, while egress remains contextual inventory for a detected proxy host.

## Second-vantage observation / 第二观察点

The audit report contains a credential-free structured listener inventory. Generate a plan on the audited host:

```bash
vps-scope probe plan --target 203.0.113.10 --output plan.json report.json
```

If no policy was attached and a known management endpoint needs an explicit role, add `--management 2095/tcp,2053/tcp`. Copy only `plan.json` to another controlled host and run:

```bash
vps-scope probe run --timeout 3s --observer lab-b --output observation.json plan.json
```

Copy the observation back and create a new report; the original is never overwritten:

```bash
vps-scope probe import --output report-observed.json report.json observation.json
vps-scope verify report-observed.json
```

The observation embeds the exact plan and its SHA-256 digest, and import rejects another host's StableID or a changed endpoint sequence. This is a consistency check, not a cryptographic identity proof: the operator controls file transfer and must trust the observation host.

TCP uses bounded concurrent connects with a 500 ms to 10 s per-endpoint timeout. Reachable management/control endpoints and exposure that contradicts policy become `RISK`; a public endpoint that cannot be reached also becomes a policy mismatch. Without explicit intent, reachability remains inventory.

UDP is reported as indeterminate. A generic UDP `connect` or successful `send` does not prove that Hysteria2, TUIC, WireGuard, Shadowsocks, or another real protocol completed authentication and received a valid response. VPS Scope does not manufacture a success result from that weaker signal.

探测计划不包含节点凭据，但会包含端口、角色和目标地址，仍应只在受控机器之间传输。导入后的报告也应在公开前脱敏并人工检查。
