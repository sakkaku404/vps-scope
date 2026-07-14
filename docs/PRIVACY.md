# Report privacy

## 中文

VPS Scope 完全在本机运行，不上传报告，也不连接遥测服务。只有在用户选择输出格式或接受交互模式的默认选项时，工具才会写入报告。

以下内容不会作为证据收集：

- 密码、API Token、订阅路径、UUID 和私钥
- 完整的进程命令行
- SSH 公钥原文及邮箱等 key 注释
- `authorized_keys` 中 `command=`、`from=` 等选项的值
- 可疑持久化项目里的完整 shell 命令
- 第三方 APT URL 里的凭据、路径和查询参数
- 可能同时含有证书与私钥的 S-UI TLS 数据库 BLOB

SSH 授权只保留账户、算法、位数和 SHA-256 指纹。代理配置只保留产品、协议、监听地址、端口和控制端点类型；密码字段和任意 tag 不会进入 finding 数据模型。

完整本地报告仍可能包含主机名、公私网 IP、证书域名、用户名、文件路径、服务和容器名称、监听端口、防火墙规则、软件源和运行日志证据，应把它视为管理员数据。

公开提交 issue 前，请先运行 `vps-scope redact report.json`。脱敏会用稳定代号替换重复标识，保留它们之间的关系。发布前仍应人工看一遍结果，因为自动脱敏无法理解每一种应用自定义字符串。

面板兼容性问题优先使用 `vps-scope support report.json`。支持包不会访问原始面板数据库或配置文件，只从现有报告生成脱敏报告和允许字段清单，并附带 SHA-256 校验清单。它仍然需要在分享前人工检查。

## English

VPS Scope runs locally and does not upload reports or contact a telemetry service. Audit reports are written only when the user selects an output format or accepts the interactive default.

## Never collected as evidence

- passwords, API tokens, subscription paths, UUIDs, or private keys
- complete process command lines
- SSH public-key material or key comments such as email addresses
- values from `authorized_keys` options such as `command=` or `from=`
- complete suspicious persistence commands
- credentials, paths, or query strings from third-party APT URLs
- S-UI TLS database BLOBs that may contain certificates and private keys together

SSH access is represented by account name, key algorithm, bit length, and SHA-256 fingerprint. Proxy configuration is reduced to product, protocol, listen address, port, and control-endpoint type. Secret-bearing fields and arbitrary tags are not retained in the in-memory finding model.

## Still present in a local report

A complete local report can contain hostnames, public and private IP addresses, domains from certificates, usernames, file paths, service/container names, listener ports, firewall rules, package sources, and operational log evidence. Treat it as administrative data.

Use `vps-scope redact report.json` before attaching a report to a public issue. Redaction replaces repeated identifiers with stable placeholders so relationships remain readable. Review the result yourself before publishing it; no automatic redactor can understand every application-specific string.

Prefer `vps-scope support report.json` for panel compatibility issues. It does not access raw panel databases or configuration files; it derives an already-redacted report and allowlisted compatibility metadata from an existing report, with a SHA-256 manifest. Review it before sharing.
