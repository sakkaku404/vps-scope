# Stability and compatibility policy / 稳定性与兼容策略

VPS Scope 1.x treats the machine-readable audit contract as a public interface. Human-readable reports may become clearer, but automation should consume canonical JSON rather than terminal text.

VPS Scope 1.x 将机器可读的审计格式视为公开接口。终端、文本、Markdown 和 HTML 报告可以继续改善排版；自动化工具应读取规范 JSON，而不是解析人类可读文本。

## Guaranteed throughout 1.x / 1.x 内的保证

- `schema_version: "1.0"` reports remain readable by current 1.x commands. Existing required fields keep their meaning; new fields are optional unless a new report schema is introduced.
- The 51 check IDs published at 1.0 are permanent and append-only. An ID is never reused for another check, and a new check receives a new ID.
- Existing `reason_code` values keep their meaning. New reason codes may be added when evidence becomes more precise, without changing the meaning of an existing code.
- Canonical statuses remain `PASS`, `RISK`, `INFO`, and `UNKNOWN`. Failed or incomplete collection does not become `PASS`.
- JSON reports created before 1.0 remain accepted according to the contract available in their tool version. Baseline v1 remains readable with its weaker identity warning; baseline v2 is the stable 1.x baseline format.
- Public commands and long flags documented in the README remain available during 1.x. A planned removal is deprecated for at least one minor release first.
- Audit findings, including `RISK`, do not by themselves make `audit` fail. Process failure is reserved for invalid arguments, unsupported hosts, collection startup failure, or output-generation failure. Commands such as `baseline check` and `verify` fail when the requested comparison or validation fails.
- Ubuntu and Debian on Linux amd64 and arm64 are the supported 1.x platform family. Unsupported distributions fail explicitly rather than receiving optimistic results.

- `schema_version: "1.0"` 的报告在 1.x 中保持可读。既有必填字段不改变含义；除非引入新的报告 schema，否则新增字段必须是可选的。
- 1.0 发布时已有的 51 个检查 ID 永久保留，只能追加，不能改作其他用途。
- 既有 `reason_code` 不改变含义。证据模型变得更精确时可以增加新原因码，但不能偷偷重定义旧原因码。
- 规范状态保持为 `PASS`、`RISK`、`INFO` 和 `UNKNOWN`；取证失败或证据不完整不能变成 `PASS`。
- 1.0 以前生成的 JSON 按其工具版本已有的契约继续可读。baseline v1 继续以较弱身份提示方式兼容，baseline v2 是稳定的 1.x 基线格式。
- README 已公开的命令和长参数在 1.x 内保持可用；若确需移除，至少提前一个次版本标记弃用。
- `RISK` 本身不会让 `audit` 进程失败。参数错误、不支持的系统、采集无法启动或报告生成失败才是执行失败；`baseline check`、`verify` 等验证命令在验证不通过时返回失败。
- 1.x 正式支持 Ubuntu/Debian 的 Linux amd64、arm64；不支持的发行版会明确失败，不会得到乐观结果。

## Allowed compatible growth / 允许的兼容扩展

- New check IDs, reason codes, optional facts, evidence records, profiles, panel adapters, and render improvements.
- More precise decisions when new evidence is available, provided the evidence and reason code explain the change.
- Additional optional files in a future, newly versioned support-bundle schema. Existing bundle schemas keep their required allowlisted file sets.

可以增加新的检查 ID、原因码、可选 facts/evidence、profile、面板适配器和报告呈现方式。新证据可以让判断更精确，但报告必须用证据和原因码说明变化。支持包若要增加文件，需要使用新的支持包 schema；既有 schema 的文件集合保持不变。

## Requires a new major or schema / 需要新主版本或新 schema

- Removing or repurposing a check ID.
- Changing the meaning of a canonical status or an existing reason code.
- Making a previously optional report field required for old readers.
- Removing a documented command or long flag without the 1.x deprecation window.
- Enabling network access by default or changing the audit from read-only behavior.

删除或改用检查 ID、改变状态或既有原因码含义、让旧读者必须理解原本可选的字段、未经弃用期删除公开命令，以及默认启用网络访问或改变只读审计原则，都需要新的主版本或报告 schema。

## Not guaranteed / 不作保证

- Terminal, text, Markdown, and HTML wording or layout is not a parsing API.
- A host-local audit cannot prove that a server is uncompromised, inspect provider security groups, or replace an external client connectivity test.
- Unknown panel forks and future database layouts may remain `UNKNOWN` until a sanitized fixture or disposable-host reproduction is available.
- A redacted or support report still requires human review before publication.

终端和人类可读报告的措辞、颜色与排版不是解析接口。本机审计不能证明服务器绝对未被入侵，不能读取云厂商安全组，也不替代外部客户端连通性测试。未知面板分支和未来数据库结构可以保持 `UNKNOWN`；任何脱敏报告在公开前仍需人工检查。
