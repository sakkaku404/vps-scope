# 发布产物校验

VPS Scope 的发布二进制带有两层可验证信息：

- `SHA256SUMS`：适合所有 Debian/Ubuntu 主机的零额外依赖完整性校验；
- Sigstore keyless bundle：由 GitHub Actions 的 OIDC 身份签名，并绑定到本仓库的 `release.yml` 标签构建；GitHub 同时保存二进制的构建溯源证明。

`install.sh` 和 `run.sh` 始终校验 SHA-256。若系统已有 `cosign`，它们还会自动验证签名。需要强制签名校验时：

```bash
VPS_SCOPE_REQUIRE_SIGNATURE=1 curl -fsSL https://sakkaku404.github.io/vps-scope/run.sh | sudo -E bash
```

`VPS_SCOPE_REQUIRE_SIGNATURE=1` 会在未安装 `cosign`、签名缺失或身份不匹配时停止；它不会自动安装任何软件。

也可以手动对已下载的二进制验证：

```bash
cosign verify-blob --bundle vps-scope_linux_amd64.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/sakkaku404/vps-scope/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vps-scope_linux_amd64
```

签名说明二进制由预期 GitHub Actions 工作流构建；它不替代你对下载脚本、版本选择和目标主机权限的判断。脚本默认仍只读取服务器状态，审计本身不修改系统配置。
