# 发布产物校验

VPS Scope 的发布二进制带有两层可验证信息：

- `SHA256SUMS`：适合所有 Debian/Ubuntu 主机的零额外依赖完整性校验；
- Sigstore keyless bundle：由 GitHub Actions 的 OIDC 身份签名，并绑定到本仓库的 `release.yml` 标签构建；GitHub 同时保存二进制的构建溯源证明。

Release 流水线先在仅有源码读取权限的独立 job 中执行 vet、race、测试和漏洞扫描；只有它成功后，高权限发布 job 才能获得写入 Release、OIDC 和 attestation 权限。Release 还包含 `LICENSE` 和 `THIRD_PARTY_NOTICES.txt`。后者由 Linux amd64/arm64 当前模块图中实际链接进二进制的依赖并集生成；两份文件都进入 `SHA256SUMS` 并拥有独立的 Sigstore bundle。生成过程找不到普通许可证文件、遇到异常大的许可证文件或结果不确定时会直接终止发布。上传前，流水线会再次验证全部校验和、五份签名和精确的十文件集合。

`install.sh` 和 `run.sh` 始终校验 SHA-256。若系统已有 `cosign`，它们还会自动验证签名。显式设置 `VPS_SCOPE_VERSION=v1.1.0` 或使用安装参数 `--version v1.1.0` 时，证书身份必须精确匹配这个标签；使用 `latest` 时，身份仍被限制在本仓库、`release.yml` 和规范语义版本标签范围内。需要强制签名校验时：

```bash
curl -fsSL https://sakkaku404.github.io/vps-scope/run.sh | sudo env VPS_SCOPE_REQUIRE_SIGNATURE=1 bash
```

`VPS_SCOPE_REQUIRE_SIGNATURE=1` 会在未安装 `cosign`、签名缺失或身份不匹配时停止；它不会自动安装任何软件。

也可以手动对已下载的二进制验证：

```bash
cosign verify-blob --bundle vps-scope_linux_amd64.sigstore.json \
  --certificate-identity 'https://github.com/sakkaku404/vps-scope/.github/workflows/release.yml@refs/tags/v1.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vps-scope_linux_amd64
```

将示例中的 `v1.1.0` 换成实际下载的标签。签名说明二进制由预期 GitHub Actions 工作流和标签构建；它不替代你对下载脚本、版本选择和目标主机权限的判断。脚本默认仍只读取服务器状态，审计本身不修改系统配置。
