# 发布产物与引导脚本校验

VPS Scope 的发布二进制、`run.sh` 和 `install.sh` 都带有两层可验证信息：

- `SHA256SUMS`：适合所有 Debian/Ubuntu 主机的零额外依赖完整性校验；
- Sigstore keyless bundle：由 GitHub Actions 的 OIDC 身份签名，并绑定到本仓库的 `release.yml` 标签构建；GitHub 同时保存二进制的构建溯源证明。

Release 流水线先在仅有源码读取权限的独立 job 中执行 vet、race、测试和漏洞扫描；只有它成功后，高权限发布 job 才能获得写入 Release、OIDC 和 attestation 权限。Release 还包含 `LICENSE` 和 `THIRD_PARTY_NOTICES.txt`。后者由 Linux amd64/arm64 当前模块图中实际链接进二进制的依赖并集生成。二进制、两个引导脚本、校验和与两份许可证文件都拥有独立的 Sigstore bundle。生成过程找不到普通许可证文件、遇到异常大的许可证文件或结果不确定时会直接终止发布。流水线会先验证本地暂存的全部校验和、七份签名和精确的十四文件集合，再创建草稿 Release；随后从 GitHub 重新下载草稿中的十四个文件并重复全部验证，只有复验通过才公开 Release。

`install.sh` 和 `run.sh` 在启动后始终校验所下载二进制的 SHA-256。若系统已有 `cosign`，它们还会自动验证二进制签名。若没有 `cosign`，临时运行器 `run.sh` 会显示一行发布者签名未验证的警告，并在 SHA-256 校验成功后直接运行；设置 `VPS_SCOPE_REQUIRE_SIGNATURE=1` 会改为强制签名验证。永久安装器 `install.sh` 仍要求交互确认，非交互安装必须显式使用 `--allow-unsigned` 或设置 `VPS_SCOPE_ALLOW_UNSIGNED=1`。显式设置 `VPS_SCOPE_VERSION=v1.0.0` 或使用安装参数 `--version v1.0.0` 时，证书身份必须精确匹配这个标签；使用 `latest` 时，身份仍被限制在本仓库、`release.yml` 和规范语义版本标签范围内。

最短的一行命令会直接执行 Release 中的引导脚本，因此它不能在执行前由自己验证自己。`VPS_SCOPE_REQUIRE_SIGNATURE=1` 只会强制验证随后下载的二进制，不能追溯认证已经开始执行的脚本。需要完整验证引导链时，应先下载固定标签的脚本及其 bundle，验证后再运行：

```bash
version=vX.Y.Z
base="https://github.com/sakkaku404/vps-scope/releases/download/$version"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLO "$base/run.sh"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLo run.sh.sigstore.json "$base/run.sh.sigstore.json"
cosign verify-blob --bundle run.sh.sigstore.json \
  --certificate-identity "https://github.com/sakkaku404/vps-scope/.github/workflows/release.yml@refs/tags/$version" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  run.sh
sudo env VPS_SCOPE_VERSION="$version" VPS_SCOPE_REQUIRE_SIGNATURE=1 bash run.sh
```

先将 `vX.Y.Z` 换成需要运行、且 Release 中包含这两个脚本资产的实际标签。`VPS_SCOPE_REQUIRE_SIGNATURE=1` 会在未安装 `cosign`、二进制签名缺失或身份不匹配时停止；它不会自动安装任何软件。安装模式同理验证 `install.sh` 和 `install.sh.sigstore.json`，再执行已验证的本地脚本。

也可以手动对已下载的二进制验证：

```bash
cosign verify-blob --bundle vps-scope_linux_amd64.sigstore.json \
  --certificate-identity 'https://github.com/sakkaku404/vps-scope/.github/workflows/release.yml@refs/tags/v1.0.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vps-scope_linux_amd64
```

签名说明产物由预期 GitHub Actions 工作流和标签构建；它不替代你对版本选择和目标主机权限的判断。审计二进制默认只读取服务器状态；安装脚本只把已验证的二进制写入明确的安装目录。
