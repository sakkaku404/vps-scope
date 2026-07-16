# Compatibility matrix / 兼容矩阵

This matrix distinguishes recognized software from evidence exercised on a reproducible fixture or disposable host. It is not a promise that an unknown fork or future database layout is compatible.

本表把“识别到软件”和“已验证其证据链”分开。未知分支、未来数据库结构或非标准部署不会被乐观地当作兼容。

| Target | Adapter/schema | Evidence covered | Validated environment |
|---|---|---|---|
| Ubuntu | host v1 | 22.04 and 26.04; systemd, journald, UFW/nftables, Docker | disposable amd64 VPS |
| Debian | host v1 | 12 and 13; systemd, journald, UFW/nftables | disposable amd64 VPS |
| Linux architecture | release target | amd64 and arm64 static builds | CI cross-build; amd64 live matrix |
| S-UI | `s-ui/native-v1`, `s-ui-db-v1` | management/subscription/inbound roles, Reality, Hysteria2, Shadowsocks, TLS, permissions, systemd and listener/firewall relation | Debian 13 native S-UI 1.5.3 install; schema-only 1.5.3 fixture |
| 3x-ui / x-ui | `x-ui/native-v1`, `x-ui-db-v1` | management/subscription roles, defaults, credentials signal, Xray ingress, Reality/Trojan/Shadowsocks/VMess, runtime drift | Debian 12 and Ubuntu 22.04 native installs plus anonymous variants |
| Marzban | `marzban/managed-v1`, `marzban-config-v1` | allowlisted environment, Uvicorn management, generated Xray, Docker and host-network context | Ubuntu 26.04 official Docker deployment |
| Hiddify | `hiddify/managed-v1`, `hiddify-config-v1` | loopback controls, split Xray/sing-box configs, Mieru TCP/UDP, HAProxy relation | Ubuntu 22.04 managed install |
| Outline | `outline/container-v1`, `outline-shadowbox-v1` | management API vs Shadowsocks TCP/UDP ingress, container/network/firewall relation | Ubuntu 26.04 official container |
| sing-box | config/native-check v1 | inbound protocol/transport, Reality/Hysteria2/TUIC/Trojan/Shadowsocks, control API, `sing-box check` | Debian 12, sing-box 1.13.14 |
| Xray | config/native-check v1 | ingress/API, Reality/Trojan/VMess, `xray run -test`, panel-generated config | 3x-ui 3.4.2 deployment |
| WireGuard | kernel/config v1 | interface, UDP listener, peer/handshake counts, private-key file posture | Debian 12 to Ubuntu 26.04 lab tunnel |
| OpenVPN | config/runtime v1 | server protocol/port/listen and runtime/firewall relation | Debian 12, OpenVPN 2.6 |
| Nginx/Caddy/HAProxy | reverse-proxy v1 | public frontend to local/external backend, panel route, TLS/front-door relationship | Marzban, S-UI and Hiddify lab chains |
| Docker/Compose | inspect/forward-path v1 | isolation, mounts, socket, namespaces, publication, INPUT vs FORWARD/DOCKER-USER | Ubuntu 26.04 safe and deliberately risky fixtures |

## Compatibility contract / 兼容规则

- Canonical reports use `schema_version: 1.0`; the machine-readable contract is [`schemas/report-v1.schema.json`](../schemas/report-v1.schema.json).
- Existing finding IDs are permanent within report schema 1.0. New checks are append-only.
- Native S-UI and 3x-ui/x-ui database capabilities are enabled only after a recognized schema; an unknown table/column fingerprint is reported without exporting row data.
- New panels are added only for a concrete user layout with a sanitized fixture or disposable-host reproduction, documented ownership boundaries, and both expected and adverse tests.
- Recognition alone can produce inventory (`INFO`), but cannot produce a security `PASS` for an unsupported schema or unreadable runtime path.
