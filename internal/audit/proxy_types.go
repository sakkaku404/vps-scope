package audit

import "regexp"

// proxyInbound is the normalized, non-secret view of a configured ingress.
type proxyInbound struct {
	Product          string
	Protocol         string
	Listen           string
	Port             string
	Transports       []string
	Security         string
	RealityEnabled   bool
	RealityKeySet    bool
	RealityTargets   int
	RealityServerIDs int
}

type controlEndpoint struct {
	Product string
	Kind    string
	Listen  string
	Port    string
}

type proxyConfigSummary struct {
	Product        string
	Path           string
	SensitiveFiles []string
	Inbounds       []proxyInbound
	Controls       []controlEndpoint
	UsesUDP        bool
	Parseable      bool
	Err            error
}

// configuredProxyInbound retains the source path while deduplicating a panel
// database and the generated runtime configuration that describe one ingress.
type configuredProxyInbound struct {
	Path string
	proxyInbound
}

var proxyProcessPattern = regexp.MustCompile(`(?i)\b(sing-box|xray|x-ui|s-ui|sui|hysteria|tuic|trojan|ss-server|sslocal|marzban|hiddify|outline-ss-server|wg-quick|openvpn)\b`)
