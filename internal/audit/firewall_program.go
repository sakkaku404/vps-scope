package audit

import (
	"sync"
	"time"
)

// firewallProgram is the raw, point-in-time firewall evidence shared by the
// host INPUT and Docker FORWARD projections. Each expensive ruleset export is
// executed at most once, so the two policies cannot accidentally describe
// different generations of a ruleset during a reload.
type firewallProgram struct {
	cmd Commander

	collectOnce sync.Once

	nftExists bool
	nft       CommandResult

	iptables4Exists bool
	iptables4       CommandResult

	iptables6Exists bool
	iptables6       CommandResult
}

func newFirewallProgram(cmd Commander) *firewallProgram {
	return &firewallProgram{cmd: cmd}
}

func (p *firewallProgram) collect() {
	p.collectOnce.Do(func() {
		p.nftExists = p.cmd.Exists("nft")
		if p.nftExists {
			p.nft = p.cmd.Run(20*time.Second, "nft", "list", "ruleset")
		}
		p.iptables4Exists = p.cmd.Exists("iptables-save")
		if p.iptables4Exists {
			p.iptables4 = p.cmd.Run(15*time.Second, "iptables-save")
		}
		p.iptables6Exists = p.cmd.Exists("ip6tables-save")
		if p.iptables6Exists {
			p.iptables6 = p.cmd.Run(15*time.Second, "ip6tables-save")
		}
	})
}

func (p *firewallProgram) nftRuleset() (CommandResult, bool) {
	p.collect()
	return p.nft, p.nftExists
}

func (p *firewallProgram) iptablesSave(family string) (CommandResult, bool) {
	p.collect()
	if family == "ipv6" {
		return p.iptables6, p.iptables6Exists
	}
	return p.iptables4, p.iptables4Exists
}
