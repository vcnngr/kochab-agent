package rules

import (
	"context"
	"regexp"
	"strings"
)

const RuleCodeFirewallDefaultDeny = "firewall.default_deny"

func init() {
	RegisterRule(RuleCodeFirewallDefaultDeny, checkFirewallDefaultDeny)
}

var (
	nftDropRe   = regexp.MustCompile(`(?i)chain\s+input[^{}]*\{[^}]*type\s+filter\s+hook\s+input[^}]*policy\s+(drop|reject)`)
	ufwDenyRe   = regexp.MustCompile(`(?i)default:\s*(deny|reject)\s*\(incoming\)`)
	iptDropRe   = regexp.MustCompile(`(?i)Chain\s+INPUT\s+\(policy\s+(DROP|REJECT)\)`)
	ufwActiveRe = regexp.MustCompile(`(?i)Status:\s*active`)
)

// checkFirewallDefaultDeny inspects nft → ufw → iptables, in that order. Pass
// if any one of them has a default-deny INPUT policy. Skip if none is
// installed (rare on Debian 12 minimal but possible in chrooted CI).
func checkFirewallDefaultDeny(ctx context.Context) (bool, map[string]any, error) {
	// nftables.
	if out, _, err := cmdOutput(ctx, "nft", "list", "ruleset"); err == nil {
		if nftDropRe.MatchString(out) {
			return true, map[string]any{"backend": "nftables"}, nil
		}
	} else if !isCmdNotFound(err) && ctx.Err() == nil {
		// nft present but failed → continue to next backend.
	}

	// ufw.
	if out, _, err := cmdOutput(ctx, "ufw", "status", "verbose"); err == nil {
		if ufwActiveRe.MatchString(out) && ufwDenyRe.MatchString(out) {
			return true, map[string]any{"backend": "ufw"}, nil
		}
	} else if !isCmdNotFound(err) && ctx.Err() == nil {
		// continue
	}

	// iptables.
	if out, _, err := cmdOutput(ctx, "iptables", "-L", "INPUT", "-n"); err == nil {
		// First line carries policy.
		first := firstLine(out)
		if iptDropRe.MatchString(first) {
			return true, map[string]any{"backend": "iptables"}, nil
		}
	} else if !isCmdNotFound(err) && ctx.Err() == nil {
		// continue
	}

	// No backend reported default-deny. If none was even installed, treat as
	// hard fail (a Debian 12 host with no firewall is failing the rule).
	return false, map[string]any{
		"checked_backends": []string{"nftables", "ufw", "iptables"},
		"hint":             strings.TrimSpace("Nessun firewall in default deny rilevato. Abilita ufw o nftables."),
	}, nil
}
