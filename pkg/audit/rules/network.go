package rules

import (
	"context"
	"net"
	"strconv"
	"strings"
)

// Story 3.2 — exposure signals for context-aware severity (FR11).
//
// Network-sensitive rules (ssh, firewall) attach a bind_scope to their
// severity_context so the platform can escalate/de-escalate severity:
//   - "public":  a listening socket is bound to a wildcard (0.0.0.0 / ::) or a
//                non-private routable address → reachable from the internet.
//   - "private": only loopback / RFC1918 / link-local binds were found.
//   - "unknown": ss unavailable or no listener for the port (skip-safe).
//
// The platform never trusts the agent's final severity; it recomputes from
// these structured signals (see internal/audit/severity.go ComputeSeverity).

const (
	bindScopePublic  = "public"
	bindScopePrivate = "private"
	bindScopeUnknown = "unknown"
)

// listenScope returns the bind scope for the given TCP port plus the raw local
// addresses observed. Uses `ss -H -tln`; if ss is absent it returns
// ("unknown", nil) so callers degrade gracefully (LL: fail-soft on probes).
func listenScope(ctx context.Context, port int) (string, []string) {
	out, code, err := cmdOutput(ctx, "ss", "-H", "-tln")
	if err != nil || code != 0 {
		return bindScopeUnknown, nil
	}
	return parseListenScope(out, port)
}

// parseListenScope is the pure, unit-tested core. ss -H -tln emits lines like:
//
//	LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
//	LISTEN 0      128             [::]:22            [::]:*
//	LISTEN 0      128        127.0.0.1:6379       0.0.0.0:*
//
// The 4th column is the local address:port. We collect every local address
// whose port matches and derive the broadest scope (public wins).
func parseListenScope(ssOutput string, port int) (string, []string) {
	portSuffix := ":" + strconv.Itoa(port)
	var addrs []string
	sawPublic := false
	sawPrivate := false

	for _, raw := range strings.Split(ssOutput, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		if !strings.HasSuffix(local, portSuffix) {
			continue
		}
		host := local[:len(local)-len(portSuffix)]
		host = strings.Trim(host, "[]") // strip IPv6 brackets
		addrs = append(addrs, local)

		switch {
		case host == "0.0.0.0" || host == "::" || host == "*":
			sawPublic = true
		default:
			ip := net.ParseIP(host)
			if ip == nil {
				// hostname or unparseable → treat conservatively as public
				sawPublic = true
				continue
			}
			if isPrivateOrLoopback(ip) {
				sawPrivate = true
			} else {
				sawPublic = true
			}
		}
	}

	switch {
	case sawPublic:
		return bindScopePublic, addrs
	case sawPrivate:
		return bindScopePrivate, addrs
	default:
		return bindScopeUnknown, addrs
	}
}

// isPrivateOrLoopback reports whether ip is loopback, link-local, or in an
// RFC1918 / unique-local range — i.e. not reachable from the public internet.
func isPrivateOrLoopback(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
