package rules

import (
	"context"
	"regexp"
	"strings"
)

const RuleCodeServicesNoUnauthExposed = "services.no_unauth_exposed"

func init() {
	RegisterRule(RuleCodeServicesNoUnauthExposed, checkServicesNoUnauthExposed)
}

// Sensitive ports — DB/cache/search/queue daemons that should never be
// exposed on a public interface without explicit authentication & TLS.
var sensitivePorts = map[string]string{
	"3306":  "MySQL/MariaDB",
	"5432":  "PostgreSQL",
	"6379":  "Redis",
	"27017": "MongoDB",
	"9200":  "Elasticsearch",
	"11211": "Memcached",
}

// localhostBindings reported by `ss -tln` as "127.x.x.x", "[::1]", or "::1".
var localhostBindingRe = regexp.MustCompile(`^(127\.|\[::1\]|::1$|0\.0\.0\.0$)`)

// checkServicesNoUnauthExposed parses `ss -tln` listing and reports any
// sensitive port bound to a non-loopback address.
func checkServicesNoUnauthExposed(ctx context.Context) (bool, map[string]any, error) {
	out, _, err := cmdOutput(ctx, "ss", "-tln")
	if isCmdNotFound(err) {
		return true, map[string]any{"skipped_reason": "ss not installed"}, nil
	}
	if err != nil {
		return false, nil, err
	}

	exposed := []map[string]any{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddr := fields[3]
		// Extract host + port.
		host, port, ok := splitHostPort(localAddr)
		if !ok {
			continue
		}
		daemon, sensitive := sensitivePorts[port]
		if !sensitive {
			continue
		}
		if isLoopback(host) {
			continue
		}
		exposed = append(exposed, map[string]any{
			"port":   port,
			"daemon": daemon,
			"bound":  localAddr,
		})
	}

	if len(exposed) == 0 {
		return true, map[string]any{}, nil
	}
	return false, map[string]any{"exposed_services": exposed}, nil
}

// splitHostPort splits the "host:port" address forms emitted by ss for both
// IPv4 ("0.0.0.0:5432", "127.0.0.1:5432") and IPv6 ("[::]:5432", "[::1]:5432").
func splitHostPort(addr string) (host, port string, ok bool) {
	// IPv6 bracketed.
	if strings.HasPrefix(addr, "[") {
		closeIdx := strings.Index(addr, "]")
		if closeIdx < 0 || len(addr) <= closeIdx+1 || addr[closeIdx+1] != ':' {
			return "", "", false
		}
		return addr[:closeIdx+1], addr[closeIdx+2:], true
	}
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return "", "", false
	}
	return addr[:idx], addr[idx+1:], true
}

func isLoopback(host string) bool {
	if host == "" {
		return false
	}
	// Strip brackets for IPv6.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "::1" {
		return true
	}
	return localhostBindingRe.MatchString(host) && !strings.HasPrefix(host, "0.0.0.0")
}
