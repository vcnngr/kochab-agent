package rules

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const RuleCodeSSHDisablePasswordAuth = "ssh.disable_password_auth"

// sshConfigDropInGlob is the standard OpenSSH drop-in directory (Debian/Ubuntu
// ship overrides here, e.g. 50-cloud-init.conf). Drop-ins are read AFTER the
// base file in lexical order, matching sshd's Include semantics for the common
// case (the base config's first line is usually `Include sshd_config.d/*.conf`).
const sshConfigDropInGlob = "/etc/ssh/sshd_config.d/*.conf"

func init() {
	RegisterRule(RuleCodeSSHDisablePasswordAuth, checkSSHDisablePasswordAuth)
}

// checkSSHDisablePasswordAuth reads /etc/ssh/sshd_config plus any *.conf files
// in /etc/ssh/sshd_config.d/ and reports passed=true iff the effective
// PasswordAuthentication directive (last one wins across base + drop-ins) is
// "no". Returns skipped if sshd_config is absent.
//
// Story 3.2: attaches exposure signals (bind_scope/exposed_public) covering
// EVERY configured Port, so the platform can compute context-aware severity.
func checkSSHDisablePasswordAuth(ctx context.Context) (bool, map[string]any, error) {
	src, present, err := readFile("/etc/ssh/sshd_config")
	if err != nil {
		return false, nil, err
	}
	if !present {
		return true, map[string]any{"skipped_reason": "sshd_config missing"}, nil
	}

	// Concatenate base + drop-ins in sshd's effective order (base first, then
	// drop-ins lexically). Last PasswordAuthentication directive wins.
	sources := []string{src}
	sources = append(sources, sshDropInContents()...)

	final := "" // "yes" / "no" / ""
	for _, content := range sources {
		for _, raw := range strings.Split(content, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "passwordauthentication ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					final = strings.ToLower(fields[1])
				}
			}
		}
	}

	// Probe EVERY configured port; public exposure on ANY of them wins (a server
	// reachable on a public port is exposed even if other ports are private).
	ports := sshPorts(sources)
	scope := bindScopeUnknown
	var addrs []string
	for _, p := range ports {
		s, a := listenScope(ctx, p)
		addrs = append(addrs, a...)
		scope = mergeScope(scope, s)
	}

	return final == "no", map[string]any{
		"effective_setting": final,
		"config_path":       "/etc/ssh/sshd_config",
		"ssh_ports":         ports,
		"bind_scope":        scope,
		"listen_addrs":      addrs,
		"exposed_public":    scope == bindScopePublic,
	}, nil
}

// sshDropInContents returns the contents of every *.conf in the drop-in dir,
// sorted lexically. Best-effort: unreadable dir/files are skipped.
func sshDropInContents() []string {
	matches, err := filepath.Glob(sshConfigDropInGlob)
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)
	var out []string
	for _, m := range matches {
		if data, rerr := os.ReadFile(m); rerr == nil {
			out = append(out, string(data))
		}
	}
	return out
}

// sshPorts returns all configured sshd Port directives across the given config
// sources, defaulting to [22] when none are set. OpenSSH allows multiple Port
// directives (the daemon listens on all of them), so we must probe each.
func sshPorts(sources []string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, content := range sources {
		for _, raw := range strings.Split(content, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "port ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p <= 65535 && !seen[p] {
						seen[p] = true
						ports = append(ports, p)
					}
				}
			}
		}
	}
	if len(ports) == 0 {
		return []int{22}
	}
	return ports
}

// mergeScope combines two bind scopes; public dominates, then private, then unknown.
func mergeScope(a, b string) string {
	if a == bindScopePublic || b == bindScopePublic {
		return bindScopePublic
	}
	if a == bindScopePrivate || b == bindScopePrivate {
		return bindScopePrivate
	}
	return bindScopeUnknown
}
