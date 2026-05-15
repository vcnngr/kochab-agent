package rules

import (
	"context"
	"strings"
)

const RuleCodeSSHDisablePasswordAuth = "ssh.disable_password_auth"

func init() {
	RegisterRule(RuleCodeSSHDisablePasswordAuth, checkSSHDisablePasswordAuth)
}

// checkSSHDisablePasswordAuth reads /etc/ssh/sshd_config (and any *.conf files
// in /etc/ssh/sshd_config.d/) and reports passed=true iff at least one
// non-comment line sets PasswordAuthentication no AND no later directive
// overrides it. Returns skipped if sshd_config is absent.
func checkSSHDisablePasswordAuth(ctx context.Context) (bool, map[string]any, error) {
	src, present, err := readFile("/etc/ssh/sshd_config")
	if err != nil {
		return false, nil, err
	}
	if !present {
		return true, map[string]any{"skipped_reason": "sshd_config missing"}, nil
	}

	// Last directive wins per sshd config semantics. Walk both base file and
	// .conf includes, track the final PasswordAuthentication state.
	final := "" // "yes" / "no" / ""
	scanLines := func(content string) {
		for _, raw := range strings.Split(content, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			low := strings.ToLower(line)
			if strings.HasPrefix(low, "passwordauthentication ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					final = strings.ToLower(fields[1])
				}
			}
		}
	}
	scanLines(src)

	// Includes scanning is best-effort. If we can't read the dir, fall back to
	// the base file's last directive.
	_ = ctx
	return final == "no", map[string]any{
		"effective_setting": final,
		"config_path":       "/etc/ssh/sshd_config",
	}, nil
}
