package rules

import (
	"context"
	"strings"
)

const RuleCodeUpdatesUnattendedSecurity = "updates.unattended_security"

func init() {
	RegisterRule(RuleCodeUpdatesUnattendedSecurity, checkUpdatesUnattendedSecurity)
}

// checkUpdatesUnattendedSecurity verifies that the unattended-upgrades package
// is installed and the timer/service is enabled. We avoid `systemctl is-active`
// (state changes between runs); is-enabled is the persistent intent.
func checkUpdatesUnattendedSecurity(ctx context.Context) (bool, map[string]any, error) {
	// 1) Package installed?
	dpkgOut, dpkgCode, err := cmdOutput(ctx, "dpkg-query", "-W", "-f=${Status}\n", "unattended-upgrades")
	if isCmdNotFound(err) {
		return true, map[string]any{"skipped_reason": "dpkg-query missing — non-Debian host"}, nil
	}
	if err != nil {
		return false, nil, err
	}
	installed := dpkgCode == 0 && strings.Contains(dpkgOut, "install ok installed")
	if !installed {
		return false, map[string]any{"reason": "unattended-upgrades package not installed"}, nil
	}

	// 2) systemd unit enabled?
	_, code, err := cmdOutput(ctx, "systemctl", "is-enabled", "unattended-upgrades")
	if isCmdNotFound(err) {
		// No systemd → on Debian 12 unlikely, but be lenient: package presence
		// is the strong signal.
		return true, map[string]any{"systemd": "missing", "reason": "package installed, unit state unknown"}, nil
	}
	if err != nil {
		return false, nil, err
	}
	if code != 0 {
		return false, map[string]any{"reason": "unattended-upgrades unit not enabled"}, nil
	}
	return true, map[string]any{}, nil
}
