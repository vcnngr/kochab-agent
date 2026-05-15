package rules

import "context"

const RuleCodeFail2banEnabled = "fail2ban.enabled"

func init() {
	RegisterRule(RuleCodeFail2banEnabled, checkFail2banEnabled)
}

func checkFail2banEnabled(ctx context.Context) (bool, map[string]any, error) {
	_, isEnabledCode, err := cmdOutput(ctx, "systemctl", "is-enabled", "fail2ban")
	if isCmdNotFound(err) {
		return false, map[string]any{"reason": "systemd absent — fail2ban cannot be verified"}, nil
	}
	if err != nil {
		return false, nil, err
	}
	if isEnabledCode != 0 {
		return false, map[string]any{"reason": "fail2ban unit not enabled"}, nil
	}
	_, isActiveCode, err := cmdOutput(ctx, "systemctl", "is-active", "fail2ban")
	if err != nil && !isCmdNotFound(err) {
		return false, nil, err
	}
	if isActiveCode != 0 {
		return false, map[string]any{"reason": "fail2ban unit enabled but not active"}, nil
	}
	return true, map[string]any{}, nil
}
