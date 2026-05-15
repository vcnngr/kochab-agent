package rules

import "github.com/kochab-ai/kochab-agent/pkg/protocol"

// SeverityForRule returns the agent's best-effort severity proposal for a
// failing rule. Platform overrides this via audit_rules.severity_base
// (Story 3.1 severity_computed STUB → Story 3.2 context-aware), so agent
// values are advisory. Keep this map in sync with migration 007
// (LL10 / Story 3.1 Task 11 cross-package grep guardrail).
var SeverityForRule = map[string]protocol.SeverityLevel{
	RuleCodeSSHDisablePasswordAuth:    protocol.SeverityCritical,
	RuleCodeFirewallDefaultDeny:       protocol.SeverityCritical,
	RuleCodeTLSMinVersion12:           protocol.SeverityWarning,
	RuleCodeUpdatesUnattendedSecurity: protocol.SeverityWarning,
	RuleCodePermissionsShadowPasswd:   protocol.SeverityCritical,
	RuleCodeFail2banEnabled:           protocol.SeverityWarning,
	RuleCodeServicesNoUnauthExposed:   protocol.SeverityCritical,
	RuleCodeDKIMSPFDMARCBasic:         protocol.SeverityInfo,
	RuleCodeBackupConfigPresent:       protocol.SeverityInfo,
	RuleCodeDockerNoHostNetwork:       protocol.SeverityWarning,
}
