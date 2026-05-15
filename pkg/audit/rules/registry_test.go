package rules

import (
	"context"
	"sort"
	"testing"
)

// Story 3.1 Task 8.1: registry sanity — every rule from the LOCKED D1 set is
// registered, no duplicates, ordering deterministic.

var lockedRuleCodes = []string{
	"backup.config_present",
	"dkim_spf_dmarc.basic",
	"docker.no_host_network",
	"fail2ban.enabled",
	"firewall.default_deny",
	"permissions.shadow_passwd",
	"services.no_unauth_exposed",
	"ssh.disable_password_auth",
	"tls.min_version_12",
	"updates.unattended_security",
}

func TestRegistry_AllLockedRulesRegistered(t *testing.T) {
	all := All()
	got := make([]string, 0, len(all))
	for _, r := range all {
		got = append(got, r.Code)
	}
	sort.Strings(got)

	if len(got) < len(lockedRuleCodes) {
		t.Fatalf("registry has %d rules, want at least %d (LOCKED D1 minimum)", len(got), len(lockedRuleCodes))
	}
	registered := map[string]bool{}
	for _, c := range got {
		registered[c] = true
	}
	for _, want := range lockedRuleCodes {
		if !registered[want] {
			t.Errorf("locked rule_code missing from registry: %s", want)
		}
	}
}

func TestRegistry_AllReturnsSortedDeterministic(t *testing.T) {
	first := All()
	second := All()
	if len(first) != len(second) {
		t.Fatal("All() length is not stable")
	}
	for i := range first {
		if first[i].Code != second[i].Code {
			t.Errorf("All() ordering not deterministic at index %d: %s vs %s", i, first[i].Code, second[i].Code)
		}
	}
}

func TestRegistry_GetReturnsKnownRule(t *testing.T) {
	r, ok := Get(RuleCodeSSHDisablePasswordAuth)
	if !ok {
		t.Fatal("Get returned !ok for ssh.disable_password_auth")
	}
	if r.Code != RuleCodeSSHDisablePasswordAuth {
		t.Errorf("Get returned wrong rule: %s", r.Code)
	}
	if r.Check == nil {
		t.Error("Get returned rule with nil Check")
	}
}

func TestRegistry_DuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	noop := func(ctx context.Context) (bool, map[string]any, error) { return true, nil, nil }
	RegisterRule(RuleCodeSSHDisablePasswordAuth, noop)
}

func TestRegistry_NilCheckFuncPanics(t *testing.T) {
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic on nil CheckFunc")
		}
	}()
	RegisterRule("test.nil_fn", nil)
}
