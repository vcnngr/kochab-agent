// Package rules contains the Go-native audit checks executed by the agent.
//
// Story 3.1: each rule is a self-contained file (ssh.go, firewall.go, …) with
// an init() that calls RegisterRule. The runner enumerates the registry via
// All() — no hardcoded switch — so new rules added by Story 6.x KB pipeline
// only need a new file + init(). LL10 sync target: rule_code constants here
// MUST match the migrations/007_seed_audit_rules.sql rule_code column values.
// The `make check-audit-symbols` guardrail (Story 3.1 Task 11) detects drift.
package rules

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// CheckFunc is the per-rule check signature.
//
// Returns:
//
//	passed  — true if the host satisfies the rule.
//	context — diagnostic key/value pairs to surface to the platform as
//	          severity_context (later consumed by Story 3.2 context-aware
//	          severity and the UI explanation panel of Story 3.4).
//	err     — fatal error preventing evaluation. The runner converts these
//	          into a `severity=info` finding with the error text; the rule is
//	          effectively skipped.
//
// Preflight conditions (file missing, command absent, etc.) should be modelled
// by returning passed=true with context["skipped_reason"]="..." rather than an
// error — pass-with-context keeps the audit report meaningful on heterogeneous
// hosts (e.g. Docker absent → "docker.no_host_network" rule is vacuously OK).
type CheckFunc func(ctx context.Context) (passed bool, context map[string]any, err error)

// Pre-flight exit-code semantics (Story 4.1, seed 007 convention). A rule's
// PreflightFunc is a READ-ONLY guardrail that decides whether the platform
// should render the (copy-paste, human-applied) fix command. It NEVER mutates
// the host and NEVER executes the fix.
//
//	PreflightExitPass    (0) => safe to suggest fix  -> protocol "passed"
//	PreflightExitBlock   (1) => dangerous, suppress  -> protocol "blocked"
//	PreflightExitSkip    (2) => not applicable, pass -> protocol "skipped"
const (
	PreflightExitPass  = 0
	PreflightExitBlock = 1
	PreflightExitSkip  = 2
)

// PreflightFunc is the per-rule read-only pre-flight check signature (Story 4.1,
// recommended approach (a): preflight is part of the agent-side rule definition,
// alongside Check). It runs ONLY when the rule has produced a finding (failed).
//
// Returns:
//
//	exitCode — one of PreflightExitPass/Block/Skip. Maps to preflight_status.
//	reason   — human-readable guidance, surfaced as preflight_reason when the
//	           exit code is PreflightExitBlock (ignored otherwise).
//	err      — fatal error while evaluating the preflight. The runner treats a
//	           preflight error conservatively as a pass (the fix is still shown)
//	           so a flaky probe never silently suppresses a legitimate fix.
//
// SAFETY INVARIANT: a PreflightFunc MUST be read-only. No mutating exec.
type PreflightFunc func(ctx context.Context) (exitCode int, reason string, err error)

// Rule is a registered audit rule.
type Rule struct {
	Code  string
	Check CheckFunc
	// Preflight is an optional read-only guardrail run when the rule fails.
	// nil => the rule has no preflight (preflight_status "none"). Story 4.1.
	Preflight PreflightFunc
	// FailClosed marks a lockout-sensitive rule: when its preflight errors,
	// panics, or returns an unknown exit code, the runner maps the outcome to
	// "blocked" (fix suppressed) instead of the default "passed". This protects
	// guardrails like ssh.disable_password_auth where SHOWING the fix on an
	// unverifiable probe carries real lockout risk. Default false (fail-open):
	// for ordinary rules a flaky probe must not hide a legitimate fix.
	FailClosed bool
}

// HasPreflight reports whether this rule defines a pre-flight check.
func (r Rule) HasPreflight() bool { return r.Preflight != nil }

var (
	mu       sync.RWMutex
	registry = map[string]Rule{}
)

// RegisterRule adds a rule to the registry. Panics on duplicate code so that
// init-time conflicts surface at agent boot rather than silently overwriting.
func RegisterRule(code string, fn CheckFunc) {
	registerRule(code, fn, nil, false)
}

// RegisterRuleWithPreflight registers a rule that also defines a read-only
// pre-flight guardrail (Story 4.1). The preflight runs only when the rule
// fails; it MUST be read-only (no mutating exec, never applies the fix). The
// preflight is fail-open: an error/panic/unknown exit degrades to "passed".
func RegisterRuleWithPreflight(code string, fn CheckFunc, pre PreflightFunc) {
	registerRule(code, fn, pre, false)
}

// RegisterLockoutSensitiveRuleWithPreflight registers a rule whose preflight is
// a LOCKOUT GUARDRAIL (e.g. ssh.disable_password_auth). Unlike the fail-open
// default, its preflight is fail-closed: an error/panic/unknown exit maps to
// "blocked" so the dangerous fix is never shown on an unverifiable probe.
func RegisterLockoutSensitiveRuleWithPreflight(code string, fn CheckFunc, pre PreflightFunc) {
	registerRule(code, fn, pre, true)
}

func registerRule(code string, fn CheckFunc, pre PreflightFunc, failClosed bool) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[code]; exists {
		panic(fmt.Sprintf("audit rules: duplicate registration for rule_code %q", code))
	}
	if fn == nil {
		panic(fmt.Sprintf("audit rules: nil CheckFunc for rule_code %q", code))
	}
	registry[code] = Rule{Code: code, Check: fn, Preflight: pre, FailClosed: failClosed}
}

// All returns rules sorted by code, deterministic ordering for tests.
func All() []Rule {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Rule, 0, len(registry))
	for _, r := range registry {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Get returns a single rule by code. Used by tests that exercise one rule.
func Get(code string) (Rule, bool) {
	mu.RLock()
	defer mu.RUnlock()
	r, ok := registry[code]
	return r, ok
}

// Reset clears the registry. Test-only; never called in production.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	registry = map[string]Rule{}
}

// DefaultRuleTimeout is the per-rule wall-clock deadline. AC-3.
const DefaultRuleTimeout = 10 * time.Second
