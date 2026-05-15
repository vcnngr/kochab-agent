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
//   passed  — true if the host satisfies the rule.
//   context — diagnostic key/value pairs to surface to the platform as
//             severity_context (later consumed by Story 3.2 context-aware
//             severity and the UI explanation panel of Story 3.4).
//   err     — fatal error preventing evaluation. The runner converts these
//             into a `severity=info` finding with the error text; the rule is
//             effectively skipped.
//
// Preflight conditions (file missing, command absent, etc.) should be modelled
// by returning passed=true with context["skipped_reason"]="..." rather than an
// error — pass-with-context keeps the audit report meaningful on heterogeneous
// hosts (e.g. Docker absent → "docker.no_host_network" rule is vacuously OK).
type CheckFunc func(ctx context.Context) (passed bool, context map[string]any, err error)

// Rule is a registered audit rule.
type Rule struct {
	Code  string
	Check CheckFunc
}

var (
	mu       sync.RWMutex
	registry = map[string]Rule{}
)

// RegisterRule adds a rule to the registry. Panics on duplicate code so that
// init-time conflicts surface at agent boot rather than silently overwriting.
func RegisterRule(code string, fn CheckFunc) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[code]; exists {
		panic(fmt.Sprintf("audit rules: duplicate registration for rule_code %q", code))
	}
	if fn == nil {
		panic(fmt.Sprintf("audit rules: nil CheckFunc for rule_code %q", code))
	}
	registry[code] = Rule{Code: code, Check: fn}
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
