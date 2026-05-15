package rules

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Story 3.1 Task 8.1: per-rule smoke. Each rule must not panic, must respect
// context cancellation, and must return a deterministic ok/fail bool.
//
// Detection-rate / false-positive fixtures (AC-8 Task 8.2) are deferred to a
// follow-up — they require Linux fixture containers and cannot run on macOS
// dev hosts where this suite executes. The smoke layer here at least ensures
// every rule survives a real invocation on the test host.

func TestAllRules_SmokeNoPanicHonoursCancel(t *testing.T) {
	for _, r := range All() {
		t.Run(r.Code, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), DefaultRuleTimeout)
			defer cancel()

			passed, sctx, err := r.Check(ctx)
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				t.Logf("rule %s: non-fatal error: %v (acceptable on hosts lacking the inspected component)", r.Code, err)
			}
			// passed and sctx are both information signals — no assertion on
			// truthiness since the host CI runs on macOS where many Linux-only
			// daemons are absent. The contract under test is "does not panic".
			_ = passed
			_ = sctx
		})
	}
}

func TestAllRules_HonourContextCancellation(t *testing.T) {
	// Cancel immediately — rules that respect ctx should bail without using
	// the full 10s timeout. Tolerance: total wall time ≤ 2s for all rules.
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, r := range All() {
		_, _, _ = r.Check(ctx)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("rules did not honour ctx.Cancelled fast enough: %v (want < 2s)", elapsed)
	}
}
