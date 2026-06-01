package audit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/audit/rules"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// Story 3.1 Task 8.1: runner orchestration.
// We seed an isolated rules registry to make assertions deterministic and
// avoid host-dependent passes/fails.

func setupTestRules(t *testing.T) {
	t.Helper()
	rules.Reset()
	t.Cleanup(func() {
		rules.Reset()
		// Re-register original rules so other tests / packages can still load.
		// Side-effect imports in main.go take care of production runtime; for
		// the test binary the package-level init() already ran once when this
		// test file was compiled — but Reset clears it. Re-import side-effect
		// is not possible at runtime; tests that need real rules must run in
		// their own t.Parallel-disabled subtests with explicit re-registration.
	})
}

func TestRun_HappyPath_NoFindings(t *testing.T) {
	setupTestRules(t)
	rules.RegisterRule("test.pass", func(ctx context.Context) (bool, map[string]any, error) {
		return true, nil, nil
	})
	rules.RegisterRule("test.also_pass", func(ctx context.Context) (bool, map[string]any, error) {
		return true, map[string]any{"detail": "ok"}, nil
	})

	payload := mustMarshal(t, TaskPayload{AuditRunID: "run-1", NodeID: "node-1"})
	task := &protocol.TaskPayload{
		TaskID:    "task-1",
		TaskType:  string(protocol.TaskTypeAudit),
		Payload:   payload,
		Timestamp: time.Now(),
	}

	result, err := Run(context.Background(), task, RunOptions{NodeID: "node-1"})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if result.Status != protocol.RunStatusCompleted {
		t.Errorf("status = %s want completed", result.Status)
	}
	if len(result.Findings) != 0 {
		t.Errorf("findings = %d want 0", len(result.Findings))
	}
	if result.ChecksTotal != 2 || result.ChecksPassed != 2 {
		t.Errorf("checks total/passed = %d/%d want 2/2", result.ChecksTotal, result.ChecksPassed)
	}
}

func TestRun_FailingRule_ProducesFinding(t *testing.T) {
	setupTestRules(t)
	rules.RegisterRule("test.fail_critical", func(ctx context.Context) (bool, map[string]any, error) {
		return false, map[string]any{"port": 22}, nil
	})

	payload := mustMarshal(t, TaskPayload{AuditRunID: "run-1"})
	task := &protocol.TaskPayload{TaskID: "t1", TaskType: string(protocol.TaskTypeAudit), Payload: payload, Timestamp: time.Now()}

	result, err := Run(context.Background(), task, RunOptions{NodeID: "n1"})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.RuleCode != "test.fail_critical" {
		t.Errorf("rule_code = %s", f.RuleCode)
	}
	if f.SeverityContext["port"] != 22 {
		t.Errorf("severity_context not propagated: %+v", f.SeverityContext)
	}
	if result.ChecksPassed != 0 {
		t.Errorf("checks_passed = %d want 0", result.ChecksPassed)
	}
}

func TestRun_RuleTimeout_ProducesInfoFinding(t *testing.T) {
	setupTestRules(t)
	rules.RegisterRule("test.timeout", func(ctx context.Context) (bool, map[string]any, error) {
		select {
		case <-time.After(10 * time.Second):
			return true, nil, nil
		case <-ctx.Done():
			return false, nil, ctx.Err()
		}
	})

	payload := mustMarshal(t, TaskPayload{AuditRunID: "run-1"})
	task := &protocol.TaskPayload{TaskID: "t1", TaskType: string(protocol.TaskTypeAudit), Payload: payload, Timestamp: time.Now()}

	result, err := Run(context.Background(), task, RunOptions{NodeID: "n1", RuleTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != protocol.SeverityInfo {
		t.Errorf("timeout finding severity = %s want info", f.Severity)
	}
	if f.Message != "rule timed out" {
		t.Errorf("timeout finding message = %q want 'rule timed out'", f.Message)
	}
}

func TestRun_NoRulesRegistered_Errors(t *testing.T) {
	setupTestRules(t)
	payload := mustMarshal(t, TaskPayload{AuditRunID: "run-1"})
	task := &protocol.TaskPayload{TaskID: "t1", TaskType: string(protocol.TaskTypeAudit), Payload: payload, Timestamp: time.Now()}

	_, err := Run(context.Background(), task, RunOptions{NodeID: "n1"})
	if err == nil {
		t.Fatal("expected error on no rules registered")
	}
}

func TestRun_MissingAuditRunID_Errors(t *testing.T) {
	setupTestRules(t)
	rules.RegisterRule("noop", func(ctx context.Context) (bool, map[string]any, error) { return true, nil, nil })

	payload := mustMarshal(t, TaskPayload{})
	task := &protocol.TaskPayload{TaskID: "t1", TaskType: string(protocol.TaskTypeAudit), Payload: payload, Timestamp: time.Now()}

	_, err := Run(context.Background(), task, RunOptions{NodeID: "n1"})
	if err == nil {
		t.Fatal("expected error on empty audit_run_id")
	}
}

func TestRun_PanickingRule_DoesNotCrashRunner(t *testing.T) {
	setupTestRules(t)
	rules.RegisterRule("test.panic", func(ctx context.Context) (bool, map[string]any, error) {
		panic("boom")
	})

	payload := mustMarshal(t, TaskPayload{AuditRunID: "run-1"})
	task := &protocol.TaskPayload{TaskID: "t1", TaskType: string(protocol.TaskTypeAudit), Payload: payload, Timestamp: time.Now()}

	result, err := Run(context.Background(), task, RunOptions{NodeID: "n1"})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 info finding from panicking rule, got %d", len(result.Findings))
	}
}

// Story 4.1 — eager preflight on failing rules. Table-driven over the exit-code
// → preflight_status mapping contract.
func TestRun_PreflightExitCodeMapping(t *testing.T) {
	const failReason = "do this first"
	cases := []struct {
		name       string
		preflight  rules.PreflightFunc // nil => rule has no preflight
		wantStatus protocol.PreflightStatus
		wantReason *string
	}{
		{
			name:       "no_preflight_is_none",
			preflight:  nil,
			wantStatus: protocol.PreflightStatusNone,
			wantReason: nil,
		},
		{
			name:       "exit0_pass",
			preflight:  func(context.Context) (int, string, error) { return rules.PreflightExitPass, "", nil },
			wantStatus: protocol.PreflightStatusPassed,
			wantReason: nil,
		},
		{
			name:       "exit1_block_with_reason",
			preflight:  func(context.Context) (int, string, error) { return rules.PreflightExitBlock, failReason, nil },
			wantStatus: protocol.PreflightStatusBlocked,
			wantReason: strPtr(failReason),
		},
		{
			name:       "exit2_skip_treated_as_pass",
			preflight:  func(context.Context) (int, string, error) { return rules.PreflightExitSkip, "", nil },
			wantStatus: protocol.PreflightStatusSkipped,
			wantReason: nil,
		},
		{
			name:       "preflight_error_degrades_to_pass",
			preflight:  func(context.Context) (int, string, error) { return 0, "", errors.New("probe boom") },
			wantStatus: protocol.PreflightStatusPassed,
			wantReason: nil,
		},
		{
			name:       "preflight_panic_degrades_to_pass",
			preflight:  func(context.Context) (int, string, error) { panic("kaboom") },
			wantStatus: protocol.PreflightStatusPassed,
			wantReason: nil,
		},
		{
			name:       "unknown_exit_degrades_to_pass",
			preflight:  func(context.Context) (int, string, error) { return 99, "ignored", nil },
			wantStatus: protocol.PreflightStatusPassed,
			wantReason: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRules(t)
			failingCheck := func(context.Context) (bool, map[string]any, error) {
				return false, map[string]any{"k": "v"}, nil
			}
			if tc.preflight == nil {
				rules.RegisterRule("test.rule", failingCheck)
			} else {
				rules.RegisterRuleWithPreflight("test.rule", failingCheck, tc.preflight)
			}

			payload := mustMarshal(t, TaskPayload{AuditRunID: "run-1"})
			task := &protocol.TaskPayload{TaskID: "t", TaskType: string(protocol.TaskTypeAudit), Payload: payload, Timestamp: time.Now()}
			result, err := Run(context.Background(), task, RunOptions{NodeID: "n1"})
			if err != nil {
				t.Fatalf("Run err: %v", err)
			}
			if len(result.Findings) != 1 {
				t.Fatalf("findings = %d want 1", len(result.Findings))
			}
			f := result.Findings[0]
			if f.PreflightStatus != tc.wantStatus {
				t.Errorf("preflight_status = %q want %q", f.PreflightStatus, tc.wantStatus)
			}
			switch {
			case tc.wantReason == nil && f.PreflightReason != nil:
				t.Errorf("preflight_reason = %q want nil", *f.PreflightReason)
			case tc.wantReason != nil && f.PreflightReason == nil:
				t.Errorf("preflight_reason = nil want %q", *tc.wantReason)
			case tc.wantReason != nil && *f.PreflightReason != *tc.wantReason:
				t.Errorf("preflight_reason = %q want %q", *f.PreflightReason, *tc.wantReason)
			}
		})
	}
}

// Story 4-1 FINDING 2: lockout-sensitive (fail-closed) rules must map a preflight
// error/panic/unknown-exit to "blocked" with the lockout-risk reason — the
// opposite of the fail-open default verified by TestRun_PreflightExitCodeMapping.
// Showing the password-disable fix on an unverifiable probe is a real lockout risk.
func TestRun_PreflightFailClosed_LockoutSensitiveRuleBlocks(t *testing.T) {
	cases := []struct {
		name      string
		preflight rules.PreflightFunc
	}{
		{
			name:      "error_blocks",
			preflight: func(context.Context) (int, string, error) { return 0, "", errors.New("probe boom") },
		},
		{
			name:      "panic_blocks",
			preflight: func(context.Context) (int, string, error) { panic("kaboom") },
		},
		{
			name:      "unknown_exit_blocks",
			preflight: func(context.Context) (int, string, error) { return 99, "ignored", nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRules(t)
			failingCheck := func(context.Context) (bool, map[string]any, error) {
				return false, map[string]any{"k": "v"}, nil
			}
			rules.RegisterLockoutSensitiveRuleWithPreflight("test.lockout", failingCheck, tc.preflight)

			payload := mustMarshal(t, TaskPayload{AuditRunID: "run-1"})
			task := &protocol.TaskPayload{TaskID: "t", TaskType: string(protocol.TaskTypeAudit), Payload: payload, Timestamp: time.Now()}
			result, err := Run(context.Background(), task, RunOptions{NodeID: "n1"})
			if err != nil {
				t.Fatalf("Run err: %v", err)
			}
			if len(result.Findings) != 1 {
				t.Fatalf("findings = %d want 1", len(result.Findings))
			}
			f := result.Findings[0]
			if f.PreflightStatus != protocol.PreflightStatusBlocked {
				t.Errorf("preflight_status = %q want %q (fail-closed)", f.PreflightStatus, protocol.PreflightStatusBlocked)
			}
			if f.PreflightReason == nil || *f.PreflightReason != lockoutPreflightUnverifiableReason {
				got := "<nil>"
				if f.PreflightReason != nil {
					got = *f.PreflightReason
				}
				t.Errorf("preflight_reason = %q want lockout-risk guidance", got)
			}
		})
	}
}

// Passing rules must produce NO finding, hence no preflight is run for them.
func TestRun_PassingRule_NoPreflight(t *testing.T) {
	setupTestRules(t)
	preflightRan := false
	rules.RegisterRuleWithPreflight("test.pass",
		func(context.Context) (bool, map[string]any, error) { return true, nil, nil },
		func(context.Context) (int, string, error) {
			preflightRan = true
			return rules.PreflightExitBlock, "x", nil
		},
	)
	payload := mustMarshal(t, TaskPayload{AuditRunID: "run-1"})
	task := &protocol.TaskPayload{TaskID: "t", TaskType: string(protocol.TaskTypeAudit), Payload: payload, Timestamp: time.Now()}
	result, err := Run(context.Background(), task, RunOptions{NodeID: "n1"})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %d want 0", len(result.Findings))
	}
	if preflightRan {
		t.Error("preflight must NOT run for a passing rule")
	}
}

func strPtr(s string) *string { return &s }

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
