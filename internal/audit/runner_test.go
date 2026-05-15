package audit

import (
	"context"
	"encoding/json"
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

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
