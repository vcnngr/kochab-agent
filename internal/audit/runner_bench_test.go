package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/audit/rules"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// Story 3.1 Task 9.1 (AC-7 NFR2): wall-clock budget for the full audit on a
// Debian 12 minimal host is 120s. This benchmark runs every registered rule
// against the test host and asserts the runner returns under 120s.
//
// On macOS / non-Linux dev hosts many rules short-circuit via "skipped_reason"
// because the inspected daemon is absent — wall time is dominated by the
// `dig` DNS lookups in dkim_spf_dmarc and `docker ps` in docker.no_host_network.
// The 120s ceiling is generous; the assertion guards against a future rule
// that regresses by introducing an unbounded loop.
func BenchmarkRunner_FullSuite(b *testing.B) {
	// Ensure the prod rules are registered. They are registered via init()
	// when the rules package is imported anywhere in the binary; reset+restore
	// during runner_test.go cleanup could leave the registry empty.
	if len(rules.All()) == 0 {
		b.Skip("no rules registered (likely test isolation cleanup) — skip bench")
	}
	payload, err := json.Marshal(TaskPayload{AuditRunID: "bench-run", NodeID: "bench-node"})
	if err != nil {
		b.Fatal(err)
	}
	task := &protocol.TaskPayload{
		TaskID:    "bench-task",
		TaskType:  string(protocol.TaskTypeAudit),
		Payload:   payload,
		Timestamp: time.Now(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		_, err := Run(ctx, task, RunOptions{NodeID: "bench-node"})
		cancel()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestRunner_FullSuiteUnder120s is the assertion test that runs the full
// suite once and fails if it takes longer than the NFR2 ceiling. Kept as a
// regular test (not a bench) so it executes under `go test`.
func TestRunner_FullSuiteUnder120s(t *testing.T) {
	if len(rules.All()) == 0 {
		t.Skip("no rules registered (likely test isolation cleanup) — skip NFR2 check")
	}
	payload, err := json.Marshal(TaskPayload{AuditRunID: "nfr-run", NodeID: "nfr-node"})
	if err != nil {
		t.Fatal(err)
	}
	task := &protocol.TaskPayload{
		TaskID:    "nfr-task",
		TaskType:  string(protocol.TaskTypeAudit),
		Payload:   payload,
		Timestamp: time.Now(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
	defer cancel()

	start := time.Now()
	_, err = Run(ctx, task, RunOptions{NodeID: "nfr-node"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if elapsed > 120*time.Second {
		t.Errorf("NFR2 violation: full audit took %v > 120s", elapsed)
	}
	t.Logf("audit wall time: %v", elapsed)
}
