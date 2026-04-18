package executor_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kochab-ai/kochab-agent/internal/executor"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

func makeTask(taskID, taskType string, payload map[string]any) *protocol.TaskPayload {
	b, _ := json.Marshal(payload)
	return &protocol.TaskPayload{
		TaskID:   taskID,
		TaskType: taskType,
		Payload:  json.RawMessage(b),
	}
}

func TestExecute_Ping(t *testing.T) {
	task := makeTask("task-ping-01", "ping", map[string]any{})

	result, err := executor.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("Execute ping: %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("status = %q, want completed", result.Status)
	}
	if result.TaskID != "task-ping-01" {
		t.Errorf("task_id = %q, want task-ping-01", result.TaskID)
	}
	if result.Error != "" {
		t.Errorf("error should be empty, got %q", result.Error)
	}

	// Verify result payload contains expected fields.
	var payload map[string]any
	if err := json.Unmarshal(result.Result, &payload); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if payload["ok"] != true {
		t.Errorf("ok = %v, want true", payload["ok"])
	}
	if payload["pong_at"] == "" || payload["pong_at"] == nil {
		t.Error("pong_at should be present")
	}
}

func TestExecute_UnsupportedTaskType(t *testing.T) {
	task := makeTask("task-xyz", "unknown_type", map[string]any{})

	result, err := executor.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("Execute should not return error for unknown type, got: %v", err)
	}

	// Unknown task type should be captured as a failed result, not a Go error.
	if result.Status != "failed" {
		t.Errorf("status = %q, want failed", result.Status)
	}
	if result.Error == "" {
		t.Error("error field should describe unsupported type")
	}
}

func TestExecute_ProfileRefresh(t *testing.T) {
	task := makeTask("task-pr-01", "profile_refresh", map[string]any{})

	result, err := executor.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("Execute profile_refresh: %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("status = %q, want completed", result.Status)
	}
}

func TestExecute_ContextCancellation(t *testing.T) {
	task := makeTask("task-cancel", "ping", map[string]any{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Even with cancelled context, ping should complete (it doesn't use ctx).
	result, err := executor.Execute(ctx, task)
	if err != nil {
		t.Fatalf("Execute with cancelled ctx: %v", err)
	}
	// ping doesn't block on ctx so it should still complete.
	if result.Status != "completed" {
		t.Errorf("status = %q, want completed", result.Status)
	}
}
