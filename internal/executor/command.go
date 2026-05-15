package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// Execute dispatches a verified task to the appropriate handler.
// Returns a TaskResult — never panics on unknown task types.
func Execute(ctx context.Context, task *protocol.TaskPayload) (*protocol.TaskResult, error) {
	slog.Info("task_executing", "task_id", task.TaskID, "task_type", task.TaskType)

	var result json.RawMessage
	var execErr error

	switch task.TaskType {
	case string(protocol.TaskTypePing):
		result, execErr = executePing(ctx, task)
	case string(protocol.TaskTypeProfileRefresh):
		result, execErr = executeProfileRefresh(ctx, task)
	case string(protocol.TaskTypeAudit):
		// Audit dispatch is handled by cmd/kochab-agent/main.go runAuditTask
		// because the result is posted to /v1/audit_results, not /v1/results.
		// If Execute is invoked directly for an audit task (tests or future
		// codepaths), surface a clear error instead of silently succeeding.
		execErr = fmt.Errorf("audit task must be dispatched via runAuditTask, not executor.Execute")
	default:
		execErr = fmt.Errorf("unsupported_task_type: %q", task.TaskType)
	}

	if execErr != nil {
		slog.Warn("task_execution_error",
			"task_id", task.TaskID,
			"task_type", task.TaskType,
			"error", execErr,
		)
		return &protocol.TaskResult{
			TaskID: task.TaskID,
			Status: "failed",
			Error:  execErr.Error(),
		}, nil // error is captured in result, not propagated
	}

	slog.Info("task_executed",
		"task_id", task.TaskID,
		"task_type", task.TaskType,
	)
	return &protocol.TaskResult{
		TaskID: task.TaskID,
		Status: "completed",
		Result: result,
	}, nil
}

// executePing responds with ok + timestamp.
func executePing(_ context.Context, task *protocol.TaskPayload) (json.RawMessage, error) {
	resp := map[string]any{
		"ok":         true,
		"task_id":    task.TaskID,
		"pong_at":    time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("ping marshal: %w", err)
	}
	return json.RawMessage(b), nil
}

// executeProfileRefresh triggers a profile collection and returns a summary.
// Full transmission is handled outside Execute to keep this package dependency-free.
func executeProfileRefresh(_ context.Context, task *protocol.TaskPayload) (json.RawMessage, error) {
	// Profile refresh collects system info via the profiler package.
	// For MVP the result is a minimal ack — the actual profile is transmitted
	// via the existing POST /v1/nodes/profile endpoint, not via task result.
	resp := map[string]any{
		"ok":         true,
		"task_id":    task.TaskID,
		"refreshed_at": time.Now().UTC().Format(time.RFC3339),
		"note":       "profile transmitted via /v1/nodes/profile",
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("profile_refresh marshal: %w", err)
	}
	return json.RawMessage(b), nil
}
