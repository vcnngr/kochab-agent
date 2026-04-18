package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRunStatus_Valid(t *testing.T) {
	tests := []struct {
		name string
		rs   RunStatus
		want bool
	}{
		{"pending", RunStatusPending, true},
		{"running", RunStatusRunning, true},
		{"completed", RunStatusCompleted, true},
		{"failed", RunStatusFailed, true},
		{"unknown", RunStatus("bogus"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rs.Valid(); got != tc.want {
				t.Errorf("RunStatus(%q).Valid() = %v, want %v", tc.rs, got, tc.want)
			}
		})
	}
}

func TestSeverityLevel_Valid(t *testing.T) {
	tests := []struct {
		name string
		sl   SeverityLevel
		want bool
	}{
		{"critical", SeverityCritical, true},
		{"warning", SeverityWarning, true},
		{"info", SeverityInfo, true},
		{"serene", SeveritySerene, true},
		{"unknown", SeverityLevel("high"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sl.Valid(); got != tc.want {
				t.Errorf("SeverityLevel(%q).Valid() = %v, want %v", tc.sl, got, tc.want)
			}
		})
	}
}

func TestFindingStatus_Valid(t *testing.T) {
	tests := []struct {
		name string
		fs   FindingStatus
		want bool
	}{
		{"open", FindingStatusOpen, true},
		{"fixed", FindingStatusFixed, true},
		{"accepted", FindingStatusAccepted, true},
		{"unknown", FindingStatus("closed"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fs.Valid(); got != tc.want {
				t.Errorf("FindingStatus(%q).Valid() = %v, want %v", tc.fs, got, tc.want)
			}
		})
	}
}

func TestTaskPayload_JSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := json.RawMessage(`{"rule_codes":["SSH-001","FW-002"]}`)
	task := TaskPayload{
		TaskID:    "task-001",
		TaskType:  string(TaskTypeAudit),
		Payload:   payload,
		Timestamp: now,
		Signature: "ed25519sig==",
	}

	data, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("Marshal TaskPayload: %v", err)
	}

	var decoded TaskPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal TaskPayload: %v", err)
	}

	if decoded.TaskID != task.TaskID {
		t.Errorf("TaskID = %q, want %q", decoded.TaskID, task.TaskID)
	}
	if decoded.TaskType != task.TaskType {
		t.Errorf("TaskType = %q, want %q", decoded.TaskType, task.TaskType)
	}
	if decoded.Signature != task.Signature {
		t.Errorf("Signature = %q, want %q", decoded.Signature, task.Signature)
	}
	if !decoded.Timestamp.Equal(task.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, task.Timestamp)
	}
	if string(decoded.Payload) != string(task.Payload) {
		t.Errorf("Payload = %s, want %s", decoded.Payload, task.Payload)
	}
}

func TestTaskResult_JSON(t *testing.T) {
	result := TaskResult{
		TaskID: "task-001",
		Status: "completed",
		Result: json.RawMessage(`{"ok":true}`),
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal TaskResult: %v", err)
	}

	var decoded TaskResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal TaskResult: %v", err)
	}

	if decoded.TaskID != result.TaskID {
		t.Errorf("TaskID = %q, want %q", decoded.TaskID, result.TaskID)
	}
	if decoded.Status != result.Status {
		t.Errorf("Status = %q, want %q", decoded.Status, result.Status)
	}
}

func TestTaskResult_ErrorOmitEmpty(t *testing.T) {
	result := TaskResult{
		TaskID: "task-001",
		Status: "completed",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal TaskResult: %v", err)
	}

	raw := make(map[string]any)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}

	if _, ok := raw["error"]; ok {
		t.Error("error field should be omitted when empty")
	}
	if _, ok := raw["result"]; ok {
		t.Error("result field should be omitted when nil")
	}
}

func TestAuditResult_JSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	result := AuditResult{
		RunID:        "run-001",
		NodeID:       "node-abc",
		Status:       RunStatusCompleted,
		ChecksTotal:  128,
		ChecksPassed: 117,
		StartedAt:    now,
		CompletedAt:  now.Add(45 * time.Second),
		Findings: []Finding{
			{
				RuleCode: "SSH-001",
				Severity: SeverityCritical,
				Status:   FindingStatusOpen,
				Message:  "SSH root login enabled",
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal AuditResult: %v", err)
	}

	var decoded AuditResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal AuditResult: %v", err)
	}

	if decoded.RunID != result.RunID {
		t.Errorf("RunID = %q, want %q", decoded.RunID, result.RunID)
	}
	if decoded.ChecksTotal != 128 {
		t.Errorf("ChecksTotal = %d, want 128", decoded.ChecksTotal)
	}
	if decoded.ChecksPassed != 117 {
		t.Errorf("ChecksPassed = %d, want 117", decoded.ChecksPassed)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("Findings len = %d, want 1", len(decoded.Findings))
	}
	if decoded.Findings[0].RuleCode != "SSH-001" {
		t.Errorf("Finding RuleCode = %q, want SSH-001", decoded.Findings[0].RuleCode)
	}
	if !decoded.StartedAt.Equal(result.StartedAt) {
		t.Errorf("StartedAt = %v, want %v", decoded.StartedAt, result.StartedAt)
	}
}

func TestFinding_OmitEmpty(t *testing.T) {
	f := Finding{
		RuleCode: "FW-001",
		Severity: SeverityWarning,
		Status:   FindingStatusOpen,
		Message:  "Firewall not configured",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal Finding: %v", err)
	}

	raw := make(map[string]any)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}

	if _, ok := raw["fix_command"]; ok {
		t.Error("fix_command should be omitted when empty")
	}
	if _, ok := raw["severity_context"]; ok {
		t.Error("severity_context should be omitted when empty")
	}
}
