package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTaskType_Valid(t *testing.T) {
	tests := []struct {
		name string
		tt   TaskType
		want bool
	}{
		{"audit", TaskTypeAudit, true},
		{"heartbeat", TaskTypeHeartbeat, true},
		{"profile", TaskTypeProfile, true},
		{"exec", TaskTypeExec, true},
		{"unknown", TaskType("unknown"), false},
		{"empty", TaskType(""), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tt.Valid(); got != tc.want {
				t.Errorf("TaskType(%q).Valid() = %v, want %v", tc.tt, got, tc.want)
			}
		})
	}
}

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
	task := TaskPayload{
		TaskID:    "task-001",
		Type:      TaskTypeAudit,
		Priority:  1,
		Payload:   map[string]any{"rule_codes": []any{"SSH-001", "FW-002"}},
		Signature: "ed25519:abc123",
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
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
	if decoded.Type != task.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, task.Type)
	}
	if decoded.Priority != task.Priority {
		t.Errorf("Priority = %d, want %d", decoded.Priority, task.Priority)
	}
	if decoded.Signature != task.Signature {
		t.Errorf("Signature = %q, want %q", decoded.Signature, task.Signature)
	}
	if !decoded.IssuedAt.Equal(task.IssuedAt) {
		t.Errorf("IssuedAt = %v, want %v", decoded.IssuedAt, task.IssuedAt)
	}
	if !decoded.ExpiresAt.Equal(task.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", decoded.ExpiresAt, task.ExpiresAt)
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
	if !decoded.CompletedAt.Equal(result.CompletedAt) {
		t.Errorf("CompletedAt = %v, want %v", decoded.CompletedAt, result.CompletedAt)
	}
}

func TestHeartbeatResponse_JSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	resp := HeartbeatResponse{
		Acknowledged: true,
		ServerTime:   now,
		PollInterval: 60,
		Tasks:        nil,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal HeartbeatResponse: %v", err)
	}

	var decoded HeartbeatResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal HeartbeatResponse: %v", err)
	}

	if !decoded.Acknowledged {
		t.Error("Acknowledged = false, want true")
	}
	if decoded.PollInterval != 60 {
		t.Errorf("PollInterval = %d, want 60", decoded.PollInterval)
	}
	if decoded.Tasks != nil {
		t.Errorf("Tasks = %v, want nil (omitempty)", decoded.Tasks)
	}
	if !decoded.ServerTime.Equal(resp.ServerTime) {
		t.Errorf("ServerTime = %v, want %v", decoded.ServerTime, resp.ServerTime)
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
