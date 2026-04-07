// Package protocol defines shared message types for agent ↔ platform communication.
package protocol

import "time"

// UUID represents a UUID v7 identifier (time-ordered). All entity IDs use this type.
type UUID = string

// TaskPayload represents a task sent from the platform to the agent.
type TaskPayload struct {
	TaskID    UUID           `json:"task_id"`
	Type      TaskType       `json:"type"`
	Priority  int            `json:"priority"`
	Payload   map[string]any `json:"payload"`
	Signature string         `json:"signature"`
	IssuedAt  time.Time      `json:"issued_at"`
	ExpiresAt time.Time      `json:"expires_at"`
}

// TaskType enumerates the types of tasks the platform can send.
type TaskType string

const (
	TaskTypeAudit     TaskType = "audit"
	TaskTypeHeartbeat TaskType = "heartbeat"
	TaskTypeProfile   TaskType = "profile"
	TaskTypeExec      TaskType = "exec"
)

// Valid reports whether the task type is a known value.
func (t TaskType) Valid() bool {
	switch t {
	case TaskTypeAudit, TaskTypeHeartbeat, TaskTypeProfile, TaskTypeExec:
		return true
	default:
		return false
	}
}

// AuditResult represents the outcome of an audit run on a node.
type AuditResult struct {
	RunID        UUID      `json:"run_id"`
	NodeID       UUID      `json:"node_id"`
	Status       RunStatus `json:"status"`
	Findings     []Finding `json:"findings"`
	ChecksTotal  int       `json:"checks_total"`
	ChecksPassed int       `json:"checks_passed"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
}

// RunStatus represents the status of an audit run.
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
)

// Valid reports whether the run status is a known value.
func (r RunStatus) Valid() bool {
	switch r {
	case RunStatusPending, RunStatusRunning, RunStatusCompleted, RunStatusFailed:
		return true
	default:
		return false
	}
}

// Finding represents a single audit finding.
type Finding struct {
	RuleCode        string        `json:"rule_code"`
	Severity        SeverityLevel `json:"severity"`
	Status          FindingStatus `json:"status"`
	Message         string        `json:"message"`
	FixCommand      string        `json:"fix_command,omitempty"`
	SeverityContext map[string]any `json:"severity_context,omitempty"`
}

// SeverityLevel represents the severity of a finding.
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityWarning  SeverityLevel = "warning"
	SeverityInfo     SeverityLevel = "info"
	SeveritySerene   SeverityLevel = "serene"
)

// Valid reports whether the severity level is a known value.
func (s SeverityLevel) Valid() bool {
	switch s {
	case SeverityCritical, SeverityWarning, SeverityInfo, SeveritySerene:
		return true
	default:
		return false
	}
}

// FindingStatus represents the status of a finding.
type FindingStatus string

const (
	FindingStatusOpen     FindingStatus = "open"
	FindingStatusFixed    FindingStatus = "fixed"
	FindingStatusAccepted FindingStatus = "accepted"
)

// Valid reports whether the finding status is a known value.
func (f FindingStatus) Valid() bool {
	switch f {
	case FindingStatusOpen, FindingStatusFixed, FindingStatusAccepted:
		return true
	default:
		return false
	}
}

// HeartbeatResponse represents the platform's response to an agent heartbeat.
type HeartbeatResponse struct {
	Acknowledged bool          `json:"acknowledged"`
	Tasks        []TaskPayload `json:"tasks,omitempty"`
	ServerTime   time.Time     `json:"server_time"`
	PollInterval int           `json:"poll_interval"` // seconds between heartbeats
}
