// Package protocol defines shared message types for agent ↔ platform communication.
package protocol

import (
	"encoding/json"
	"time"
)

// UUID represents a UUID identifier. All entity IDs use this type.
type UUID = string

// TaskPayload represents a task sent from the platform to the agent.
// The signature covers: task_id|task_type|hex(sha256(payload))|RFC3339(timestamp)
type TaskPayload struct {
	TaskID    UUID            `json:"task_id"`
	TaskType  string          `json:"task_type"`
	Payload   json.RawMessage `json:"payload"`
	Timestamp time.Time       `json:"timestamp"`
	Signature string          `json:"signature"` // Ed25519 base64
}

// TaskResult is sent from the agent to the platform after executing a task.
type TaskResult struct {
	TaskID string          `json:"task_id"`
	Status string          `json:"status"` // "completed" or "failed"
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// TaskType enumerates the types of tasks the platform can send.
type TaskType string

const (
	TaskTypeAudit          TaskType = "audit"
	TaskTypePing           TaskType = "ping"
	TaskTypeProfileRefresh TaskType = "profile_refresh"
)

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

// Finding represents a single audit finding.
type Finding struct {
	RuleCode        string         `json:"rule_code"`
	Severity        SeverityLevel  `json:"severity"`
	Status          FindingStatus  `json:"status"`
	Message         string         `json:"message"`
	FixCommand      string         `json:"fix_command,omitempty"`
	SeverityContext map[string]any `json:"severity_context,omitempty"`
}

// EnrollmentRequest is the payload sent to the platform during enrollment.
type EnrollmentRequest struct {
	EnrollmentToken   string `json:"enrollment_token"`
	ServerFingerprint string `json:"server_fingerprint"`
	Hostname          string `json:"hostname"`
	OSInfo            OSInfo `json:"os_info"`
}

// OSInfo describes the agent's operating system.
type OSInfo struct {
	Distro  string `json:"distro"`
	Version string `json:"version"`
	Kernel  string `json:"kernel"`
	Arch    string `json:"arch"`
}

// EnrollmentResponse is returned from the platform after successful enrollment.
type EnrollmentResponse struct {
	AgentID        string `json:"agent_id"`
	AgentSecret    string `json:"agent_secret"`
	PlatformPubKey string `json:"platform_public_key"`
	PlatformURL    string `json:"platform_url"`
}

// ProfilePayload is the server profile sent to the platform.
type ProfilePayload struct {
	NodeID    string  `json:"node_id"`
	Timestamp string  `json:"timestamp"`
	Profile   Profile `json:"profile"`
}

// Profile contains the server's system information.
type Profile struct {
	Hostname    string           `json:"hostname"`
	OS          OSInfo           `json:"os"`
	Packages    PackagesInfo     `json:"packages"`
	Services    ServicesInfo     `json:"services"`
	Network     NetworkInfo      `json:"network"`
	Config      ConfigInfo       `json:"configuration"`
	LogMetadata *LogMetadataInfo `json:"log_metadata,omitempty"`
}

// LogMetadataInfo holds log file line counts — never log content (FR50, NFR12).
type LogMetadataInfo struct {
	SSHLogCount      int `json:"ssh_log_count"`
	PostfixLogCount  int `json:"postfix_log_count"`
	Fail2banLogCount int `json:"fail2ban_log_count"`
}

// PackagesInfo summarizes installed packages.
type PackagesInfo struct {
	TotalCount      int      `json:"total_count"`
	SecurityUpdates int      `json:"security_updates"`
	List            []string `json:"list"`
}

// ServicesInfo summarizes running services.
type ServicesInfo struct {
	TotalRunning int      `json:"total_running"`
	List         []string `json:"list"`
}

// NetworkInfo describes network configuration.
type NetworkInfo struct {
	OpenPorts  []int    `json:"open_ports"`
	Interfaces []string `json:"interfaces"`
}

// ConfigInfo holds security-relevant configuration details.
type ConfigInfo struct {
	SSHAuthMethods   []string `json:"ssh_auth_methods"`
	SSHCiphers       []string `json:"ssh_ciphers"`
	FirewallEnabled  bool     `json:"firewall_enabled"`
	UsersCount       int      `json:"users_count"`
	ContainerRuntime *string  `json:"container_runtime"`
}
