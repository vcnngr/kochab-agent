// Package audit holds the agent-side audit runner that orchestrates rule
// execution and assembles the AuditResult payload for /v1/audit_results.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/audit/rules"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// TaskPayload is the JSON shape the platform serialises into protocol.TaskPayload.Payload
// for audit dispatches (Story 3.1 AC-2). Only audit_run_id is consumed by the
// runner; rule_categories and estimated_duration_seconds are advisory.
type TaskPayload struct {
	AuditRunID               string   `json:"audit_run_id"`
	NodeID                   string   `json:"node_id,omitempty"`
	RuleCategories           []string `json:"rule_categories,omitempty"`
	EstimatedDurationSeconds int      `json:"estimated_duration_seconds,omitempty"`
}

// RunOptions controls the audit runner. Used to inject a fixed clock and
// override the per-rule timeout from tests.
type RunOptions struct {
	NodeID      string
	Now         func() time.Time
	RuleTimeout time.Duration
}

// Run executes every registered rule against the host and returns an
// AuditResult ready to POST to /v1/audit_results. The error return is
// reserved for setup-level failures (bad payload, no rules registered);
// rule-level failures are surfaced as findings, not errors.
func Run(ctx context.Context, task *protocol.TaskPayload, opts RunOptions) (*protocol.AuditResult, error) {
	if task == nil {
		return nil, errors.New("audit runner: nil task")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.RuleTimeout <= 0 {
		opts.RuleTimeout = rules.DefaultRuleTimeout
	}

	var payload TaskPayload
	if len(task.Payload) > 0 {
		if err := json.Unmarshal(task.Payload, &payload); err != nil {
			return nil, fmt.Errorf("audit runner: parse payload: %w", err)
		}
	}
	if payload.AuditRunID == "" {
		return nil, errors.New("audit runner: payload missing audit_run_id")
	}

	registered := rules.All()
	if len(registered) == 0 {
		return nil, errors.New("audit runner: no rules registered")
	}

	nodeID := opts.NodeID
	if nodeID == "" {
		nodeID = payload.NodeID
	}

	startedAt := opts.Now().UTC()
	result := &protocol.AuditResult{
		RunID:        payload.AuditRunID,
		NodeID:       nodeID,
		Status:       protocol.RunStatusCompleted,
		Findings:     []protocol.Finding{},
		ChecksTotal:  len(registered),
		ChecksPassed: 0,
		StartedAt:    startedAt,
	}

	for _, rule := range registered {
		if ctx.Err() != nil {
			result.Status = protocol.RunStatusFailed
			break
		}
		ruleCtx, cancel := context.WithTimeout(ctx, opts.RuleTimeout)
		passed, rctx, rerr := safeCheck(ruleCtx, rule.Check)
		cancel()

		if rerr != nil {
			// Timeout → "rule timed out" finding (info). Other errors → info finding.
			msg := "rule check failed: " + rerr.Error()
			ctxOut := rctx
			if ctxOut == nil {
				ctxOut = map[string]any{}
			}
			if errors.Is(rerr, context.DeadlineExceeded) {
				msg = "rule timed out"
				ctxOut["timeout_seconds"] = int(opts.RuleTimeout.Seconds())
			}
			result.Findings = append(result.Findings, protocol.Finding{
				RuleCode:        rule.Code,
				Severity:        protocol.SeverityInfo,
				Status:          protocol.FindingStatusOpen,
				Message:         msg,
				SeverityContext: ctxOut,
			})
			slog.Warn("audit_rule_error", "rule_code", rule.Code, "error", rerr)
			continue
		}

		if passed {
			result.ChecksPassed++
			continue
		}

		severity := rules.SeverityForRule[rule.Code]
		if severity == "" {
			severity = protocol.SeverityWarning
		}
		result.Findings = append(result.Findings, protocol.Finding{
			RuleCode:        rule.Code,
			Severity:        severity,
			Status:          protocol.FindingStatusOpen,
			Message:         "rule failed",
			SeverityContext: rctx,
		})
	}

	result.CompletedAt = opts.Now().UTC()
	if result.Status == "" {
		result.Status = protocol.RunStatusCompleted
	}
	return result, nil
}

// safeCheck wraps a CheckFunc call so a rule panic becomes an error rather
// than crashing the agent process. Defensive — rules in the founder seed are
// trusted, but Story 6.x KB pipeline may admit third-party rules.
func safeCheck(ctx context.Context, fn rules.CheckFunc) (passed bool, sctx map[string]any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("rule panic: %v", rec)
		}
	}()
	return fn(ctx)
}
