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
			status, reason := runPreflight(ctx, rule, opts.RuleTimeout)
			result.Findings = append(result.Findings, protocol.Finding{
				RuleCode:        rule.Code,
				Severity:        protocol.SeverityInfo,
				Status:          protocol.FindingStatusOpen,
				Message:         msg,
				SeverityContext: ctxOut,
				PreflightStatus: status,
				PreflightReason: reason,
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
		// D-4.1-1: eager pre-flight. The rule failed (finding produced), so run
		// its read-only preflight now and embed the outcome in the payload —
		// zero extra round-trips when the operator opens the finding detail.
		status, reason := runPreflight(ctx, rule, opts.RuleTimeout)
		result.Findings = append(result.Findings, protocol.Finding{
			RuleCode:        rule.Code,
			Severity:        severity,
			Status:          protocol.FindingStatusOpen,
			Message:         "rule failed",
			SeverityContext: rctx,
			PreflightStatus: status,
			PreflightReason: reason,
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

// lockoutPreflightUnverifiableReason is surfaced as preflight_reason when a
// fail-closed (lockout-sensitive) rule's preflight cannot be verified — error,
// panic, or unknown exit code. Showing the fix in this case carries real
// lockout risk, so the fix is suppressed and this guidance is shown instead.
const lockoutPreflightUnverifiableReason = "Impossibile verificare l'accesso con chiave SSH — fix bloccato per sicurezza. Configura e verifica una chiave SSH."

// runPreflight executes a failing rule's READ-ONLY pre-flight guardrail (Story
// 4.1, D-4.1-1) and maps its exit code to a protocol.PreflightStatus.
//
//	rule has no preflight        → "none"   (fix shown)
//	PreflightExitPass  (exit 0)  → "passed" (fix shown)
//	PreflightExitBlock (exit 1)  → "blocked" + reason (fix suppressed by platform)
//	PreflightExitSkip  (exit 2)  → "skipped" (not applicable → treated as pass; fix shown)
//
// Per-rule failure policy for the error/panic/unknown-exit branch:
//
//   - Default (fail-OPEN): degrades to "passed" so a flaky read-only probe never
//     silently suppresses a legitimate fix. This suits the bulk of rules.
//   - FailClosed (fail-CLOSED): for lockout-sensitive guardrails (e.g.
//     ssh.disable_password_auth) the same branch maps to "blocked" with a
//     lockout-risk reason. Showing the fix on an unverifiable probe could lock
//     the operator out, so the safe default is to suppress it.
//
// The preflight runs under the same per-rule timeout as the check and is
// strictly read-only — no fix is ever executed here.
func runPreflight(ctx context.Context, rule rules.Rule, timeout time.Duration) (protocol.PreflightStatus, *string) {
	if !rule.HasPreflight() {
		return protocol.PreflightStatusNone, nil
	}
	preCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	code, reason, err := safePreflight(preCtx, rule.Preflight)
	if err != nil {
		slog.Warn("audit_preflight_error", "rule_code", rule.Code, "error", err, "fail_closed", rule.FailClosed)
		return preflightFailurePolicy(rule)
	}
	switch code {
	case rules.PreflightExitBlock:
		r := reason
		return protocol.PreflightStatusBlocked, &r
	case rules.PreflightExitSkip:
		return protocol.PreflightStatusSkipped, nil
	case rules.PreflightExitPass:
		return protocol.PreflightStatusPassed, nil
	default:
		slog.Warn("audit_preflight_unknown_exit", "rule_code", rule.Code, "exit_code", code, "fail_closed", rule.FailClosed)
		return preflightFailurePolicy(rule)
	}
}

// preflightFailurePolicy resolves the error/panic/unknown-exit outcome for a
// rule according to its FailClosed flag: lockout-sensitive rules block (suppress
// the fix) with lockout guidance; all others pass (show the fix).
func preflightFailurePolicy(rule rules.Rule) (protocol.PreflightStatus, *string) {
	if rule.FailClosed {
		r := lockoutPreflightUnverifiableReason
		return protocol.PreflightStatusBlocked, &r
	}
	return protocol.PreflightStatusPassed, nil
}

// safePreflight wraps a PreflightFunc call so a panic becomes an error rather
// than crashing the agent process. Mirrors safeCheck.
func safePreflight(ctx context.Context, fn rules.PreflightFunc) (code int, reason string, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("preflight panic: %v", rec)
		}
	}()
	return fn(ctx)
}
