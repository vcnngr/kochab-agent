package transport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// Story 3.1 AC-3/AC-4: agent posts AuditResult to /v1/audit_results (distinct
// from the Story 2-2 generic /v1/results contract).
//
// Headers: X-Agent-ID, X-Agent-Auth (hex(HMAC-SHA256(body))), X-Agent-Timestamp
// (RFC3339). The platform's shared.AgentAuthMiddleware verifies replay
// (±5 min) and HMAC; the audit handler verifies the audit_run ↔ node anti-
// spoof inside the engine.
//
// Retries follow the same 3-attempt exponential-backoff pattern as
// ReportClient. Transient 5xx/network failures are retried; 4xx returns
// immediately (platform rejected the payload).

const (
	auditReportPath          = "/v1/audit_results"
	auditReportMaxRetries    = 3
	auditReportInitialBackoff = 1 * time.Second
)

// AuditReportClient posts AuditResult payloads to the platform.
type AuditReportClient struct {
	platformURL string
	agentID     string
	agentSecret string
	httpClient  *http.Client
}

// NewAuditReportClient constructs a reporter. If httpClient is nil, the
// hardened ReportClient TLS-enabled http.Client is reused.
func NewAuditReportClient(platformURL, agentID, agentSecret string, httpClient *http.Client) *AuditReportClient {
	if httpClient == nil {
		httpClient = NewPollClient(platformURL, agentID, agentSecret).httpClient
	}
	return &AuditReportClient{
		platformURL: strings.TrimRight(platformURL, "/"),
		agentID:     agentID,
		agentSecret: agentSecret,
		httpClient:  httpClient,
	}
}

// Report sends result with retry on transient errors.
func (c *AuditReportClient) Report(ctx context.Context, result *protocol.AuditResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("audit_report marshal: %w", err)
	}
	if len(body) > (1 << 20) {
		return fmt.Errorf("audit_report payload exceeds 1MB (%d bytes)", len(body))
	}

	url := c.platformURL + auditReportPath
	backoff := auditReportInitialBackoff
	var lastErr error
	for attempt := range auditReportMaxRetries {
		lastErr = c.doReport(ctx, url, body)
		if lastErr == nil {
			slog.Info("audit_result_reported",
				"audit_run_id", result.RunID,
				"findings", len(result.Findings),
				"attempt", attempt+1,
			)
			return nil
		}
		var ce *clientError
		if errors.As(lastErr, &ce) {
			slog.Warn("audit_result_report_client_error",
				"audit_run_id", result.RunID,
				"status_code", ce.status,
			)
			return fmt.Errorf("audit report %s: %w", result.RunID, lastErr)
		}
		slog.Warn("audit_result_report_retry",
			"audit_run_id", result.RunID,
			"attempt", attempt+1,
			"error", lastErr,
			"backoff", backoff,
		)
		select {
		case <-ctx.Done():
			return fmt.Errorf("audit report context cancelled: %w", ctx.Err())
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return fmt.Errorf("audit report %s failed after %d attempts: %w", result.RunID, auditReportMaxRetries, lastErr)
}

func (c *AuditReportClient) doReport(ctx context.Context, url string, body []byte) error {
	mac := hmac.New(sha256.New, []byte(c.agentSecret))
	mac.Write(body)
	authMAC := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.agentID)
	req.Header.Set("X-Agent-Auth", authMAC)
	req.Header.Set("X-Agent-Timestamp", time.Now().UTC().Format(time.RFC3339))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return &clientError{status: resp.StatusCode, body: string(respBody)}
	}
	return fmt.Errorf("server error HTTP %d: %s", resp.StatusCode, string(respBody))
}

// ReportAuditResult is the package-level convenience wrapper, matching the
// shape of the existing ReportResult helper for ergonomic use from main.go.
func ReportAuditResult(ctx context.Context, result *protocol.AuditResult, platformURL, agentID, agentSecret string, httpClient *http.Client) error {
	return NewAuditReportClient(platformURL, agentID, agentSecret, httpClient).Report(ctx, result)
}
