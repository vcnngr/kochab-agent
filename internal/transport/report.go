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

const (
	reportMaxRetries     = 3
	reportInitialBackoff = 1 * time.Second
)

// ReportClient sends task results to the platform.
type ReportClient struct {
	platformURL string
	agentID     string
	agentSecret string
	httpClient  *http.Client
}

// NewReportClient creates a ReportClient sharing the same TLS config as PollClient.
func NewReportClient(platformURL, agentID, agentSecret string, httpClient *http.Client) *ReportClient {
	if httpClient == nil {
		httpClient = NewPollClient(platformURL, agentID, agentSecret).httpClient
	}
	return &ReportClient{
		platformURL: strings.TrimRight(platformURL, "/"),
		agentID:     agentID,
		agentSecret: agentSecret,
		httpClient:  httpClient,
	}
}

// ReportResult sends the task result to the platform with retry on 5xx / network errors.
// Never retries on 4xx (client errors).
func ReportResult(ctx context.Context, result *protocol.TaskResult, platformURL, agentID, agentSecret string, httpClient *http.Client) error {
	c := NewReportClient(platformURL, agentID, agentSecret, httpClient)
	return c.Report(ctx, result)
}

// Report sends the result with exponential backoff on transient errors.
func (c *ReportClient) Report(ctx context.Context, result *protocol.TaskResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("report marshal: %w", err)
	}

	url := c.platformURL + "/v1/results"
	backoff := reportInitialBackoff

	var lastErr error
	for attempt := range reportMaxRetries {
		lastErr = c.doReport(ctx, url, body)
		if lastErr == nil {
			slog.Info("task_result_reported",
				"task_id", result.TaskID,
				"status", result.Status,
				"attempt", attempt+1,
			)
			return nil
		}

		// Do not retry on 4xx client errors.
		var ce *clientError
		if errors.As(lastErr, &ce) {
			slog.Warn("task_result_report_client_error",
				"task_id", result.TaskID,
				"status_code", ce.status,
			)
			return fmt.Errorf("report result %s: %w", result.TaskID, lastErr)
		}

		slog.Warn("task_result_report_retry",
			"task_id", result.TaskID,
			"attempt", attempt+1,
			"error", lastErr,
			"backoff", backoff,
		)
		select {
		case <-ctx.Done():
			return fmt.Errorf("report result context cancelled: %w", ctx.Err())
		case <-time.After(backoff):
			backoff *= 2
		}
	}

	slog.Warn("task_result_report_giving_up",
		"task_id", result.TaskID,
		"error", lastErr,
	)
	return fmt.Errorf("report result %s failed after %d attempts: %w", result.TaskID, reportMaxRetries, lastErr)
}

func (c *ReportClient) doReport(ctx context.Context, url string, body []byte) error {
	// Compute HMAC-SHA256 over the body.
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return &clientError{status: resp.StatusCode, body: string(respBody)}
	}
	return fmt.Errorf("server error HTTP %d: %s", resp.StatusCode, string(respBody))
}
