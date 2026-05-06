// Package transport manages the communication channel between agent and platform.
package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

const (
	pollMaxRetries     = 3
	pollInitialBackoff = 2 * time.Second
)

// PollClient polls the platform for pending tasks using HTTP long-polling.
type PollClient struct {
	platformURL string
	agentID     string
	agentSecret string
	httpClient  *http.Client
}

// NewPollClient creates a PollClient with TLS 1.3 enforcement.
func NewPollClient(platformURL, agentID, agentSecret string) *PollClient {
	return NewPollClientWithHTTPClient(platformURL, agentID, agentSecret, &http.Client{
		// Timeout longer than server hang-hold (60s) + margin.
		Timeout: 90 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				// Certificate pinning: deferred W1 from review 2-1, acceptable for MVP.
			},
		},
	})
}

// NewPollClientWithHTTPClient creates a PollClient using the provided HTTP client.
// Use this in tests to inject a custom transport (e.g., httptest.Server TLS).
func NewPollClientWithHTTPClient(platformURL, agentID, agentSecret string, httpClient *http.Client) *PollClient {
	return &PollClient{
		platformURL: strings.TrimRight(platformURL, "/"),
		agentID:     agentID,
		agentSecret: agentSecret,
		httpClient:  httpClient,
	}
}

// InsecureTestClient returns an http.Client that accepts any TLS certificate.
// FOR TESTS ONLY — never use in production.
func InsecureTestClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test-only
			},
		},
	}
}

// Poll performs a single long-poll GET /v1/tasks request.
// Returns nil, nil if the platform responded 204 (no task available).
// Returns an error for non-retryable failures (4xx).
func (c *PollClient) Poll(ctx context.Context) (*protocol.TaskPayload, error) {
	url := c.platformURL + "/v1/tasks"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("poll create request: %w", err)
	}

	// HMAC auth headers — body is empty for GET, sign empty string.
	c.setAuthHeaders(req, nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNoContent:
		// No task available — reconnect immediately.
		return nil, nil

	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("poll read body: %w", err)
		}

		// Response shape: {"data": TaskPayload, "meta": {...}}
		var wrapper struct {
			Data protocol.TaskPayload `json:"data"`
		}
		if err := json.Unmarshal(body, &wrapper); err != nil {
			return nil, fmt.Errorf("poll decode response: %w", err)
		}
		return &wrapper.Data, nil

	case http.StatusGone:
		// Platform has soft-deleted the node — stop polling immediately.
		return nil, ErrNodeDecommissioned

	case http.StatusUnauthorized, http.StatusForbidden:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		slog.Error("poll_auth_failed", "status", resp.StatusCode, "body", string(body))
		return nil, &fatalError{msg: fmt.Sprintf("agent not authorized: HTTP %d", resp.StatusCode)}

	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("poll unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

// RunLoop runs the poll → verify → execute → report cycle until ctx is cancelled.
// Returns ErrNodeDecommissioned if the platform responds 410 GONE; nil on normal shutdown.
// verifyFn and executeFn are injected to break import cycles.
func (c *PollClient) RunLoop(
	ctx context.Context,
	verifyFn func(*protocol.TaskPayload) error,
	executeFn func(context.Context, *protocol.TaskPayload) (*protocol.TaskResult, error),
	reportFn func(context.Context, *protocol.TaskResult) error,
) error {
	slog.Info("poll_loop_started", "platform_url", c.platformURL, "agent_id", c.agentID)
	backoff := pollInitialBackoff

	for {
		if ctx.Err() != nil {
			slog.Info("poll_loop_stopped", "reason", "context_cancelled")
			return nil
		}

		task, err := c.Poll(ctx)
		if err != nil {
			if IsNodeDecommissioned(err) {
				slog.Warn("poll_loop_node_decommissioned", "msg", "node rimosso dalla piattaforma — poll loop terminato")
				return ErrNodeDecommissioned
			}
			if isFatal(err) {
				slog.Error("poll_loop_fatal_error", "error", err)
				return nil
			}
			slog.Warn("poll_error_retrying", "error", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
				backoff = min(backoff*2, 60*time.Second)
				continue
			}
		}

		// Reset backoff on successful poll.
		backoff = pollInitialBackoff

		if task == nil {
			// 204 — no task, reconnect immediately.
			continue
		}

		// Verify signature before any execution.
		if err := verifyFn(task); err != nil {
			slog.Warn("task_rejected", "task_id", task.TaskID, "reason", err.Error())
			continue
		}

		// Execute with per-task timeout.
		taskCtx, taskCancel := context.WithTimeout(ctx, 5*time.Minute)
		result, execErr := executeFn(taskCtx, task)
		taskCancel()

		if execErr != nil {
			slog.Warn("task_execution_failed", "task_id", task.TaskID, "error", execErr)
			result = &protocol.TaskResult{
				TaskID: task.TaskID,
				Status: "failed",
				Error:  execErr.Error(),
			}
		}

		// Report result — best-effort with retries in reportFn.
		if reportErr := reportFn(ctx, result); reportErr != nil {
			slog.Warn("task_report_failed", "task_id", task.TaskID, "error", reportErr)
		}
	}
}

// setAuthHeaders adds HMAC auth headers to the request.
// body may be nil for GET requests (signs empty string per spec).
func (c *PollClient) setAuthHeaders(req *http.Request, body []byte) {
	if body == nil {
		body = []byte{}
	}
	mac := hmac.New(sha256.New, []byte(c.agentSecret))
	mac.Write(body)
	authMAC := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-Agent-ID", c.agentID)
	req.Header.Set("X-Agent-Auth", authMAC)
	req.Header.Set("X-Agent-Timestamp", time.Now().UTC().Format(time.RFC3339))
}

// fatalError marks non-retryable failures (4xx auth errors).
type fatalError struct{ msg string }

func (e *fatalError) Error() string { return e.msg }

func isFatal(err error) bool {
	_, ok := err.(*fatalError)
	return ok
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
