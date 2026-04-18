package profiler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kochab-ai/kochab-agent/internal/enrollment"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// clientError represents a non-retryable HTTP client error (4xx).
type clientError struct {
	status int
	body   string
}

func (e *clientError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}

const (
	maxRetries     = 3
	initialBackoff = 1 * time.Second
)

// TransmitProfile sends the server profile to the platform with HMAC auth.
func TransmitProfile(creds *enrollment.Credentials, profile *protocol.ProfilePayload) error {
	profile.NodeID = creds.AgentID
	profile.Timestamp = time.Now().UTC().Format(time.RFC3339)

	body, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}

	url := strings.TrimRight(creds.PlatformURL, "/") + "/v1/nodes/profile"

	// Retry with exponential backoff (only for network/5xx errors)
	backoff := initialBackoff
	var lastErr error
	for attempt := range maxRetries {
		lastErr = doTransmit(url, creds.AgentID, creds.AgentSecret, body)
		if lastErr == nil {
			slog.Info("profile_transmitted", "agent_id", creds.AgentID, "attempt", attempt+1)
			return nil
		}
		// Don't retry client errors (4xx)
		var ce *clientError
		if errors.As(lastErr, &ce) {
			return lastErr
		}
		slog.Warn("profile_transmit_retry", "attempt", attempt+1, "error", lastErr)
		time.Sleep(backoff)
		backoff *= 2
	}

	return fmt.Errorf("profile transmit failed after %d attempts: %w", maxRetries, lastErr)
}

func doTransmit(url, agentID, agentSecret string, body []byte) error {
	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(agentSecret))
	mac.Write(body)
	authMAC := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("X-Agent-Auth", authMAC)
	req.Header.Set("X-Agent-Timestamp", time.Now().UTC().Format(time.RFC3339))

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return &clientError{status: resp.StatusCode, body: string(respBody)}
		}
		return fmt.Errorf("server error HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
