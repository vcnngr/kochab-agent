package enrollment

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// RunEnrollment performs the enrollment handshake with the platform.
func RunEnrollment(token, platformURL, fingerprint, hostname string, osInfo protocol.OSInfo) (*Credentials, error) {
	platformURL = strings.TrimRight(platformURL, "/")

	req := protocol.EnrollmentRequest{
		EnrollmentToken:   token,
		ServerFingerprint: fingerprint,
		Hostname:          hostname,
		OSInfo:            osInfo,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal enrollment request: %w", err)
	}

	url := platformURL + "/v1/agents/enroll"
	slog.Info("enrollment_request", "url", url, "hostname", hostname)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		},
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read enrollment response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		var errResp struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error.Code != "" {
			return nil, fmt.Errorf("enrollment failed [%s]: %s", errResp.Error.Code, errResp.Error.Message)
		}
		return nil, fmt.Errorf("enrollment failed: HTTP %d", resp.StatusCode)
	}

	var successResp struct {
		Data protocol.EnrollmentResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &successResp); err != nil {
		return nil, fmt.Errorf("parse enrollment response: %w", err)
	}

	data := successResp.Data
	if data.AgentID == "" || data.AgentSecret == "" {
		return nil, fmt.Errorf("enrollment response missing agent_id or agent_secret")
	}

	// Fall back to user-provided URL if response is empty
	credsPlatformURL := data.PlatformURL
	if credsPlatformURL == "" {
		credsPlatformURL = platformURL
	}

	creds := &Credentials{
		AgentID:        data.AgentID,
		AgentSecret:    data.AgentSecret,
		PlatformPubKey: data.PlatformPubKey,
		PlatformURL:    credsPlatformURL,
		EnrolledAt:     time.Now().UTC(),
	}

	slog.Info("enrollment_completed", "agent_id", data.AgentID)
	return creds, nil
}
