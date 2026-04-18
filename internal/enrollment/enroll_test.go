package enrollment

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

func TestRunEnrollment_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/enroll" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}

		var req protocol.EnrollmentRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.EnrollmentToken == "" {
			t.Fatal("missing enrollment token")
		}
		if req.ServerFingerprint == "" {
			t.Fatal("missing fingerprint")
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"data": protocol.EnrollmentResponse{
				AgentID:        "agent-123",
				AgentSecret:    "secret-abc",
				PlatformPubKey: "pubkey-xyz",
				PlatformURL:    "https://api.kochab.ai",
			},
			"meta": map[string]string{"request_id": "test", "timestamp": "2026-04-10T00:00:00Z"},
		})
	}))
	defer ts.Close()

	creds, err := RunEnrollment("test-token", ts.URL, "fp-123", "vortex.local", protocol.OSInfo{
		Distro: "Debian", Version: "12",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.AgentID != "agent-123" {
		t.Fatalf("expected agent-123, got %s", creds.AgentID)
	}
	if creds.AgentSecret != "secret-abc" {
		t.Fatalf("expected secret-abc, got %s", creds.AgentSecret)
	}
	if creds.PlatformURL != "https://api.kochab.ai" {
		t.Fatalf("expected https://api.kochab.ai, got %s", creds.PlatformURL)
	}
}

func TestRunEnrollment_TokenExpired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "ENROLLMENT_TOKEN_EXPIRED", "message": "Token scaduto"},
			"meta":  map[string]string{"request_id": "test"},
		})
	}))
	defer ts.Close()

	_, err := RunEnrollment("expired-token", ts.URL, "fp", "host", protocol.OSInfo{})
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestRunEnrollment_ServerDown(t *testing.T) {
	_, err := RunEnrollment("token", "http://localhost:1", "fp", "host", protocol.OSInfo{})
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}
