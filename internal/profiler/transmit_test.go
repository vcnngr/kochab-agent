package profiler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kochab-ai/kochab-agent/internal/enrollment"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

func TestTransmitProfile_HappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/nodes/profile" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Agent-ID") != "agent-1" {
			t.Fatal("missing X-Agent-ID")
		}
		if r.Header.Get("X-Agent-Auth") == "" {
			t.Fatal("missing X-Agent-Auth HMAC")
		}
		if r.Header.Get("X-Agent-Timestamp") == "" {
			t.Fatal("missing X-Agent-Timestamp")
		}

		var payload protocol.ProfilePayload
		json.NewDecoder(r.Body).Decode(&payload)
		if payload.Profile.Hostname != "vortex.local" {
			t.Fatalf("unexpected hostname: %s", payload.Profile.Hostname)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
	}))
	defer ts.Close()

	creds := &enrollment.Credentials{
		AgentID:     "agent-1",
		AgentSecret: "secret-abc",
		PlatformURL: ts.URL,
	}

	profile := &protocol.ProfilePayload{
		Profile: protocol.Profile{
			Hostname: "vortex.local",
			OS:       protocol.OSInfo{Distro: "Debian", Version: "12"},
		},
	}

	err := TransmitProfile(creds, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientError_Message(t *testing.T) {
	// Covers the clientError.Error() method (previously 0% coverage).
	err := &clientError{status: 401, body: "unauthorized"}
	got := err.Error()
	if got != "HTTP 401: unauthorized" {
		t.Errorf("clientError.Error() = %q, want \"HTTP 401: unauthorized\"", got)
	}
}

func TestTransmitProfile_ClientError4xx(t *testing.T) {
	// 4xx → clientError → no retry, immediate return.
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	creds := &enrollment.Credentials{
		AgentID:     "agent-1",
		AgentSecret: "secret",
		PlatformURL: ts.URL,
	}
	profile := &protocol.ProfilePayload{Profile: protocol.Profile{Hostname: "test"}}

	err := TransmitProfile(creds, profile)
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 attempt for 4xx (no retry), got %d", calls)
	}
}

func TestTransmitProfile_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	creds := &enrollment.Credentials{
		AgentID:     "agent-1",
		AgentSecret: "secret",
		PlatformURL: ts.URL,
	}

	profile := &protocol.ProfilePayload{
		Profile: protocol.Profile{Hostname: "test"},
	}

	err := TransmitProfile(creds, profile)
	if err == nil {
		t.Fatal("expected error for server failure")
	}
}
