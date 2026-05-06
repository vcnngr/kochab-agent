package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kochab-ai/kochab-agent/internal/transport"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// taskResponse mirrors the platform response shape.
type taskResponseWrapper struct {
	Data protocol.TaskPayload `json:"data"`
	Meta map[string]any       `json:"meta"`
}

func makeTaskServer(t *testing.T, statusCode int, task *protocol.TaskPayload) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tasks" || r.Method != http.MethodGet {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Agent-ID") == "" || r.Header.Get("X-Agent-Auth") == "" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		if statusCode == http.StatusNoContent {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if task != nil {
			_ = json.NewEncoder(w).Encode(taskResponseWrapper{Data: *task})
		}
	}))
}

func newTestClient(t *testing.T, serverURL, agentID, agentSecret string) *transport.PollClient {
	t.Helper()
	// For tests against httptest.TLSServer we need to use the test client transport.
	// PollClient enforces TLS1.3 but httptest uses its own cert — we expose a constructor
	// that accepts a custom http.Client for testability.
	return transport.NewPollClientWithHTTPClient(serverURL, agentID, agentSecret, transport.InsecureTestClient())
}

// --- Tests ---

func TestPollClient_200_ReturnsTask(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	task := &protocol.TaskPayload{
		TaskID:    "task-abc",
		TaskType:  "ping",
		Payload:   json.RawMessage(`{}`),
		Timestamp: now,
		Signature: "sig==",
	}

	srv := makeTaskServer(t, http.StatusOK, task)
	defer srv.Close()

	client := newTestClient(t, srv.URL, "agent-01", "secret")
	got, err := client.Poll(context.Background())

	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got == nil {
		t.Fatal("expected task, got nil")
	}
	if got.TaskID != "task-abc" {
		t.Errorf("TaskID = %q, want task-abc", got.TaskID)
	}
	if got.TaskType != "ping" {
		t.Errorf("TaskType = %q, want ping", got.TaskType)
	}
}

func TestPollClient_204_ReturnsNil(t *testing.T) {
	srv := makeTaskServer(t, http.StatusNoContent, nil)
	defer srv.Close()

	client := newTestClient(t, srv.URL, "agent-01", "secret")
	got, err := client.Poll(context.Background())

	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for 204, got %+v", got)
	}
}

func TestPollClient_401_ReturnsFatalError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "agent-01", "secret")
	_, err := client.Poll(context.Background())

	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	// Error message should indicate auth failure.
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}
}

func TestPollClient_AuthHeadersPresent(t *testing.T) {
	var gotAgentID, gotAgentAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgentID = r.Header.Get("X-Agent-ID")
		gotAgentAuth = r.Header.Get("X-Agent-Auth")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "my-agent-id", "my-secret")
	_, _ = client.Poll(context.Background())

	if gotAgentID != "my-agent-id" {
		t.Errorf("X-Agent-ID = %q, want my-agent-id", gotAgentID)
	}
	if gotAgentAuth == "" {
		t.Error("X-Agent-Auth should not be empty")
	}
}

func TestPollClient_TimestampHeader(t *testing.T) {
	var gotTimestamp string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTimestamp = r.Header.Get("X-Agent-Timestamp")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "agent-01", "secret")
	_, _ = client.Poll(context.Background())

	if gotTimestamp == "" {
		t.Error("X-Agent-Timestamp must be present (W0 closed: timestamp reintroduced in commit 968aa3a)")
	}
	// Must be valid RFC3339.
	if _, err := time.Parse(time.RFC3339, gotTimestamp); err != nil {
		t.Errorf("X-Agent-Timestamp %q is not RFC3339: %v", gotTimestamp, err)
	}
}

func TestRunLoop_204Reconnects(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "agent-01", "secret")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	noopVerify := func(*protocol.TaskPayload) error { return nil }
	noopExecute := func(context.Context, *protocol.TaskPayload) (*protocol.TaskResult, error) {
		return &protocol.TaskResult{TaskID: "", Status: "completed"}, nil
	}
	noopReport := func(context.Context, *protocol.TaskResult) error { return nil }

	client.RunLoop(ctx, noopVerify, noopExecute, noopReport)

	// With 204s, the loop reconnects immediately — expect multiple calls.
	if got := callCount.Load(); got < 2 {
		t.Errorf("expected multiple poll calls after 204, got %d", got)
	}
}
