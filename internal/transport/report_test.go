package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kochab-ai/kochab-agent/internal/transport"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

func makeResult(taskID, status string) *protocol.TaskResult {
	return &protocol.TaskResult{
		TaskID: taskID,
		Status: status,
		Result: json.RawMessage(`{"ok":true}`),
	}
}

func TestReportResult_200_Accepted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/results" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Agent-ID") == "" || r.Header.Get("X-Agent-Auth") == "" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]bool{"accepted": true}})
	}))
	defer srv.Close()

	err := transport.ReportResult(
		context.Background(),
		makeResult("task-001", "completed"),
		srv.URL, "agent-01", "secret",
		transport.InsecureTestClient(),
	)
	if err != nil {
		t.Fatalf("ReportResult: %v", err)
	}
}

func TestReportResult_RetryOn500(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Succeed on 3rd attempt.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]bool{"accepted": true}})
	}))
	defer srv.Close()

	err := transport.ReportResult(
		context.Background(),
		makeResult("task-002", "completed"),
		srv.URL, "agent-01", "secret",
		transport.InsecureTestClient(),
	)
	if err != nil {
		t.Fatalf("ReportResult should succeed after retry, got: %v", err)
	}
	if calls < 3 {
		t.Errorf("expected at least 3 attempts, got %d", calls)
	}
}

func TestReportResult_NoRetryOn400(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	err := transport.ReportResult(
		context.Background(),
		makeResult("task-003", "completed"),
		srv.URL, "agent-01", "secret",
		transport.InsecureTestClient(),
	)
	if err == nil {
		t.Fatal("expected error for 400, got nil")
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 call for 400 (no retry), got %d", calls)
	}
}
