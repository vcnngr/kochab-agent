package enrollment

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoadCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key")

	creds := &Credentials{
		AgentID:        "agent-test-123",
		AgentSecret:    "secret-test-abc",
		PlatformPubKey: "pubkey-test",
		PlatformURL:    "https://api.kochab.ai",
		EnrolledAt:     time.Now().UTC().Truncate(time.Second),
	}

	if err := SaveCredentialsTo(creds, path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600, got %04o", perm)
	}

	// Load back
	loaded, err := LoadCredentialsFrom(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.AgentID != creds.AgentID {
		t.Fatalf("agent_id mismatch: %s != %s", loaded.AgentID, creds.AgentID)
	}
	if loaded.AgentSecret != creds.AgentSecret {
		t.Fatalf("agent_secret mismatch")
	}
	if loaded.PlatformURL != creds.PlatformURL {
		t.Fatalf("platform_url mismatch")
	}
}

func TestLoadCredentials_NotFound(t *testing.T) {
	_, err := LoadCredentialsFrom("/nonexistent/path/agent.key")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadCredentials_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCredentialsFrom(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadCredentials_MissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(path, []byte(`{"agent_id":"","agent_secret":"","platform_url":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCredentialsFrom(path)
	if err == nil {
		t.Fatal("expected error for empty agent_id")
	}
}
