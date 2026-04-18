package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateConfigTo_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	cfg := Config{
		PlatformURL: "https://api.kochab.ai",
		AgentID:     "agent-abc-123",
		LogLevel:    "debug",
	}

	if err := GenerateConfigTo(cfg, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, `url = "https://api.kochab.ai"`) {
		t.Fatal("config should contain platform URL")
	}
	if !strings.Contains(content, `id = "agent-abc-123"`) {
		t.Fatal("config should contain agent ID")
	}
	if !strings.Contains(content, `level = "debug"`) {
		t.Fatal("config should contain log level")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0640 {
		t.Fatalf("expected file perms 0640, got %04o", perm)
	}
}

func TestGenerateConfigTo_DefaultLogLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	cfg := Config{
		PlatformURL: "https://api.kochab.ai",
		AgentID:     "agent-xyz",
	}

	if err := GenerateConfigTo(cfg, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `level = "info"`) {
		t.Fatal("empty LogLevel should default to info")
	}
}

func TestGenerateConfigTo_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub", "dir")
	path := filepath.Join(nested, "config.toml")

	cfg := Config{
		PlatformURL: "https://api.kochab.ai",
		AgentID:     "agent-nested",
		LogLevel:    "warn",
	}

	if err := GenerateConfigTo(cfg, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config file should exist: %v", err)
	}
}

func TestGenerateConfigTo_InvalidPath(t *testing.T) {
	// /dev/null/impossible is not writable on any OS
	path := "/dev/null/impossible/config.toml"
	cfg := Config{PlatformURL: "https://api.kochab.ai", AgentID: "x"}

	if err := GenerateConfigTo(cfg, path); err == nil {
		t.Fatal("expected error for invalid path")
	}
}
