package enrollment

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const (
	configDir = "/etc/kochab"
	keyFile   = "agent.key"
	keyPerms  = 0600
	dirPerms  = 0755
)

// Credentials holds the agent's enrollment credentials.
type Credentials struct {
	AgentID        string    `json:"agent_id"`
	AgentSecret    string    `json:"agent_secret"`
	PlatformPubKey string    `json:"platform_public_key"`
	PlatformURL    string    `json:"platform_url"`
	EnrolledAt     time.Time `json:"enrolled_at"`
}

// SaveCredentials writes credentials to /etc/kochab/agent.key with 0600 perms.
func SaveCredentials(creds *Credentials) error {
	return SaveCredentialsTo(creds, filepath.Join(configDir, keyFile))
}

// SaveCredentialsTo writes credentials to a specific path (testable).
func SaveCredentialsTo(creds *Credentials, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}

	// Warn if overwriting existing credentials (re-enrollment)
	if _, err := os.Stat(path); err == nil {
		slog.Warn("overwriting existing credentials — previous enrollment will be invalidated", "path", path)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, keyPerms); err != nil {
		return fmt.Errorf("write credentials to %s: %w", path, err)
	}

	// Enforce 0600 even if file existed with different permissions
	if err := os.Chmod(path, keyPerms); err != nil {
		return fmt.Errorf("chmod credentials %s: %w", path, err)
	}

	slog.Info("credentials_saved", "path", path)
	return nil
}

// LoadCredentials reads credentials from /etc/kochab/agent.key.
func LoadCredentials() (*Credentials, error) {
	return LoadCredentialsFrom(filepath.Join(configDir, keyFile))
}

// LoadCredentialsFrom reads credentials from a specific path (testable).
func LoadCredentialsFrom(path string) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials from %s: %w", path, err)
	}

	// Warn if permissions are not 0600
	info, err := os.Stat(path)
	if err == nil {
		mode := info.Mode().Perm()
		if mode != keyPerms {
			slog.Warn("credentials file has insecure permissions",
				"path", path,
				"mode", fmt.Sprintf("%04o", mode),
				"expected", fmt.Sprintf("%04o", keyPerms),
			)
		}
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parse credentials from %s: %w", path, err)
	}

	if creds.AgentID == "" || creds.AgentSecret == "" {
		return nil, fmt.Errorf("credentials file %s missing agent_id or agent_secret", path)
	}

	return &creds, nil
}
