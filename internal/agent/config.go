package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	configDir  = "/etc/kochab"
	configFile = "config.toml"
	dirPerms   = 0755
	filePerms  = 0640
)

// Config holds the agent runtime configuration.
type Config struct {
	PlatformURL string
	AgentID     string
	LogLevel    string
}

// GenerateConfig writes config.toml after enrollment.
func GenerateConfig(cfg Config) error {
	return GenerateConfigTo(cfg, filepath.Join(configDir, configFile))
}

// GenerateConfigTo writes config to a specific path (testable).
func GenerateConfigTo(cfg Config, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}

	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}

	content := fmt.Sprintf(`# Kochab Agent Configuration
# Auto-generated after enrollment — do not edit manually

[platform]
url = %q

[agent]
id = %q

[logging]
level = %q
`, cfg.PlatformURL, cfg.AgentID, logLevel)

	if err := os.WriteFile(path, []byte(content), filePerms); err != nil {
		return fmt.Errorf("write config to %s: %w", path, err)
	}

	return nil
}
