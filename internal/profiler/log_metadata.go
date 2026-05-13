package profiler

import (
	"context"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// LogCommandRunner executes a command with context. Overridable for testing.
var LogCommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error) = defaultLogRunner

func defaultLogRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// CollectLogMetadata counts log file lines using wc -l / grep -c.
// Never reads file content — only counts (NFR12, FR50).
// Missing / inaccessible files return 0 + slog.Warn (no error propagated).
// Total timeout is 5s regardless of caller context.
func CollectLogMetadata(ctx context.Context) protocol.LogMetadataInfo {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var (
		ssh, postfix, fail2ban int
		wg                     sync.WaitGroup
	)
	wg.Add(3)
	go func() { defer wg.Done(); ssh = countLogLines(ctx, "/var/log/auth.log", "sshd") }()
	go func() { defer wg.Done(); postfix = countLogLines(ctx, "/var/log/mail.log", "postfix") }()
	go func() { defer wg.Done(); fail2ban = countLogLines(ctx, "/var/log/fail2ban.log", "") }()
	wg.Wait()

	return protocol.LogMetadataInfo{
		SSHLogCount:      ssh,
		PostfixLogCount:  postfix,
		Fail2banLogCount: fail2ban,
	}
}

// countLogLines returns number of matching lines in path.
// Uses grep -c when pattern is non-empty, wc -l otherwise.
// Returns 0 on any error (file missing, permission denied, timeout).
func countLogLines(ctx context.Context, path, pattern string) int {
	var out []byte
	var err error
	if pattern != "" {
		out, err = LogCommandRunner(ctx, "grep", "-c", pattern, path)
	} else {
		out, err = LogCommandRunner(ctx, "wc", "-l", path)
	}
	if err != nil {
		// grep -c exits 1 with zero matches — treat as 0, not error.
		if exitErr, ok := err.(*exec.ExitError); ok && pattern != "" && exitErr.ProcessState != nil && exitErr.ExitCode() == 1 {
			return 0
		}
		slog.Warn("log_metadata: file not accessible", "path", path, "error", err)
		return 0
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return 0
	}
	n, parseErr := strconv.Atoi(fields[0])
	if parseErr != nil {
		slog.Warn("log_metadata: parse count failed", "path", path, "output", string(out))
		return 0
	}
	return n
}
