package rules

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
)

// cmdOutput runs a binary with a context deadline and returns stdout + exit code.
// Honours the rule timeout: if ctx fires, the process is killed.
// Returns (stdout, exitCode, errIfFatal). exitCode == -1 means "no process".
func cmdOutput(ctx context.Context, name string, args ...string) (string, int, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", -1, errCmdNotFound
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return "", -1, ctx.Err()
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout.String(), exitErr.ExitCode(), nil
		}
		return "", -1, err
	}
	return stdout.String(), 0, nil
}

// errCmdNotFound is returned by cmdOutput when the binary is absent. Rule
// authors map it to "skip" semantics: pass=true with skipped_reason in context.
var errCmdNotFound = errors.New("command not found")

// isCmdNotFound reports whether err originates from a missing binary.
func isCmdNotFound(err error) bool {
	return errors.Is(err, errCmdNotFound)
}

// readFile returns file contents as string. Missing file returns ("", false, nil).
// errors other than ENOENT are surfaced.
func readFile(path string) (string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return string(data), true, nil
}

// fileExists is a tight helper for preflight checks.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// lineMatches returns true if any non-comment line of s matches predicate.
func lineMatches(s string, pred func(string) bool) bool {
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if pred(line) {
			return true
		}
	}
	return false
}

// firstLine returns the first non-empty line of s.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}

// readerLines wraps an io.Reader → []string. Not exported but handy.
func readerLines(r io.Reader) ([]string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(b), "\n"), nil
}
