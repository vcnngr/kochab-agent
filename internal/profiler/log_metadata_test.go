package profiler

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestCollectLogMetadata_MockRunner(t *testing.T) {
	orig := LogCommandRunner
	defer func() { LogCommandRunner = orig }()

	LogCommandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		// grep -c sshd /var/log/auth.log  → args[2] = path
		if name == "grep" && len(args) >= 3 && args[2] == "/var/log/auth.log" {
			return []byte("1247\n"), nil
		}
		// grep -c postfix /var/log/mail.log
		if name == "grep" && len(args) >= 3 && args[2] == "/var/log/mail.log" {
			return []byte("89\n"), nil
		}
		// wc -l /var/log/fail2ban.log
		if name == "wc" {
			return []byte("12 /var/log/fail2ban.log\n"), nil
		}
		return []byte("0\n"), nil
	}

	info := CollectLogMetadata(context.Background())

	if info.SSHLogCount != 1247 {
		t.Errorf("SSHLogCount = %d, want 1247", info.SSHLogCount)
	}
	if info.PostfixLogCount != 89 {
		t.Errorf("PostfixLogCount = %d, want 89", info.PostfixLogCount)
	}
	if info.Fail2banLogCount != 12 {
		t.Errorf("Fail2banLogCount = %d, want 12", info.Fail2banLogCount)
	}
}

func TestCollectLogMetadata_FileMissing(t *testing.T) {
	orig := LogCommandRunner
	defer func() { LogCommandRunner = orig }()

	LogCommandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, &exec.ExitError{ProcessState: nil}
	}

	info := CollectLogMetadata(context.Background())

	if info.SSHLogCount != 0 {
		t.Errorf("SSHLogCount = %d, want 0 on file missing", info.SSHLogCount)
	}
	if info.PostfixLogCount != 0 {
		t.Errorf("PostfixLogCount = %d, want 0 on file missing", info.PostfixLogCount)
	}
	if info.Fail2banLogCount != 0 {
		t.Errorf("Fail2banLogCount = %d, want 0 on file missing", info.Fail2banLogCount)
	}
}

func TestCollectLogMetadata_GrepZeroMatch(t *testing.T) {
	orig := LogCommandRunner
	defer func() { LogCommandRunner = orig }()

	// grep -c returns exit code 1 when no lines match — should return 0, not error.
	LogCommandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "grep" {
			return []byte("0\n"), &exec.ExitError{} // exit code 1 normally
		}
		return []byte("0\n"), nil
	}

	info := CollectLogMetadata(context.Background())
	// Should not panic and return 0 counts.
	if info.SSHLogCount != 0 {
		t.Errorf("SSHLogCount = %d, want 0 for zero-match grep", info.SSHLogCount)
	}
}

func TestCollectLogMetadata_TimeoutContext(t *testing.T) {
	orig := LogCommandRunner
	defer func() { LogCommandRunner = orig }()

	LogCommandRunner = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		// Block until context cancelled — simulates slow wc on huge file.
		<-ctx.Done()
		return nil, ctx.Err()
	}

	// Already-cancelled context — should return immediately with 0.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // ensure timeout fires

	info := CollectLogMetadata(ctx)

	if info.SSHLogCount != 0 || info.PostfixLogCount != 0 || info.Fail2banLogCount != 0 {
		t.Error("all counts should be 0 on timeout, got non-zero")
	}
}
