package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/kochab-ai/kochab-agent/internal/agent"
	"github.com/kochab-ai/kochab-agent/internal/enrollment"
	"github.com/kochab-ai/kochab-agent/internal/executor"
	"github.com/kochab-ai/kochab-agent/internal/profiler"
	"github.com/kochab-ai/kochab-agent/internal/transport"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "0.1.0"

// errNodeAlreadyDecommissioned is returned by run() when the decommissioned sentinel
// file exists on startup. main() maps this to os.Exit(0) — systemd must not restart.
var errNodeAlreadyDecommissioned = errors.New("node_already_decommissioned")

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	enroll := flag.Bool("enroll", false, "Perform enrollment and exit (token via KOCHAB_ENROLL_TOKEN env var)")
	uninstall := flag.Bool("uninstall", false, "Stop the service and remove agent files (requires root)")
	platformURL := flag.String("platform-url", "https://api.kochab.ai", "Platform API URL")
	flag.Parse()

	if *uninstall {
		if err := runUninstall(); err != nil {
			fmt.Fprintf(os.Stderr, "Errore: %s\n", err)
			os.Exit(2) // partial uninstall — distinguishes from generic errors (1)
		}
		return
	}

	slog.Info("kochab-agent starting", "version", version, "pid", os.Getpid())

	// Validate platform URL scheme
	if !strings.HasPrefix(*platformURL, "https://") {
		slog.Error("platform-url must use HTTPS", "url", *platformURL)
		fmt.Fprintf(os.Stderr, "Errore: platform-url deve usare HTTPS.\n")
		os.Exit(1)
	}

	// Enrollment mode — token from env var (never CLI args, visible in /proc/cmdline)
	if *enroll {
		enrollToken := os.Getenv("KOCHAB_ENROLL_TOKEN")
		if enrollToken == "" {
			slog.Error("KOCHAB_ENROLL_TOKEN env var not set")
			fmt.Fprintf(os.Stderr, "Errore: variabile d'ambiente KOCHAB_ENROLL_TOKEN non impostata.\n")
			os.Exit(1)
		}
		if err := runEnrollment(enrollToken, *platformURL); err != nil {
			slog.Error("enrollment failed", "error", err)
			fmt.Fprintf(os.Stderr, "Errore: %s\n", err)
			os.Exit(1)
		}
		return
	}

	// Normal agent mode — load credentials and enter poll loop.
	creds, err := enrollment.LoadCredentials()
	if err != nil {
		slog.Error("cannot load credentials — run enrollment first", "error", err)
		fmt.Fprintf(os.Stderr, "Errore: credenziali non trovate. Esegui prima l'enrollment.\n")
		os.Exit(1)
	}

	slog.Info("credentials loaded", "agent_id", creds.AgentID, "platform_url", creds.PlatformURL)

	// Load platform public key for Ed25519 task verification.
	platformPubKey, err := loadPlatformPubKey(creds.PlatformPubKey)
	if err != nil {
		slog.Error("cannot load platform public key", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, creds, platformPubKey); err != nil {
		if errors.Is(err, errNodeAlreadyDecommissioned) {
			// Node was decommissioned in a prior run; deferred os.Exit(0) so
			// defer cancel() and other deferred cleanup in main() can execute.
			os.Exit(0)
		}
		// 410 GONE → exit 70 (EX_SOFTWARE) so the operator can distinguish
		// decommissioning from generic agent failure. Flag was persisted in run();
		// systemd restarts and the next startup short-circuits with Exit(0).
		if transport.IsNodeDecommissioned(err) {
			slog.Warn("agent_exit_decommissioned", "code", 70)
			os.Exit(70)
		}
		slog.Error("agent exited with error", "error", err)
		os.Exit(1)
	}

	slog.Info("kochab-agent stopped gracefully")
}

func runEnrollment(token, platformURL string) error {
	slog.Info("enrollment_starting", "platform_url", platformURL)

	fingerprint, err := profiler.GenerateFingerprint()
	if err != nil {
		return fmt.Errorf("generate fingerprint: %w", err)
	}

	hostname, _ := os.Hostname()
	osInfo := profiler.CollectOSInfo()

	creds, err := enrollment.RunEnrollment(token, platformURL, fingerprint, hostname, osInfo)
	if err != nil {
		return err
	}

	if err := enrollment.SaveCredentials(creds); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	if err := agent.GenerateConfig(agent.Config{
		PlatformURL: creds.PlatformURL,
		AgentID:     creds.AgentID,
		LogLevel:    "info",
	}); err != nil {
		slog.Warn("failed to generate config (non-fatal)", "error", err)
	}

	profile, err := profiler.CollectProfile(context.Background(), hostname)
	if err != nil {
		slog.Warn("failed to collect profile (non-fatal)", "error", err)
	} else {
		if err := profiler.TransmitProfile(creds, profile); err != nil {
			slog.Warn("failed to transmit profile (non-fatal)", "error", err)
		}
	}

	_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)

	fmt.Println("✓ Kochab agent installato. Il tuo server è nel cielo.")
	return nil
}

const (
	bufferDir           = "/etc/kochab/buffer"
	decommissionedFlag  = "/etc/kochab/decommissioned"
	decommissionedFlagTmp = "/etc/kochab/decommissioned.tmp"
)

// writeDecommissionedFlag atomically creates the decommissioned sentinel file.
// tmp → fsync → rename → dir-fsync ensures durability across crashes.
// Falls back to a direct write if rename fails (e.g. cross-device).
func writeDecommissionedFlag() {
	if err := os.MkdirAll(filepath.Dir(decommissionedFlagTmp), 0700); err != nil {
		slog.Warn("decommissioned_flag_mkdir_failed", "error", err)
		return
	}
	f, err := os.OpenFile(decommissionedFlagTmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		slog.Warn("decommissioned_flag_create_failed", "error", err)
		return
	}
	if syncErr := f.Sync(); syncErr != nil {
		slog.Warn("decommissioned_flag_sync_failed", "error", syncErr)
	}
	_ = f.Close()
	if renameErr := os.Rename(decommissionedFlagTmp, decommissionedFlag); renameErr != nil {
		slog.Warn("decommissioned_flag_rename_failed", "error", renameErr)
		// Fallback: direct write without atomic rename.
		if df, werr := os.OpenFile(decommissionedFlag, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); werr == nil {
			_ = df.Sync()
			_ = df.Close()
		} else {
			slog.Error("decommissioned_flag_write_failed", "error", werr)
			return
		}
	}
	// Sync the containing directory so the rename is visible after a crash.
	if dirF, dirErr := os.Open(filepath.Dir(decommissionedFlag)); dirErr == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
}

func run(ctx context.Context, creds *enrollment.Credentials, platformPubKey ed25519.PublicKey) error {
	// 6.3 — refuse to start if the platform has already decommissioned this node.
	if _, err := os.Stat(decommissionedFlag); err == nil {
		slog.Warn("node_decommissioned_flag_exists", "path", decommissionedFlag,
			"msg", "nodo rimosso dalla piattaforma — avvio bloccato. Usa --uninstall per rimuovere l'agent.")
		return errNodeAlreadyDecommissioned
	}

	if !strings.HasPrefix(creds.PlatformURL, "https://") {
		return fmt.Errorf("credentials platform_url must use HTTPS, got: %s", creds.PlatformURL)
	}
	pollClient := transport.NewPollClient(creds.PlatformURL, creds.AgentID, creds.AgentSecret)

	buf, err := transport.NewResultBuffer(bufferDir, 0)
	if err != nil {
		return fmt.Errorf("init result buffer: %w", err)
	}

	// Verify function: checks Ed25519 signature and replay protection.
	verifyFn := func(task *protocol.TaskPayload) error {
		return executor.VerifyTask(task, platformPubKey)
	}

	// Execute function: dispatches to the appropriate task handler.
	executeFn := func(ctx context.Context, task *protocol.TaskPayload) (*protocol.TaskResult, error) {
		return executor.Execute(ctx, task)
	}

	// Direct report (no buffering) — used both by retransmit and by the
	// buffering closure passed to RunLoop.
	directReport := func(ctx context.Context, result *protocol.TaskResult) error {
		return transport.ReportResult(ctx, result, creds.PlatformURL, creds.AgentID, creds.AgentSecret, nil)
	}

	// Bounded pre-loop drain: cap wall time so a slow platform with a full
	// buffer cannot starve the poll loop and cause the systemd watchdog to
	// kill us before we ever ping it (review finding H4).
	preDrainCtx, preDrainCancel := context.WithTimeout(ctx, 30*time.Second)
	transport.RetransmitBuffered(preDrainCtx, buf, directReport)
	preDrainCancel()

	// Background drainer: signal-driven (post-success nudge) with a 60s
	// safety ticker. Buffered chan(1) so reportFn can fire-and-forget. The
	// drainer respects ctx; RetransmitBuffered itself is mutex-safe vs the
	// buffering reportFn closure below.
	drainSignal := make(chan struct{}, 1)
	go drainLoop(ctx, buf, directReport, drainSignal)

	// Buffering reporter: on transient failure, persist the result so it
	// survives crashes/restarts. 4xx errors are not buffered (platform
	// rejected the payload). On success, nudge the drainer to flush any
	// older buffered entries while connectivity is known good.
	reportFn := func(ctx context.Context, result *protocol.TaskResult) error {
		err := directReport(ctx, result)
		if err == nil {
			select {
			case drainSignal <- struct{}{}:
			default:
			}
			return nil
		}
		if transport.IsClientError(err) {
			return err
		}
		if writeErr := buf.Write(result); writeErr != nil {
			slog.Warn("buffer_write_failed", "task_id", result.TaskID, "error", writeErr)
		}
		return err
	}

	// Notify systemd watchdog while in loop — RunLoop blocks until ctx cancelled.
	go func() {
		<-ctx.Done()
		_, _ = daemon.SdNotify(false, daemon.SdNotifyStopping)
	}()

	// Watchdog goroutine — keeps systemd happy when WatchdogSec is configured.
	go watchdogLoop(ctx)

	// Notify systemd we are ready only after buffer init, retransmit, and
	// watchdog goroutine are live — otherwise systemd marks the unit ready
	// before its core invariants hold.
	if sent, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		slog.Warn("systemd_notify_ready_failed", "error", err)
	} else if sent {
		slog.Info("systemd_notified_ready")
	}

	slog.Info("entering poll loop")
	loopErr := pollClient.RunLoop(ctx, verifyFn, executeFn, reportFn)
	if transport.IsNodeDecommissioned(loopErr) {
		// 6.2 — platform sent 410 GONE: persist flag so next start aborts cleanly.
		slog.Warn("node_decommissioned", "msg", "Il nodo è stato rimosso dalla piattaforma. Esegui `kochab-agent --uninstall` per rimuovere l'agent locale.")
		writeDecommissionedFlag()
	}
	return loopErr
}

// drainLoop empties the result buffer after the agent enters the poll loop.
// It fires whenever the poll loop reports a successful delivery (the signal
// channel) and on a 60s safety ticker, so a stale buffer eventually drains
// even if no fresh task results trigger a nudge.
func drainLoop(ctx context.Context, buf *transport.ResultBuffer, fn transport.ReportFunc, signal <-chan struct{}) {
	const safetyTick = 60 * time.Second
	ticker := time.NewTicker(safetyTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("drain_loop_stopped")
			return
		case <-signal:
		case <-ticker.C:
		}
		// RetransmitBuffered exits on first transient error; that's fine —
		// next signal/tick will retry.
		transport.RetransmitBuffered(ctx, buf, fn)
	}
}

// watchdogLoop periodically pings systemd watchdog. Interval is half of
// WATCHDOG_USEC (set by systemd when WatchdogSec is configured); falls back
// to 60s when the env var is missing (still cheap; systemd ignores notifies
// outside of WatchdogSec).
func watchdogLoop(ctx context.Context) {
	const minInterval = time.Second // protects against ticker(0) panic on misconfig
	interval := 60 * time.Second
	if v := os.Getenv("WATCHDOG_USEC"); v != "" {
		// systemd sets WATCHDOG_USEC to the unit's WatchdogSec in microseconds;
		// recommended ping interval is half that value.
		usec, err := strconv.ParseUint(v, 10, 64)
		if err == nil && usec >= 2 {
			candidate := time.Duration(usec/2) * time.Microsecond
			if candidate < minInterval {
				candidate = minInterval
			}
			interval = candidate
		} else {
			slog.Warn("watchdog_usec_invalid", "value", v, "fallback", interval)
		}
	}
	slog.Info("watchdog_loop_started", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("watchdog_loop_stopped")
			return
		case <-ticker.C:
			if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
				slog.Warn("watchdog_notify_failed", "error", err)
			}
		}
	}
}

// runUninstall stops the service, verifies it is actually inactive, then
// removes binary, unit, and /etc/kochab. Requires root. Failed steps are
// tracked: if any step fails (or the service is still active after the stop
// timeout) we return an error so the caller can exit non-zero — operators
// running --uninstall in scripts must not be misled by a "rimosso" message
// after a partial cleanup.
func runUninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("kochab-agent --uninstall richiede root")
	}

	binPath, _ := os.Executable()
	const canonicalBin = "/usr/local/bin/kochab-agent"
	if binPath == "" {
		binPath = canonicalBin
	}

	var failed []string
	runStep := func(name string, fn func() error) {
		if err := fn(); err != nil {
			slog.Warn("uninstall_step_failed", "step", name, "error", err)
			failed = append(failed, name)
		}
	}

	runStep("systemctl stop", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "systemctl", "stop", "kochab-agent").Run()
	})
	// Verify the unit is actually inactive before removing files — avoids the
	// race where systemctl returned but the daemon is still mid-write.
	if !waitServiceInactive("kochab-agent", 5*time.Second) {
		slog.Warn("uninstall_step_failed", "step", "stop verify", "error", "service still active after 5s")
		failed = append(failed, "stop verify")
	}
	runStep("systemctl disable", func() error {
		return exec.Command("systemctl", "disable", "kochab-agent").Run()
	})
	runStep("remove binary", func() error {
		// Always remove the canonical install path. os.Executable() may return a
		// symlink or temp path, so we clean the real location unconditionally.
		err := os.Remove(canonicalBin)
		if os.IsNotExist(err) {
			err = nil
		}
		if binPath != canonicalBin {
			if e := os.Remove(binPath); e != nil && !os.IsNotExist(e) && err == nil {
				err = e
			}
		}
		return err
	})
	runStep("remove unit", func() error {
		return os.Remove("/etc/systemd/system/kochab-agent.service")
	})
	runStep("remove /etc/kochab", func() error {
		if _, statErr := os.Stat(decommissionedFlag); statErr == nil {
			slog.Info("decommissioned_flag_removed_during_uninstall", "path", decommissionedFlag)
		}
		return os.RemoveAll("/etc/kochab")
	})
	runStep("systemctl daemon-reload", func() error {
		return exec.Command("systemctl", "daemon-reload").Run()
	})

	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "Uninstall parziale. Step falliti: %v\n", failed)
		return fmt.Errorf("uninstall: %d step falliti", len(failed))
	}
	fmt.Println("Kochab agent rimosso. Il nodo resta visibile nel tuo cielo.")
	return nil
}

// waitServiceInactive polls `systemctl is-active --quiet` until it reports
// not-active or timeout elapses. Uses CommandContext so a hung systemctl
// subprocess cannot block uninstall beyond the remaining deadline.
func waitServiceInactive(unit string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	const checkTimeout = 2 * time.Second
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		ctxTimeout := checkTimeout
		if remaining < ctxTimeout {
			ctxTimeout = remaining
		}
		ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
		err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run()
		cancel()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return true // non-zero exit from systemctl ⇒ not active
			}
			// exec error (binary not found, dbus unavailable) — cannot determine state
			slog.Warn("waitServiceInactive_exec_error", "error", err)
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// loadPlatformPubKey decodes the base64-encoded Ed25519 public key from credentials.
func loadPlatformPubKey(pubKeyB64 string) (ed25519.PublicKey, error) {
	if pubKeyB64 == "" {
		return nil, fmt.Errorf("platform_public_key is empty in credentials")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode platform public key: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("platform public key: expected %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
	}
	return ed25519.PublicKey(keyBytes), nil
}
