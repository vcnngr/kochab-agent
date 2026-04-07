package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "0.1.0"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("kochab-agent starting", "version", version, "pid", os.Getpid())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Notify systemd we are ready
	sent, err := daemon.SdNotify(false, daemon.SdNotifyReady)
	if err != nil {
		slog.Error("systemd notify failed", "error", err)
	}
	if sent {
		slog.Info("systemd notified: ready")
	}

	if err := run(ctx); err != nil {
		slog.Error("agent exited with error", "error", err)
		os.Exit(1)
	}

	slog.Info("kochab-agent stopped gracefully")
}

func run(ctx context.Context) error {
	// Read watchdog interval from systemd (returns 0 if not running under systemd)
	wdInterval, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		slog.Warn("failed to read watchdog interval from systemd", "error", err)
	}

	// Default to 30s tick; if systemd watchdog is active, tick at half the interval
	tickInterval := 30 * time.Second
	if wdInterval > 0 {
		tickInterval = wdInterval / 2
		slog.Info("systemd watchdog active", "watchdog_sec", wdInterval, "notify_interval", tickInterval)
	}

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	slog.Info("entering agent loop", "tick_interval", tickInterval.String())

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutdown signal received")
			_, _ = daemon.SdNotify(false, daemon.SdNotifyStopping)
			return nil
		case <-ticker.C:
			// Watchdog keepalive
			_, _ = daemon.SdNotify(false, daemon.SdNotifyWatchdog)

			status := map[string]any{
				"status":    "idle",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			}
			statusJSON, err := json.Marshal(status)
			if err != nil {
				slog.Warn("failed to marshal heartbeat status", "error", err)
			}
			slog.Debug("heartbeat", "status", string(statusJSON))

			// Placeholder: qui verrà il loop agent reale
			// 1. Long-poll per task dalla piattaforma
			// 2. Esecuzione task firmati
			// 3. Report risultati
			_ = fmt.Sprintf("agent loop tick at %s", time.Now().UTC())
		}
	}
}
