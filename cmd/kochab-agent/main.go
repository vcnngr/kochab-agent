package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	enroll := flag.Bool("enroll", false, "Perform enrollment and exit (token via KOCHAB_ENROLL_TOKEN env var)")
	platformURL := flag.String("platform-url", "https://api.kochab.ai", "Platform API URL")
	flag.Parse()

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

	// Notify systemd we are ready.
	sent, err := daemon.SdNotify(false, daemon.SdNotifyReady)
	if err != nil {
		slog.Error("systemd notify failed", "error", err)
	}
	if sent {
		slog.Info("systemd notified: ready")
	}

	if err := run(ctx, creds, platformPubKey); err != nil {
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

	profile, err := profiler.CollectProfile(hostname)
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

func run(ctx context.Context, creds *enrollment.Credentials, platformPubKey ed25519.PublicKey) error {
	if !strings.HasPrefix(creds.PlatformURL, "https://") {
		return fmt.Errorf("credentials platform_url must use HTTPS, got: %s", creds.PlatformURL)
	}
	pollClient := transport.NewPollClient(creds.PlatformURL, creds.AgentID, creds.AgentSecret)

	// Verify function: checks Ed25519 signature and replay protection.
	verifyFn := func(task *protocol.TaskPayload) error {
		return executor.VerifyTask(task, platformPubKey)
	}

	// Execute function: dispatches to the appropriate task handler.
	executeFn := func(ctx context.Context, task *protocol.TaskPayload) (*protocol.TaskResult, error) {
		return executor.Execute(ctx, task)
	}

	// Report function: sends task result back to the platform with retry.
	reportFn := func(ctx context.Context, result *protocol.TaskResult) error {
		return transport.ReportResult(ctx, result, creds.PlatformURL, creds.AgentID, creds.AgentSecret, nil)
	}

	slog.Info("entering poll loop")

	// Notify systemd watchdog while in loop — RunLoop blocks until ctx cancelled.
	go func() {
		<-ctx.Done()
		_, _ = daemon.SdNotify(false, daemon.SdNotifyStopping)
	}()

	pollClient.RunLoop(ctx, verifyFn, executeFn, reportFn)
	return nil
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
