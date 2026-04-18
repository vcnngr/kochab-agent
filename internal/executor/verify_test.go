package executor_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kochab-ai/kochab-agent/internal/executor"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// buildSignedMessage replicates the platform signing format for test setup.
func buildSignedMessage(taskID, taskType string, payload []byte, timestamp time.Time) []byte {
	hash := sha256.Sum256(payload)
	hashHex := fmt.Sprintf("%x", hash)
	msg := fmt.Sprintf("%s|%s|%s|%s",
		taskID,
		taskType,
		hashHex,
		timestamp.UTC().Format(time.RFC3339),
	)
	return []byte(msg)
}

func makeSignedTask(t *testing.T, priv ed25519.PrivateKey, taskID, taskType string, payload map[string]any, ts time.Time) protocol.TaskPayload {
	t.Helper()
	payloadBytes, _ := json.Marshal(payload)
	msg := buildSignedMessage(taskID, taskType, payloadBytes, ts)
	sig := ed25519.Sign(priv, msg)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	return protocol.TaskPayload{
		TaskID:    taskID,
		TaskType:  taskType,
		Payload:   json.RawMessage(payloadBytes),
		Timestamp: ts,
		Signature: sigB64,
	}
}

func TestVerifyTask_ValidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ts := time.Now().UTC().Truncate(time.Second)
	task := makeSignedTask(t, priv, "task-001", "ping", map[string]any{}, ts)

	if err := executor.VerifyTask(&task, pub); err != nil {
		t.Errorf("expected nil error for valid signature, got %v", err)
	}
}

func TestVerifyTask_InvalidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ts := time.Now().UTC().Truncate(time.Second)
	task := makeSignedTask(t, priv, "task-001", "ping", map[string]any{}, ts)

	// Tamper with the signature.
	task.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))

	err := executor.VerifyTask(&task, pub)
	if !errors.Is(err, executor.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyTask_TamperedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ts := time.Now().UTC().Truncate(time.Second)
	task := makeSignedTask(t, priv, "task-001", "audit", map[string]any{"rule": "SSH-001"}, ts)

	// Tamper with payload after signing — signature should fail.
	task.Payload = json.RawMessage(`{"rule":"EVIL-999"}`)

	err := executor.VerifyTask(&task, pub)
	if !errors.Is(err, executor.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for tampered payload, got %v", err)
	}
}

func TestVerifyTask_TimestampExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	// Timestamp 6 minutes in the past — beyond replay window.
	ts := time.Now().UTC().Add(-6 * time.Minute).Truncate(time.Second)
	task := makeSignedTask(t, priv, "task-001", "ping", map[string]any{}, ts)

	err := executor.VerifyTask(&task, pub)
	if !errors.Is(err, executor.ErrTimestampExpired) {
		t.Errorf("expected ErrTimestampExpired, got %v", err)
	}
}

func TestVerifyTask_TimestampFuture(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	// Timestamp 6 minutes in the future — clock skew protection.
	ts := time.Now().UTC().Add(6 * time.Minute).Truncate(time.Second)
	task := makeSignedTask(t, priv, "task-001", "ping", map[string]any{}, ts)

	err := executor.VerifyTask(&task, pub)
	if !errors.Is(err, executor.ErrTimestampFuture) {
		t.Errorf("expected ErrTimestampFuture, got %v", err)
	}
}

func TestVerifyTask_TimestampAtBoundary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	// Exactly at the boundary — should still be valid (within window).
	ts := time.Now().UTC().Add(-4 * time.Minute).Truncate(time.Second)
	task := makeSignedTask(t, priv, "task-001", "ping", map[string]any{}, ts)

	if err := executor.VerifyTask(&task, pub); err != nil {
		t.Errorf("expected nil for timestamp within window, got %v", err)
	}
}

func TestVerifyTask_WrongPublicKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	ts := time.Now().UTC().Truncate(time.Second)
	task := makeSignedTask(t, priv, "task-001", "ping", map[string]any{}, ts)

	err := executor.VerifyTask(&task, wrongPub)
	if !errors.Is(err, executor.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for wrong key, got %v", err)
	}
}

func TestVerifyTask_InvalidBase64Signature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	ts := time.Now().UTC().Truncate(time.Second)
	task := protocol.TaskPayload{
		TaskID:    "task-001",
		TaskType:  "ping",
		Payload:   json.RawMessage(`{}`),
		Timestamp: ts,
		Signature: "not-valid-base64!!!",
	}

	err := executor.VerifyTask(&task, pub)
	if !errors.Is(err, executor.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for bad base64, got %v", err)
	}
}
