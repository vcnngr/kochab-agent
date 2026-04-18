// Package executor runs signed tasks received from the platform.
package executor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

const replayWindow = 5 * time.Minute

// ErrInvalidSignature is returned when the Ed25519 signature does not verify.
var ErrInvalidSignature = errors.New("invalid task signature")

// ErrTimestampExpired is returned when the task timestamp is outside the replay window.
var ErrTimestampExpired = errors.New("task timestamp expired (replay protection)")

// ErrTimestampFuture is returned when the task timestamp is too far in the future.
var ErrTimestampFuture = errors.New("task timestamp too far in the future")

// VerifyTask verifies the Ed25519 signature on a task payload and enforces replay protection.
// Returns nil if the task is valid and safe to execute.
func VerifyTask(task *protocol.TaskPayload, pubKey ed25519.PublicKey) error {
	// Replay protection: reject tasks with timestamps outside ±replayWindow.
	age := time.Since(task.Timestamp)
	if age > replayWindow {
		slog.Warn("task_rejected",
			"task_id", task.TaskID,
			"reason", "timestamp_expired",
			"age_seconds", age.Seconds(),
		)
		return ErrTimestampExpired
	}
	if age < -replayWindow {
		slog.Warn("task_rejected",
			"task_id", task.TaskID,
			"reason", "timestamp_future",
			"age_seconds", age.Seconds(),
		)
		return ErrTimestampFuture
	}

	// Decode the base64 signature.
	sigBytes, err := base64.StdEncoding.DecodeString(task.Signature)
	if err != nil {
		slog.Warn("task_rejected",
			"task_id", task.TaskID,
			"reason", "invalid_signature_encoding",
		)
		return fmt.Errorf("decode signature: %w", ErrInvalidSignature)
	}

	// Reconstruct the signed message using the same format as the platform.
	// Format: "taskID|taskType|hex(sha256(payload))|RFC3339(timestamp)"
	msg := buildSignedMessage(task.TaskID, task.TaskType, []byte(task.Payload), task.Timestamp)

	if !ed25519.Verify(pubKey, msg, sigBytes) {
		slog.Warn("task_rejected",
			"task_id", task.TaskID,
			"reason", "invalid_signature",
		)
		return ErrInvalidSignature
	}

	return nil
}

// buildSignedMessage constructs the canonical message for verification.
// Must match the platform's BuildSignedMessage exactly.
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
