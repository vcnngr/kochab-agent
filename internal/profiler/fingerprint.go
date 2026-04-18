package profiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strings"
)

// GenerateFingerprint creates a deterministic SHA256 fingerprint from hardware identifiers.
// Input: /etc/machine-id + hostname + CPU model + disk model.
// Fallback: missing sources use empty string (not fatal), but warnings are logged.
func GenerateFingerprint() (string, error) {
	return GenerateFingerprintFrom(defaultSources())
}

// FingerprintSources provides the input data for fingerprint generation.
type FingerprintSources struct {
	MachineID string
	Hostname  string
	CPUModel  string
	DiskModel string
}

// GenerateFingerprintFrom creates a fingerprint from given sources (testable).
// Uses null byte delimiter between fields to prevent collision from field boundary shifts.
// Returns error if all sources are empty (cannot generate a meaningful fingerprint).
func GenerateFingerprintFrom(src FingerprintSources) (string, error) {
	if src.MachineID == "" && src.Hostname == "" && src.CPUModel == "" && src.DiskModel == "" {
		return "", errors.New("all fingerprint sources are empty — cannot generate unique fingerprint")
	}
	h := sha256.New()
	h.Write([]byte(src.MachineID))
	h.Write([]byte{0})
	h.Write([]byte(src.Hostname))
	h.Write([]byte{0})
	h.Write([]byte(src.CPUModel))
	h.Write([]byte{0})
	h.Write([]byte(src.DiskModel))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func defaultSources() FingerprintSources {
	src := FingerprintSources{}

	// /etc/machine-id
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		src.MachineID = strings.TrimSpace(string(data))
	} else {
		slog.Warn("fingerprint: /etc/machine-id not available", "error", err)
	}

	// hostname
	if h, err := os.Hostname(); err == nil {
		src.Hostname = h
	} else {
		slog.Warn("fingerprint: hostname not available", "error", err)
	}

	// CPU model from /proc/cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					src.CPUModel = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	} else {
		slog.Warn("fingerprint: /proc/cpuinfo not available", "error", err)
	}

	// Disk model from /sys/block/*/device/model
	entries, err := os.ReadDir("/sys/block")
	if err == nil {
		for _, e := range entries {
			model, err := os.ReadFile("/sys/block/" + e.Name() + "/device/model")
			if err == nil {
				src.DiskModel = strings.TrimSpace(string(model))
				break
			}
		}
	} else {
		slog.Warn("fingerprint: /sys/block not available", "error", err)
	}

	return src
}
