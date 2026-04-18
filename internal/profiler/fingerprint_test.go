package profiler

import (
	"testing"
)

func TestGenerateFingerprintFrom_Deterministic(t *testing.T) {
	src := FingerprintSources{
		MachineID: "abc123",
		Hostname:  "vortex.blackhole.global",
		CPUModel:  "Intel Xeon E5-2680",
		DiskModel: "SAMSUNG SSD 860",
	}

	fp1, err := GenerateFingerprintFrom(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fp2, err := GenerateFingerprintFrom(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fp1 != fp2 {
		t.Fatal("fingerprint should be deterministic")
	}

	if len(fp1) != 64 { // SHA256 hex = 64 chars
		t.Fatalf("expected 64 char hex, got %d", len(fp1))
	}
}

func TestGenerateFingerprintFrom_DifferentInputs(t *testing.T) {
	fp1, _ := GenerateFingerprintFrom(FingerprintSources{MachineID: "aaa"})
	fp2, _ := GenerateFingerprintFrom(FingerprintSources{MachineID: "bbb"})

	if fp1 == fp2 {
		t.Fatal("different inputs should produce different fingerprints")
	}
}

func TestGenerateFingerprintFrom_AllEmpty_ReturnsError(t *testing.T) {
	_, err := GenerateFingerprintFrom(FingerprintSources{})
	if err == nil {
		t.Fatal("expected error for all-empty sources")
	}
}

func TestGenerateFingerprintFrom_PartialSources(t *testing.T) {
	// Only one source available — should produce a valid fingerprint
	fp, err := GenerateFingerprintFrom(FingerprintSources{Hostname: "vortex"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("expected 64 char hex, got %d", len(fp))
	}
}

func TestGenerateFingerprintFrom_DelimiterPreventsCollision(t *testing.T) {
	// "abc" + "def" vs "ab" + "cdef" must produce different fingerprints
	fp1, _ := GenerateFingerprintFrom(FingerprintSources{MachineID: "abc", Hostname: "def"})
	fp2, _ := GenerateFingerprintFrom(FingerprintSources{MachineID: "ab", Hostname: "cdef"})
	if fp1 == fp2 {
		t.Fatal("delimiter should prevent field boundary collision")
	}
}
