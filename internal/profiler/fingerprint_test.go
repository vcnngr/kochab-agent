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

func TestGenerateFingerprintFrom_ProductUUIDDistinguishes(t *testing.T) {
	// Cloned VMs may share machine-id/hostname/cpu/disk but have distinct
	// DMI product_uuid — fingerprints must differ (deneb incident 2026-06-01).
	base := FingerprintSources{MachineID: "same", Hostname: "same", CPUModel: "same", DiskModel: "same"}
	a := base
	a.ProductUUID = "1364d958-3b29-11eb-9757-200ddc305f00"
	b := base
	b.ProductUUID = "a84f4838-5807-0000-0000-000000000000"
	fa, _ := GenerateFingerprintFrom(a)
	fb, _ := GenerateFingerprintFrom(b)
	if fa == fb {
		t.Fatal("fingerprints must differ when only product_uuid differs")
	}
}
