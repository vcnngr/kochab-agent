package transport_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kochab-ai/kochab-agent/internal/transport"
	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

func newBuffer(t *testing.T, max int) (*transport.ResultBuffer, string) {
	t.Helper()
	dir := t.TempDir()
	bufDir := filepath.Join(dir, "buffer")
	buf, err := transport.NewResultBuffer(bufDir, max)
	if err != nil {
		t.Fatalf("NewResultBuffer: %v", err)
	}
	return buf, bufDir
}

func TestNewResultBuffer_CreatesDir(t *testing.T) {
	dir := t.TempDir()
	bufDir := filepath.Join(dir, "nested", "buffer")
	if _, err := transport.NewResultBuffer(bufDir, 0); err != nil {
		t.Fatalf("create: %v", err)
	}
	info, err := os.Stat(bufDir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected dir")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("expected perm 0700, got %o", perm)
	}
}

func TestResultBuffer_WriteReadRemove(t *testing.T) {
	buf, dir := newBuffer(t, 10)

	r := &protocol.TaskResult{TaskID: "t1", Status: "completed", Result: json.RawMessage(`{"ok":true}`)}
	if err := buf.Write(r); err != nil {
		t.Fatalf("write: %v", err)
	}

	entries, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Result.TaskID != "t1" {
		t.Fatalf("expected t1, got %s", entries[0].Result.TaskID)
	}

	// File perm 0600
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		info, _ := f.Info()
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected file perm 0600, got %o for %s", info.Mode().Perm(), f.Name())
		}
	}

	if err := buf.Remove(entries[0].Filename); err != nil {
		t.Fatalf("remove: %v", err)
	}
	entries, _ = buf.ReadAll()
	if len(entries) != 0 {
		t.Fatalf("expected 0 after remove, got %d", len(entries))
	}
}

func TestResultBuffer_ChronologicalOrder(t *testing.T) {
	buf, _ := newBuffer(t, 10)
	for _, id := range []string{"a", "b", "c"} {
		if err := buf.Write(&protocol.TaskResult{TaskID: id, Status: "completed"}); err != nil {
			t.Fatalf("write %s: %v", id, err)
		}
	}
	entries, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	got := []string{entries[0].Result.TaskID, entries[1].Result.TaskID, entries[2].Result.TaskID}
	want := []string{"a", "b", "c"}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("order mismatch at %d: got %v, want %v", i, got, want)
		}
	}
}

func TestResultBuffer_CapDropsSilently(t *testing.T) {
	buf, _ := newBuffer(t, 2)
	for _, id := range []string{"a", "b", "c"} {
		if err := buf.Write(&protocol.TaskResult{TaskID: id, Status: "completed"}); err != nil {
			t.Fatalf("write %s: %v", id, err)
		}
	}
	count, _ := buf.Count()
	if count != 2 {
		t.Fatalf("expected 2 (cap), got %d", count)
	}
}

func TestResultBuffer_ConcurrentWrites(t *testing.T) {
	buf, _ := newBuffer(t, 100)
	var wg sync.WaitGroup
	const n = 50
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := &protocol.TaskResult{TaskID: "task", Status: "completed"}
			if err := buf.Write(r); err != nil {
				t.Errorf("write %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	// Strong assertion: every concurrent Write must produce a distinct file.
	// Earlier the test only checked count > 0, which silently masked filename
	// collisions on coarse-clock platforms (review finding M1).
	count, err := buf.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != n {
		t.Fatalf("expected %d entries (no collision loss), got %d", n, count)
	}
}

func TestResultBuffer_TmpFilesIgnored(t *testing.T) {
	buf, dir := newBuffer(t, 10)
	// Inject a stray .tmp_ file
	if err := os.WriteFile(filepath.Join(dir, ".tmp_999.json"), []byte("garbage"), 0o600); err != nil {
		t.Fatalf("seed tmp: %v", err)
	}
	if err := buf.Write(&protocol.TaskResult{TaskID: "real", Status: "completed"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, _ := buf.ReadAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 (tmp ignored), got %d", len(entries))
	}
}

func TestResultBuffer_AtomicWriteNoLeftoverTmp(t *testing.T) {
	buf, dir := newBuffer(t, 10)
	if err := buf.Write(&protocol.TaskResult{TaskID: "x", Status: "completed"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".tmp_") {
			t.Fatalf("tmp leftover: %s", f.Name())
		}
	}
}

func TestResultBuffer_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	bufDir := filepath.Join(dir, "buffer")
	buf1, err := transport.NewResultBuffer(bufDir, 10)
	if err != nil {
		t.Fatalf("create1: %v", err)
	}
	if err := buf1.Write(&protocol.TaskResult{TaskID: "persist", Status: "completed"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Simulate restart: new buffer instance over same dir
	buf2, err := transport.NewResultBuffer(bufDir, 10)
	if err != nil {
		t.Fatalf("create2: %v", err)
	}
	entries, _ := buf2.ReadAll()
	if len(entries) != 1 || entries[0].Result.TaskID != "persist" {
		t.Fatalf("expected persisted entry, got %+v", entries)
	}
}

func TestResultBuffer_RemoveRejectsTraversal(t *testing.T) {
	buf, _ := newBuffer(t, 10)
	if err := buf.Remove("../etc/passwd"); err == nil {
		t.Fatalf("expected reject path traversal")
	}
}

func TestResultBuffer_NilResult(t *testing.T) {
	buf, _ := newBuffer(t, 10)
	if err := buf.Write(nil); err == nil {
		t.Fatalf("expected error on nil result")
	}
}

func TestRetransmitBuffered_DeliversAndRemoves(t *testing.T) {
	buf, _ := newBuffer(t, 10)
	for _, id := range []string{"a", "b", "c"} {
		_ = buf.Write(&protocol.TaskResult{TaskID: id, Status: "completed"})
	}

	var delivered []string
	report := func(_ context.Context, r *protocol.TaskResult) error {
		delivered = append(delivered, r.TaskID)
		return nil
	}

	transport.RetransmitBuffered(context.Background(), buf, report)
	if got := strings.Join(delivered, ","); got != "a,b,c" {
		t.Fatalf("expected a,b,c order, got %s", got)
	}
	count, _ := buf.Count()
	if count != 0 {
		t.Fatalf("expected buffer empty after retransmit, got %d", count)
	}
}

func TestRetransmitBuffered_TransientKeepsEntries(t *testing.T) {
	// Contract: on transient failure, NO entries are lost — they must remain
	// in the buffer for a subsequent attempt. We deliberately do not assert
	// the early-stop behaviour (calls == 1) because that is an implementation
	// detail; future versions may continue/retry without breaking the contract.
	buf, _ := newBuffer(t, 10)
	_ = buf.Write(&protocol.TaskResult{TaskID: "first", Status: "completed"})
	_ = buf.Write(&protocol.TaskResult{TaskID: "second", Status: "completed"})

	report := func(_ context.Context, r *protocol.TaskResult) error {
		return errors.New("network down")
	}
	transport.RetransmitBuffered(context.Background(), buf, report)

	count, _ := buf.Count()
	if count != 2 {
		t.Fatalf("transient failure must preserve all entries, got %d", count)
	}
}

func TestRetransmitBuffered_RecoversAfterFailure(t *testing.T) {
	buf, _ := newBuffer(t, 10)
	_ = buf.Write(&protocol.TaskResult{TaskID: "x", Status: "completed"})

	// First pass fails
	transport.RetransmitBuffered(context.Background(), buf, func(_ context.Context, _ *protocol.TaskResult) error {
		return errors.New("offline")
	})
	if c, _ := buf.Count(); c != 1 {
		t.Fatalf("entry should remain after failure, got %d", c)
	}

	// Second pass succeeds
	transport.RetransmitBuffered(context.Background(), buf, func(_ context.Context, _ *protocol.TaskResult) error {
		return nil
	})
	if c, _ := buf.Count(); c != 0 {
		t.Fatalf("entry should be drained, got %d", c)
	}
}

func TestRetransmitBuffered_EmptyBufferNoop(t *testing.T) {
	buf, _ := newBuffer(t, 10)
	called := false
	transport.RetransmitBuffered(context.Background(), buf, func(_ context.Context, _ *protocol.TaskResult) error {
		called = true
		return nil
	})
	if called {
		t.Fatalf("expected no calls on empty buffer")
	}
}

func TestResultBuffer_CorruptEntrySkipped(t *testing.T) {
	buf, dir := newBuffer(t, 10)
	if err := buf.Write(&protocol.TaskResult{TaskID: "good", Status: "completed"}); err != nil {
		t.Fatalf("write good: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	entries, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(entries) != 1 || entries[0].Result.TaskID != "good" {
		t.Fatalf("expected only 'good', got %+v", entries)
	}
}
