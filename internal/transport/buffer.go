package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// ReportFunc is the signature used by RunLoop and RetransmitBuffered to
// deliver a TaskResult to the platform.
type ReportFunc func(ctx context.Context, result *protocol.TaskResult) error

// RetransmitBuffered iterates buffered results in chronological order and
// delivers each via reportFn. Successful entries are removed from the buffer.
// Failures are tolerated: client errors (4xx) drop the entry; transient errors
// keep it in the buffer for the next attempt and stop the iteration so the
// agent can enter the poll loop without blocking.
func RetransmitBuffered(ctx context.Context, buf *ResultBuffer, reportFn ReportFunc) {
	if buf == nil || reportFn == nil {
		return
	}
	entries, err := buf.ReadAll()
	if err != nil {
		slog.Warn("buffer_retransmit_readall_failed", "error", err)
		return
	}
	if len(entries) == 0 {
		return
	}
	slog.Info("buffer_retransmit_start", "entries", len(entries))

	delivered := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			slog.Info("buffer_retransmit_cancelled", "delivered", delivered, "remaining", len(entries)-delivered)
			return
		}
		if err := reportFn(ctx, entry.Result); err != nil {
			if IsClientError(err) {
				slog.Warn("buffer_retransmit_client_error_drop",
					"task_id", entry.Result.TaskID,
					"filename", entry.Filename,
					"error", err,
				)
				if rmErr := buf.Remove(entry.Filename); rmErr != nil {
					slog.Warn("buffer_retransmit_remove_failed", "filename", entry.Filename, "error", rmErr)
				}
				continue
			}
			slog.Warn("buffer_retransmit_transient_skip",
				"task_id", entry.Result.TaskID,
				"filename", entry.Filename,
				"error", err,
			)
			// Stop here: connection still bad, retry on next agent start.
			return
		}
		if err := buf.Remove(entry.Filename); err != nil {
			slog.Warn("buffer_retransmit_remove_failed", "filename", entry.Filename, "error", err)
			continue
		}
		delivered++
	}
	slog.Info("buffer_retransmit_done", "delivered", delivered)
}

const defaultBufferMaxFiles = 1000

// ResultBuffer persists TaskResults on disk when the platform is unreachable.
// Files are written atomically (tmp + fsync + rename + dir-fsync) under dir,
// named by UnixNano timestamp + monotonic seq so lexicographic order matches
// chronological order even when two writes share the same nanosecond.
type ResultBuffer struct {
	dir      string
	maxFiles int
	mu       sync.Mutex
	seq      uint64 // monotonic per-buffer counter to disambiguate same-nano writes
}

// BufferedEntry pairs the on-disk filename with the decoded result.
type BufferedEntry struct {
	Filename string
	Result   *protocol.TaskResult
}

// NewResultBuffer creates the buffer dir (0700) if missing and returns a buffer
// with the given file cap. maxFiles <= 0 falls back to defaultBufferMaxFiles.
func NewResultBuffer(dir string, maxFiles int) (*ResultBuffer, error) {
	if dir == "" {
		return nil, fmt.Errorf("buffer dir is empty")
	}
	if maxFiles <= 0 {
		maxFiles = defaultBufferMaxFiles
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("buffer mkdir %s: %w", dir, err)
	}
	// Sweep stale .tmp_* leftovers from prior crashes during write+rename.
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if strings.HasPrefix(e.Name(), ".tmp_") {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	return &ResultBuffer{dir: dir, maxFiles: maxFiles}, nil
}

// Write persists the result atomically. Returns nil (silent drop with warn log)
// if the buffer is full per AC-2.
func (b *ResultBuffer) Write(result *protocol.TaskResult) error {
	if result == nil {
		return fmt.Errorf("buffer write: nil result")
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	count, err := b.countLocked()
	if err != nil {
		return err
	}
	if count >= b.maxFiles {
		slog.Warn("buffer_full_drop",
			"task_id", result.TaskID,
			"buffer_count", count,
			"max_files", b.maxFiles,
		)
		return nil
	}

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("buffer marshal %s: %w", result.TaskID, err)
	}

	nano := time.Now().UnixNano()
	b.seq++
	// Pad nano to 19 digits and seq to 6 digits so lex order = chrono order
	// even when many writes share the same nanosecond on coarse clocks.
	finalName := fmt.Sprintf("%019d_%06d.json", nano, b.seq)
	tmpName := fmt.Sprintf(".tmp_%019d_%06d.json", nano, b.seq)
	finalPath := filepath.Join(b.dir, finalName)
	tmpPath := filepath.Join(b.dir, tmpName)

	// Crash-durable write: O_EXCL refuses to clobber stale tmp; explicit fsync
	// on the file before rename and on the parent dir after rename guarantees
	// metadata is on disk before we ack to caller.
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("buffer open tmp %s: %w", tmpPath, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("buffer write tmp %s: %w", tmpPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("buffer fsync tmp %s: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("buffer close tmp %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("buffer rename %s: %w", finalPath, err)
	}
	// fsync parent dir so the rename itself is durable across crashes.
	if dirF, err := os.Open(b.dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	slog.Info("result_buffered",
		"task_id", result.TaskID,
		"path", finalPath,
	)
	return nil
}

// ReadAll returns all buffered entries sorted chronologically.
// Skips tmp files and unreadable/corrupt entries (logging a warn).
func (b *ResultBuffer) ReadAll() ([]BufferedEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return nil, fmt.Errorf("buffer readdir %s: %w", b.dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".tmp_") {
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]BufferedEntry, 0, len(names))
	for _, name := range names {
		path := filepath.Join(b.dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("buffer_entry_unreadable", "path", path, "error", err)
			continue
		}
		var result protocol.TaskResult
		if err := json.Unmarshal(data, &result); err != nil {
			slog.Warn("buffer_entry_corrupt", "path", path, "error", err)
			// Quarantine the corrupt file under .bad/ so it stops counting
			// toward the cap. ReadDir filters subdirs, so .bad/ contents are
			// never re-enumerated. Forensic copy preserved for debugging.
			badDir := filepath.Join(b.dir, ".bad")
			if mkErr := os.MkdirAll(badDir, 0o700); mkErr == nil {
				target := filepath.Join(badDir, name)
				if rnErr := os.Rename(path, target); rnErr == nil {
					slog.Info("buffer_corrupt_quarantined", "from", path, "to", target)
				} else {
					slog.Warn("buffer_corrupt_quarantine_failed", "path", path, "error", rnErr)
				}
			} else {
				slog.Warn("buffer_corrupt_quarantine_mkdir_failed", "path", badDir, "error", mkErr)
			}
			continue
		}
		out = append(out, BufferedEntry{Filename: name, Result: &result})
	}
	return out, nil
}

// Remove deletes a single buffered entry by filename (no path traversal).
func (b *ResultBuffer) Remove(filename string) error {
	if filename == "" || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return fmt.Errorf("buffer remove: invalid filename %q", filename)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	path := filepath.Join(b.dir, filename)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("buffer remove %s: %w", path, err)
	}
	return nil
}

// Count returns the number of buffered (non-tmp) result files.
func (b *ResultBuffer) Count() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.countLocked()
}

func (b *ResultBuffer) countLocked() (int, error) {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return 0, fmt.Errorf("buffer count readdir %s: %w", b.dir, err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".tmp_") || !strings.HasSuffix(name, ".json") {
			continue
		}
		n++
	}
	return n, nil
}
