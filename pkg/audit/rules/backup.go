package rules

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const RuleCodeBackupConfigPresent = "backup.config_present"

func init() {
	RegisterRule(RuleCodeBackupConfigPresent, checkBackupConfigPresent)
}

// checkBackupConfigPresent looks for evidence of a configured backup tool.
// Heuristics — presence of any of:
//   - config dir/files: /etc/restic, /etc/borg*, /etc/borgmatic*, /etc/rsnapshot.conf, /etc/duplicity, /etc/bacula
//   - installed binaries: restic, borg, borgmatic, duplicity, rsnapshot, bareos-fd
//   - systemd timer/service unit with name including backup/borg/restic/bacula/bareos
func checkBackupConfigPresent(ctx context.Context) (bool, map[string]any, error) {
	_ = ctx

	// Config files / dirs.
	for _, path := range []string{
		"/etc/restic",
		"/etc/rsnapshot.conf",
		"/etc/duplicity",
		"/etc/bacula",
	} {
		if fileExists(path) {
			return true, map[string]any{"detected_via": "config", "path": path}, nil
		}
	}
	// Glob-style for borg*.
	for _, pattern := range []string{"/etc/borg*", "/etc/borgmatic*"} {
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return true, map[string]any{"detected_via": "config", "path": matches[0]}, nil
		}
	}

	// Installed binaries.
	for _, bin := range []string{"restic", "borg", "borgmatic", "duplicity", "rsnapshot", "bareos-fd"} {
		if _, err := exec.LookPath(bin); err == nil {
			return true, map[string]any{"detected_via": "binary", "binary": bin}, nil
		}
	}

	// systemd units.
	out, _, err := cmdOutput(ctx, "systemctl", "list-unit-files", "--type=service", "--type=timer", "--no-pager", "--no-legend")
	if err == nil {
		for _, raw := range strings.Split(out, "\n") {
			low := strings.ToLower(strings.TrimSpace(raw))
			if low == "" {
				continue
			}
			for _, needle := range []string{"backup", "borg", "borgmatic", "restic", "bacula", "bareos"} {
				if strings.Contains(low, needle) {
					return true, map[string]any{"detected_via": "systemd", "match": strings.Fields(raw)[0]}, nil
				}
			}
		}
	}

	// /var/backups heuristic — Debian-friendly, but only counts if it has
	// recent contents (filesystem stamps differ; just check non-empty dir).
	if d, err := os.ReadDir("/var/backups"); err == nil && len(d) > 0 {
		return true, map[string]any{"detected_via": "var_backups", "entries": len(d)}, nil
	}

	return false, map[string]any{
		"hint": "Nessuno strumento di backup riconosciuto trovato. Installa restic / borg / duplicity / rsnapshot.",
	}, nil
}
