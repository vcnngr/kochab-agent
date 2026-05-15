package rules

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

const RuleCodePermissionsShadowPasswd = "permissions.shadow_passwd"

func init() {
	RegisterRule(RuleCodePermissionsShadowPasswd, checkPermissionsShadowPasswd)
}

type permCheck struct {
	Path        string
	WantModes   []os.FileMode // accept any of these (Debian historically ships either 0640 or 0600 for shadow)
	WantUID     uint32
	WantGIDs    []uint32 // accept any of these (root or shadow group)
}

// checkPermissionsShadowPasswd verifies ownership and modes on the four files
// that, together, gate the integrity of the local user database. Failing any
// one of them yields a single finding citing every misconfig.
func checkPermissionsShadowPasswd(ctx context.Context) (bool, map[string]any, error) {
	_ = ctx

	rootUID, _, shadowGID, err := resolveSystemIDs()
	if err != nil {
		return false, nil, err
	}

	checks := []permCheck{
		{Path: "/etc/passwd", WantModes: []os.FileMode{0644}, WantUID: rootUID, WantGIDs: []uint32{0}},
		{Path: "/etc/group", WantModes: []os.FileMode{0644}, WantUID: rootUID, WantGIDs: []uint32{0}},
		{Path: "/etc/shadow", WantModes: []os.FileMode{0640, 0600}, WantUID: rootUID, WantGIDs: []uint32{shadowGID, 0}},
		{Path: "/etc/gshadow", WantModes: []os.FileMode{0640, 0600}, WantUID: rootUID, WantGIDs: []uint32{shadowGID, 0}},
	}

	violations := []map[string]any{}
	for _, c := range checks {
		fi, err := os.Stat(c.Path)
		if err != nil {
			if os.IsNotExist(err) {
				violations = append(violations, map[string]any{"path": c.Path, "issue": "missing"})
				continue
			}
			return false, nil, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return false, nil, fmt.Errorf("stat_t not available for %s", c.Path)
		}
		mode := fi.Mode().Perm()
		if !modeAllowed(mode, c.WantModes) {
			violations = append(violations, map[string]any{
				"path":      c.Path,
				"got_mode":  fmt.Sprintf("%04o", mode),
				"want_mode": modesString(c.WantModes),
			})
			continue
		}
		if st.Uid != c.WantUID {
			violations = append(violations, map[string]any{
				"path":     c.Path,
				"got_uid":  st.Uid,
				"want_uid": c.WantUID,
			})
			continue
		}
		if !uidAllowed(st.Gid, c.WantGIDs) {
			violations = append(violations, map[string]any{
				"path":     c.Path,
				"got_gid":  st.Gid,
				"want_gid": c.WantGIDs,
			})
		}
	}

	if len(violations) == 0 {
		return true, map[string]any{}, nil
	}
	return false, map[string]any{"violations": violations}, nil
}

func modeAllowed(got os.FileMode, want []os.FileMode) bool {
	for _, w := range want {
		if got == w {
			return true
		}
	}
	return false
}

func uidAllowed(got uint32, want []uint32) bool {
	for _, w := range want {
		if got == w {
			return true
		}
	}
	return false
}

func modesString(want []os.FileMode) string {
	parts := make([]string, 0, len(want))
	for _, w := range want {
		parts = append(parts, fmt.Sprintf("%04o", w))
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "|"
		}
		out += p
	}
	return out
}

// resolveSystemIDs returns uid(root), gid(root), gid(shadow). Used by
// the permissions rule. Reading /etc/passwd + /etc/group directly avoids
// linking glibc through cgo.
func resolveSystemIDs() (rootUID, rootGID, shadowGID uint32, err error) {
	rootUID = 0
	rootGID = 0
	// Locate shadow group ID.
	body, ok, rerr := readFile("/etc/group")
	if rerr != nil {
		return 0, 0, 0, rerr
	}
	if !ok {
		return rootUID, rootGID, 42, nil // historical Debian shadow GID
	}
	for _, raw := range splitNonEmpty(body) {
		if len(raw) > 7 && raw[:7] == "shadow:" {
			fields := splitColons(raw)
			if len(fields) >= 3 {
				var gid uint32
				_, _ = fmt.Sscanf(fields[2], "%d", &gid)
				if gid > 0 {
					shadowGID = gid
				}
			}
		}
	}
	if shadowGID == 0 {
		shadowGID = 42
	}
	return rootUID, rootGID, shadowGID, nil
}

func splitNonEmpty(s string) []string {
	out := []string{}
	cur := ""
	for _, ch := range s {
		if ch == '\n' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(ch)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func splitColons(s string) []string {
	out := []string{}
	cur := ""
	for _, ch := range s {
		if ch == ':' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(ch)
	}
	out = append(out, cur)
	return out
}
