package rules

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const RuleCodeSSHDisablePasswordAuth = "ssh.disable_password_auth"

// sshConfigDropInGlob is the standard OpenSSH drop-in directory (Debian/Ubuntu
// ship overrides here, e.g. 50-cloud-init.conf). Drop-ins are read AFTER the
// base file in lexical order, matching sshd's Include semantics for the common
// case (the base config's first line is usually `Include sshd_config.d/*.conf`).
const sshConfigDropInGlob = "/etc/ssh/sshd_config.d/*.conf"

func init() {
	// Lockout-sensitive: this preflight gates a fix that disables SSH password
	// auth. If the key-access probe can't be verified, the fix must be SUPPRESSED
	// (fail-closed), never shown — showing it on an unverifiable probe is a real
	// lockout risk.
	RegisterLockoutSensitiveRuleWithPreflight(RuleCodeSSHDisablePasswordAuth, checkSSHDisablePasswordAuth, preflightSSHDisablePasswordAuth)
}

// sshLockoutReason is the guidance shown when disabling password auth would
// remove the ONLY working access method (AC-4). Surfaced as preflight_reason.
const sshLockoutReason = "Prima configura l'accesso con chiave SSH: nessuna chiave autorizzata rilevata, disabilitare la password ti escluderebbe dal server."

// Filesystem roots for the SSH lockout preflight. Package vars (not consts) so
// tests can point them at a temp fixture tree without touching the real host.
// Production values are the canonical Linux paths.
var (
	sshdConfigPath = "/etc/ssh/sshd_config"
	etcPasswdPath  = "/etc/passwd"
	rootHomeDir    = "/root"
)

// preflightSSHDisablePasswordAuth is the READ-ONLY guardrail for the
// "disable password authentication" fix (AC-4, FR16). The fix is dangerous when
// password auth is the ONLY active access method: with no authorized SSH keys
// in place, applying it would lock the operator out of the server.
//
// Decision:
//   - sshd_config absent          → PreflightExitSkip (rule isn't really
//     applicable; matches seed 007 `test -f ... || exit 2`).
//   - at least one authorized key → PreflightExitPass (key access survives).
//   - no authorized key anywhere  → PreflightExitBlock with lockout guidance.
//
// This function ONLY reads files (sshd_config, authorized_keys, /etc/passwd).
// It NEVER mutates the host and NEVER applies the fix.
func preflightSSHDisablePasswordAuth(_ context.Context) (int, string, error) {
	if !fileExists(sshdConfigPath) {
		return PreflightExitSkip, "", nil
	}
	if sshHasAnyAuthorizedKey() {
		return PreflightExitPass, "", nil
	}
	return PreflightExitBlock, sshLockoutReason, nil
}

// sshHasAnyAuthorizedKey reports whether ANY accessible user has at least one
// non-empty, non-comment line in an authorized_keys file. Read-only.
//
// It inspects the home directories of users with a real login shell parsed from
// /etc/passwd (covering root + admin accounts), checking the standard
// ~/.ssh/authorized_keys and ~/.ssh/authorized_keys2 locations.
func sshHasAnyAuthorizedKey() bool {
	for _, home := range sshCandidateHomes() {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			if authorizedKeysFileHasKey(filepath.Join(home, ".ssh", name)) {
				return true
			}
		}
	}
	return false
}

// sshCandidateHomes returns home directories worth checking for authorized_keys:
// every /etc/passwd account whose shell is a genuine interactive login shell
// (per isLoginShell). root is NOT special-cased — its keys count ONLY if root's
// own passwd shell is interactive (BUG 3a: a key under /root/.ssh while root's
// shell is nologin/false is NOT a usable access path and must not pass the
// preflight). The rootHomeDir override is substituted for root's home so tests
// can point it at a fixture tree; if /etc/passwd is unreadable or root has no
// interactive entry, root keys do NOT count (fail closed).
func sshCandidateHomes() []string {
	seen := map[string]bool{}
	var homes []string
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		homes = append(homes, h)
	}

	content, present, err := readFile(etcPasswdPath)
	if err != nil || !present {
		return homes
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		name, home, shell := fields[0], fields[5], fields[6]
		if !isLoginShell(shell) {
			continue
		}
		// Use the rootHomeDir override for root so the canonical /root path (or a
		// test fixture) is inspected rather than the literal passwd home field.
		if name == "root" {
			home = rootHomeDir
		}
		add(home)
	}
	return homes
}

// interactiveShells is the allowlist of genuine interactive login shells that
// grant usable admin SSH access. We allowlist rather than denylist: an unknown
// or uncertain shell must NOT count as usable (fail closed) — showing the
// password-disable fix because of a misjudged shell carries lockout risk.
var interactiveShells = map[string]bool{
	"bash": true,
	"sh":   true,
	"zsh":  true,
	"fish": true,
	"dash": true,
	"ksh":  true,
	"tcsh": true,
	"csh":  true,
	"ash":  true,
	"mksh": true,
}

// isLoginShell reports whether the given login shell grants interactive SSH
// access usable for administration. Restricted/non-login shells (nologin,
// false, git-shell, rbash, scponly, …) and the empty shell are rejected.
//
// Conservative by design: only shells on the interactiveShells allowlist count.
// Anything unrecognised returns false (fail closed), since treating an uncertain
// shell as usable could wrongly show the lockout-risky fix.
func isLoginShell(shell string) bool {
	shell = strings.TrimSpace(shell)
	if shell == "" {
		return false
	}
	return interactiveShells[filepath.Base(shell)]
}

// sshKeyTypes is the set of recognised SSH public key type tokens. A valid
// authorized_keys entry must carry one of these as a field on the line. Source:
// OpenSSH key algorithm names (sshd_config(5), ssh-keygen(1)).
var sshKeyTypes = map[string]bool{
	"ssh-rsa":                            true,
	"ssh-ed25519":                        true,
	"ssh-dss":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// authorizedKeysFileHasKey reports whether path exists and contains at least one
// line that looks like a genuine SSH public key. Read-only.
//
// authorized_keys lines may carry leading options before the key type (e.g.
// `no-pty,from="10.0.0.0/8" ssh-ed25519 AAAA... user@host`), so we scan EVERY
// whitespace-separated field for a recognised key-type token rather than only
// the first. Comment/blank lines and lines with no recognisable key type do NOT
// count — a permissive "any non-comment line is a key" rule would wrongly show
// the lockout-risky fix on a garbage/placeholder file.
func authorizedKeysFileHasKey(path string) bool {
	content, present, err := readFile(path)
	if err != nil || !present {
		return false
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if lineHasSSHKeyType(line) {
			return true
		}
	}
	return false
}

// sshKeyBlobRe matches a base64-encoded SSH key blob (RFC 4648 alphabet with
// optional '=' padding). The real blob is always well over 60 bytes; we require
// a conservative minimum length so a stray short token can't masquerade as one.
var sshKeyBlobRe = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)

// minSSHKeyBlobLen is the smallest plausible base64 key-blob length. Even the
// shortest real key (ed25519) encodes to ~68 base64 chars; 40 leaves headroom
// while still rejecting truncated/garbage tokens.
const minSSHKeyBlobLen = 40

// lineHasSSHKeyType reports whether the line contains a recognised SSH public
// key type token IMMEDIATELY FOLLOWED by a non-empty, base64-ish key blob field
// (BUG 3b). A bare key-type token with no blob (e.g. just "ssh-ed25519"), or a
// type followed by a garbage/too-short field, is a truncated/malformed entry and
// must NOT count as a usable key — counting it would risk showing the
// lockout-prone fix on a host with no real key.
func lineHasSSHKeyType(line string) bool {
	fields := strings.Fields(line)
	for i, field := range fields {
		if !sshKeyTypes[field] {
			continue
		}
		// The key blob must be the very next field (authorized_keys format:
		// [options] <type> <base64-blob> [comment]).
		if i+1 >= len(fields) {
			continue
		}
		blob := fields[i+1]
		if len(blob) >= minSSHKeyBlobLen && sshKeyBlobRe.MatchString(blob) {
			return true
		}
	}
	return false
}

// checkSSHDisablePasswordAuth reads /etc/ssh/sshd_config plus any *.conf files
// in /etc/ssh/sshd_config.d/ and reports passed=true iff the effective
// PasswordAuthentication directive (last one wins across base + drop-ins) is
// "no". Returns skipped if sshd_config is absent.
//
// Story 3.2: attaches exposure signals (bind_scope/exposed_public) covering
// EVERY configured Port, so the platform can compute context-aware severity.
func checkSSHDisablePasswordAuth(ctx context.Context) (bool, map[string]any, error) {
	src, present, err := readFile("/etc/ssh/sshd_config")
	if err != nil {
		return false, nil, err
	}
	if !present {
		return true, map[string]any{"skipped_reason": "sshd_config missing"}, nil
	}

	// Concatenate base + drop-ins in sshd's effective order (base first, then
	// drop-ins lexically). Last PasswordAuthentication directive wins.
	sources := []string{src}
	sources = append(sources, sshDropInContents()...)

	final := "" // "yes" / "no" / ""
	for _, content := range sources {
		for _, raw := range strings.Split(content, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "passwordauthentication ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					final = strings.ToLower(fields[1])
				}
			}
		}
	}

	// Probe EVERY configured port; public exposure on ANY of them wins (a server
	// reachable on a public port is exposed even if other ports are private).
	ports := sshPorts(sources)
	scope := bindScopeUnknown
	var addrs []string
	for _, p := range ports {
		s, a := listenScope(ctx, p)
		addrs = append(addrs, a...)
		scope = mergeScope(scope, s)
	}

	return final == "no", map[string]any{
		"effective_setting": final,
		"config_path":       "/etc/ssh/sshd_config",
		"ssh_ports":         ports,
		"bind_scope":        scope,
		"listen_addrs":      addrs,
		"exposed_public":    scope == bindScopePublic,
	}, nil
}

// sshDropInContents returns the contents of every *.conf in the drop-in dir,
// sorted lexically. Best-effort: unreadable dir/files are skipped.
func sshDropInContents() []string {
	matches, err := filepath.Glob(sshConfigDropInGlob)
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)
	var out []string
	for _, m := range matches {
		if data, rerr := os.ReadFile(m); rerr == nil {
			out = append(out, string(data))
		}
	}
	return out
}

// sshPorts returns all configured sshd Port directives across the given config
// sources, defaulting to [22] when none are set. OpenSSH allows multiple Port
// directives (the daemon listens on all of them), so we must probe each.
func sshPorts(sources []string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, content := range sources {
		for _, raw := range strings.Split(content, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "port ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p <= 65535 && !seen[p] {
						seen[p] = true
						ports = append(ports, p)
					}
				}
			}
		}
	}
	if len(ports) == 0 {
		return []int{22}
	}
	return ports
}

// mergeScope combines two bind scopes; public dominates, then private, then unknown.
func mergeScope(a, b string) string {
	if a == bindScopePublic || b == bindScopePublic {
		return bindScopePublic
	}
	if a == bindScopePrivate || b == bindScopePrivate {
		return bindScopePrivate
	}
	return bindScopeUnknown
}
