package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Story 4.1 AC-4: the ssh.disable_password_auth preflight must detect the
// lockout risk. If no authorized SSH key exists for any accessible user,
// disabling password auth would lock the operator out → exit 1 (blocked).
// If at least one authorized key exists → exit 0 (pass).

// Realistic-length base64 key blobs (BUG 3b requires a key-type token followed
// by a real blob ≥ minSSHKeyBlobLen chars; the truncated stubs used before would
// now be rejected as malformed). Lengths here mirror real ed25519/rsa/ecdsa keys.
const (
	testEd25519Blob = "AAAAC3NzaC1lZDI1NTE5AAAAIE3aR0YzvTn6Qm2dZ4kqX1uJ9wL0pPbV7sN8cH5fG6m"
	testRSABlob     = "AAAAB3NzaC1yc2EAAAADAQABAAABgQDQ7Xj2kFv8mN3pR1tYzL9bWcQ4eH6sJ0aU5dK2nP7iVxBgMoC3rT8uYwE1qS"
	testECDSABlob   = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPx4tQzVn6dWkL2mJ9eR0aH5"
)

// sshFixture builds an isolated filesystem root and points the SSH preflight
// path vars at it for the duration of the test.
type sshFixture struct {
	root   string
	passwd string // contents for /etc/passwd (empty => no file)
}

func (f sshFixture) apply(t *testing.T) {
	t.Helper()
	prevSSHD, prevPasswd, prevRoot := sshdConfigPath, etcPasswdPath, rootHomeDir
	t.Cleanup(func() {
		sshdConfigPath, etcPasswdPath, rootHomeDir = prevSSHD, prevPasswd, prevRoot
	})

	sshdConfigPath = filepath.Join(f.root, "etc", "ssh", "sshd_config")
	etcPasswdPath = filepath.Join(f.root, "etc", "passwd")
	rootHomeDir = filepath.Join(f.root, "root")

	if f.passwd != "" {
		mustWrite(t, etcPasswdPath, f.passwd)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestPreflightSSH_Skip_WhenNoSSHDConfig(t *testing.T) {
	root := t.TempDir()
	sshFixture{root: root}.apply(t)
	// Deliberately do NOT create sshd_config.

	code, reason, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitSkip {
		t.Errorf("exit = %d want %d (skip)", code, PreflightExitSkip)
	}
	if reason != "" {
		t.Errorf("reason = %q want empty on skip", reason)
	}
}

func TestPreflightSSH_Pass_WhenRootHasAuthorizedKey(t *testing.T) {
	root := t.TempDir()
	fixture := sshFixture{
		root:   root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/bin/bash\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		"# my key\nssh-ed25519 "+testEd25519Blob+" user@host\n")

	code, reason, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitPass {
		t.Errorf("exit = %d want %d (pass)", code, PreflightExitPass)
	}
	if reason != "" {
		t.Errorf("reason = %q want empty on pass", reason)
	}
}

func TestPreflightSSH_Block_WhenNoAuthorizedKeyAnywhere(t *testing.T) {
	root := t.TempDir()
	sshFixture{root: root}.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	// No authorized_keys files created anywhere → lockout risk.

	code, reason, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitBlock {
		t.Errorf("exit = %d want %d (block)", code, PreflightExitBlock)
	}
	if reason != sshLockoutReason {
		t.Errorf("reason = %q want lockout guidance", reason)
	}
}

func TestPreflightSSH_Block_WhenAuthorizedKeysOnlyCommentsOrEmpty(t *testing.T) {
	root := t.TempDir()
	sshFixture{root: root}.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	// File exists but holds only comments/blank lines → no real key.
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		"# placeholder\n\n   \n")

	code, _, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitBlock {
		t.Errorf("exit = %d want %d (block) for keyless file", code, PreflightExitBlock)
	}
}

func TestPreflightSSH_Pass_WhenAdminUserHasKey(t *testing.T) {
	root := t.TempDir()
	adminHome := filepath.Join(root, "home", "deploy")
	fixture := sshFixture{
		root: root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/usr/sbin/nologin\n" +
			"deploy:x:1000:1000:deploy:" + adminHome + ":/bin/bash\n" +
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	// root has no key and a nologin shell; the admin 'deploy' user has a key.
	mustWrite(t, filepath.Join(adminHome, ".ssh", "authorized_keys2"),
		"ssh-rsa "+testRSABlob+" deploy@laptop\n")

	code, _, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitPass {
		t.Errorf("exit = %d want %d (pass) when admin user has key", code, PreflightExitPass)
	}
}

func TestPreflightSSH_Block_IgnoresNologinUserKeys(t *testing.T) {
	// A key belonging ONLY to a nologin/system account must NOT count as a
	// usable access method (that user can't SSH in interactively).
	root := t.TempDir()
	svcHome := filepath.Join(root, "var", "lib", "svc")
	fixture := sshFixture{
		root: root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/bin/bash\n" +
			"svc:x:998:998:svc:" + svcHome + ":/usr/sbin/nologin\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	mustWrite(t, filepath.Join(svcHome, ".ssh", "authorized_keys"),
		"ssh-ed25519 "+testEd25519Blob+" svc@host\n")
	// root (login shell) has NO key → still a lockout risk.

	code, _, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitBlock {
		t.Errorf("exit = %d want %d (block); nologin-user keys must not count", code, PreflightExitBlock)
	}
}

func TestIsLoginShell(t *testing.T) {
	cases := map[string]bool{
		"/bin/bash":         true,
		"/bin/zsh":          true,
		"/bin/sh":           true,
		"/usr/bin/fish":     true,
		"/bin/dash":         true,
		"/bin/ksh":          true,
		"/bin/tcsh":         true,
		"/usr/sbin/nologin": false,
		"/bin/false":        false,
		"/sbin/nologin":     false,
		"":                  false,
		// Restricted shells must NOT count as usable admin access (fail closed).
		"/usr/bin/git-shell": false,
		"git-shell":          false,
		"/bin/rbash":         false,
		"rbash":              false,
		"/usr/bin/scponly":   false,
		// Unknown/uncertain shells must not count (fail closed).
		"/opt/weird/shell": false,
	}
	for shell, want := range cases {
		if got := isLoginShell(shell); got != want {
			t.Errorf("isLoginShell(%q) = %v want %v", shell, got, want)
		}
	}
}

// FINDING 3(a): a non-comment authorized_keys line that is NOT a plausible key
// (garbage / no recognised key-type token) must NOT count → preflight blocks.
func TestPreflightSSH_Block_WhenAuthorizedKeysIsGarbage(t *testing.T) {
	root := t.TempDir()
	sshFixture{root: root}.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		"this is not a key\nlorem ipsum dolor\n12345 random text\n")

	code, reason, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitBlock {
		t.Errorf("exit = %d want %d (block) for malformed/garbage authorized_keys", code, PreflightExitBlock)
	}
	if reason != sshLockoutReason {
		t.Errorf("reason = %q want lockout guidance", reason)
	}
}

// FINDING 3(a): an ed25519 key preceded by authorized_keys options must be
// recognised (scan fields, not just field[0]) → preflight passes.
func TestPreflightSSH_Pass_WhenKeyHasOptionsPrefix(t *testing.T) {
	root := t.TempDir()
	fixture := sshFixture{
		root:   root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/bin/bash\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		`no-pty,from="10.0.0.0/8",command="/bin/true" ssh-ed25519 `+testEd25519Blob+" user@host\n")

	code, _, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitPass {
		t.Errorf("exit = %d want %d (pass) for valid key with options prefix", code, PreflightExitPass)
	}
}

// FINDING 3(b): a user whose ONLY shell is git-shell is not login-capable for
// admin, so its key must not count → preflight blocks (root has no key).
func TestPreflightSSH_Block_IgnoresGitShellUserKeys(t *testing.T) {
	root := t.TempDir()
	gitHome := filepath.Join(root, "home", "git")
	fixture := sshFixture{
		root: root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/bin/bash\n" +
			"git:x:1001:1001:git:" + gitHome + ":/usr/bin/git-shell\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	// git user has a perfectly valid key, but git-shell is not usable admin access.
	mustWrite(t, filepath.Join(gitHome, ".ssh", "authorized_keys"),
		"ssh-ed25519 "+testEd25519Blob+" git@host\n")
	// root (interactive shell) has NO key → still a lockout risk.

	code, _, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitBlock {
		t.Errorf("exit = %d want %d (block); git-shell user keys must not count", code, PreflightExitBlock)
	}
}

// Sanity: a valid ecdsa key for an interactive-shell admin user passes.
func TestPreflightSSH_Pass_WhenEcdsaKeyPresent(t *testing.T) {
	root := t.TempDir()
	fixture := sshFixture{
		root:   root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/bin/bash\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		"ecdsa-sha2-nistp256 "+testECDSABlob+" root@host\n")

	code, _, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitPass {
		t.Errorf("exit = %d want %d (pass) for valid ecdsa key", code, PreflightExitPass)
	}
}

// BUG 3a: root's authorized_keys must be shell-filtered like any other account.
// A key under /root/.ssh while root's login shell is nologin (and no other
// interactive-shell user has a key) is NOT a usable access path → block.
func TestPreflightSSH_Block_WhenRootHasKeyButNologinShell(t *testing.T) {
	root := t.TempDir()
	fixture := sshFixture{
		root:   root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/usr/sbin/nologin\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	// root HAS a valid key, but root cannot log in interactively.
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		"ssh-ed25519 "+testEd25519Blob+" root@host\n")

	code, reason, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitBlock {
		t.Errorf("exit = %d want %d (block); root key must not count when root shell is nologin", code, PreflightExitBlock)
	}
	if reason != sshLockoutReason {
		t.Errorf("reason = %q want lockout guidance", reason)
	}
}

// BUG 3a: if /etc/passwd has no root entry at all, root keys must not count
// (fail closed — we can't confirm root has an interactive shell).
func TestPreflightSSH_Block_WhenRootHasKeyButNoPasswdEntry(t *testing.T) {
	root := t.TempDir()
	fixture := sshFixture{
		root:   root,
		passwd: "deploy:x:1000:1000:deploy:" + filepath.Join(root, "home", "deploy") + ":/usr/sbin/nologin\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		"ssh-ed25519 "+testEd25519Blob+" root@host\n")

	code, _, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitBlock {
		t.Errorf("exit = %d want %d (block); root key must not count without an interactive root passwd entry", code, PreflightExitBlock)
	}
}

// BUG 3b: a bare key-type token with NO key blob is a truncated/malformed entry
// and must NOT count as a key → block.
func TestPreflightSSH_Block_WhenKeyTypeHasNoBlob(t *testing.T) {
	root := t.TempDir()
	fixture := sshFixture{
		root:   root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/bin/bash\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	// Just the key type, nothing after it.
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		"ssh-ed25519\n")

	code, reason, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitBlock {
		t.Errorf("exit = %d want %d (block) for bare key-type with no blob", code, PreflightExitBlock)
	}
	if reason != sshLockoutReason {
		t.Errorf("reason = %q want lockout guidance", reason)
	}
}

// BUG 3b: a key type followed by an empty/garbage (non-base64 or too-short) blob
// field must NOT count → block.
func TestPreflightSSH_Block_WhenKeyBlobIsGarbageOrTooShort(t *testing.T) {
	cases := map[string]string{
		"too_short":   "ssh-ed25519 AAAA user@host\n",
		"non_base64":  "ssh-ed25519 !!!not-base64-data-here-@@@###$$$%%%^^^&&&***((()))___ x\n",
		"trailing_eq": "ssh-rsa == user@host\n",
	}
	for name, keysContent := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			fixture := sshFixture{
				root:   root,
				passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/bin/bash\n",
			}
			fixture.apply(t)
			mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
			mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"), keysContent)

			code, _, err := preflightSSHDisablePasswordAuth(context.Background())
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if code != PreflightExitBlock {
				t.Errorf("exit = %d want %d (block) for %s blob", code, PreflightExitBlock, name)
			}
		})
	}
}

// BUG 3b: a well-formed "<type> <base64-blob> <comment>" entry counts → pass.
func TestPreflightSSH_Pass_WhenKeyTypeBlobAndComment(t *testing.T) {
	root := t.TempDir()
	fixture := sshFixture{
		root:   root,
		passwd: "root:x:0:0:root:" + filepath.Join(root, "root") + ":/bin/bash\n",
	}
	fixture.apply(t)
	mustWrite(t, sshdConfigPath, "PasswordAuthentication yes\n")
	mustWrite(t, filepath.Join(rootHomeDir, ".ssh", "authorized_keys"),
		"ssh-ed25519 "+testEd25519Blob+" alice@workstation\n")

	code, _, err := preflightSSHDisablePasswordAuth(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != PreflightExitPass {
		t.Errorf("exit = %d want %d (pass) for valid type+blob+comment", code, PreflightExitPass)
	}
}

// BUG 3b unit-level: lineHasSSHKeyType directly.
func TestLineHasSSHKeyType(t *testing.T) {
	cases := map[string]bool{
		"ssh-ed25519 " + testEd25519Blob + " user@host":            true,
		`no-pty,from="x" ssh-ed25519 ` + testEd25519Blob:           true,
		"ssh-rsa " + testRSABlob:                                   true,
		"ssh-ed25519":                                              false, // bare type, no blob
		"ssh-ed25519 ":                                             false, // trailing space, still no blob
		"ssh-ed25519 AAAA":                                         false, // blob too short
		"ssh-ed25519 !!!bad-base64-@@@" + strings.Repeat("x!", 30): false, // non-base64
		"not-a-key-type " + testEd25519Blob:                        false, // no recognised type
		"# ssh-ed25519 " + testEd25519Blob:                         true,  // '#' is a separate field; type+blob still present
	}
	for line, want := range cases {
		if got := lineHasSSHKeyType(line); got != want {
			t.Errorf("lineHasSSHKeyType(%q) = %v want %v", line, got, want)
		}
	}
}
