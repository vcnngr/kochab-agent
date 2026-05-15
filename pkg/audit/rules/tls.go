package rules

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const RuleCodeTLSMinVersion12 = "tls.min_version_12"

func init() {
	RegisterRule(RuleCodeTLSMinVersion12, checkTLSMinVersion12)
}

// Directories scanned for TLS config drift.
var tlsScanRoots = []string{
	"/etc/nginx",
	"/etc/apache2",
	"/etc/httpd",
	"/etc/postfix",
	"/etc/dovecot",
	"/etc/haproxy",
}

// Patterns matching directives that allow legacy TLS protocols.
var (
	nginxLegacyRe   = regexp.MustCompile(`(?im)^\s*ssl_protocols[^;#\n]*\b(SSLv[23]|TLSv1(?:\.[01])?)\b`)
	apacheLegacyRe  = regexp.MustCompile(`(?im)^\s*SSLProtocol[^#\n]*\b(?:\+|all)?\s*(SSLv[23]|TLSv1(?:\.[01])?)\b`)
	postfixLegacyRe = regexp.MustCompile(`(?im)^\s*smtpd?_tls_protocols\s*=[^#\n]*\b(SSLv[23]|TLSv1(?:\.[01])?)\b`)
	dovecotLegacyRe = regexp.MustCompile(`(?im)^\s*ssl_min_protocol\s*=\s*(SSLv[23]|TLSv1(?:\.[01])?)\b`)
)

func checkTLSMinVersion12(ctx context.Context) (bool, map[string]any, error) {
	hits := []string{}
	anyConfigSeen := false

	for _, root := range tlsScanRoots {
		if ctx.Err() != nil {
			return false, nil, ctx.Err()
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		anyConfigSeen = true
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil || d == nil || d.IsDir() {
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".conf") && name != "main.cf" && name != "master.cf" && !strings.HasSuffix(name, ".cf") {
				return nil
			}
			body, ok, _ := readFile(path)
			if !ok {
				return nil
			}
			if nginxLegacyRe.MatchString(body) ||
				apacheLegacyRe.MatchString(body) ||
				postfixLegacyRe.MatchString(body) ||
				dovecotLegacyRe.MatchString(body) {
				hits = append(hits, path)
			}
			return nil
		})
	}

	if !anyConfigSeen {
		return true, map[string]any{"skipped_reason": "no TLS-serving daemons installed"}, nil
	}
	if len(hits) == 0 {
		return true, map[string]any{}, nil
	}
	return false, map[string]any{
		"legacy_config_files": hits,
	}, nil
}
