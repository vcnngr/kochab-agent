package rules

import (
	"context"
	"net"
	"os"
	"strings"
)

const RuleCodeDKIMSPFDMARCBasic = "dkim_spf_dmarc.basic"

func init() {
	RegisterRule(RuleCodeDKIMSPFDMARCBasic, checkDKIMSPFDMARCBasic)
}

// hasMailServer detects an installed mail daemon. We skip the rule on hosts
// that are not mail servers — info-level finding noise is not worth it.
func hasMailServer() bool {
	for _, path := range []string{
		"/usr/sbin/postfix",
		"/usr/sbin/exim4",
		"/usr/sbin/sendmail",
		"/usr/sbin/smtpd",
	} {
		if fileExists(path) {
			return true
		}
	}
	return false
}

// hostDomain returns the FQDN's domain part (everything after the first dot).
// Returns "" if the system hostname has no domain component.
func hostDomain() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	if i := strings.Index(host, "."); i >= 0 {
		return host[i+1:], nil
	}
	return "", nil
}

func checkDKIMSPFDMARCBasic(ctx context.Context) (bool, map[string]any, error) {
	if !hasMailServer() {
		return true, map[string]any{"skipped_reason": "no mail server installed"}, nil
	}
	domain, err := hostDomain()
	if err != nil {
		return false, nil, err
	}
	if domain == "" {
		return true, map[string]any{"skipped_reason": "hostname has no domain part"}, nil
	}

	resolver := &net.Resolver{}
	spfOK := dnsHasRecord(ctx, resolver, domain, "v=spf1")
	dmarcOK := dnsHasRecord(ctx, resolver, "_dmarc."+domain, "v=DMARC1")

	if spfOK && dmarcOK {
		return true, map[string]any{"domain": domain}, nil
	}
	return false, map[string]any{
		"domain":   domain,
		"spf_ok":   spfOK,
		"dmarc_ok": dmarcOK,
	}, nil
}

func dnsHasRecord(ctx context.Context, r *net.Resolver, name, prefix string) bool {
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return false
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, prefix) {
			return true
		}
	}
	return false
}
