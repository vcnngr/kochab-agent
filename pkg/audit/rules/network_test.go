package rules

import "testing"

func TestParseListenScope(t *testing.T) {
	cases := []struct {
		name      string
		ss        string
		port      int
		wantScope string
		wantAddrs int
	}{
		{
			name:      "wildcard ipv4 is public",
			ss:        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
			port:      22,
			wantScope: bindScopePublic,
			wantAddrs: 1,
		},
		{
			name:      "wildcard ipv6 is public",
			ss:        "LISTEN 0 128 [::]:22 [::]:*",
			port:      22,
			wantScope: bindScopePublic,
			wantAddrs: 1,
		},
		{
			name:      "loopback only is private",
			ss:        "LISTEN 0 128 127.0.0.1:22 0.0.0.0:*",
			port:      22,
			wantScope: bindScopePrivate,
			wantAddrs: 1,
		},
		{
			name:      "rfc1918 only is private",
			ss:        "LISTEN 0 128 10.0.0.5:22 0.0.0.0:*\nLISTEN 0 128 192.168.1.10:22 0.0.0.0:*",
			port:      22,
			wantScope: bindScopePrivate,
			wantAddrs: 2,
		},
		{
			name:      "public routable ip is public",
			ss:        "LISTEN 0 128 203.0.113.10:22 0.0.0.0:*",
			port:      22,
			wantScope: bindScopePublic,
			wantAddrs: 1,
		},
		{
			name:      "mixed private+wildcard wins public",
			ss:        "LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
			port:      22,
			wantScope: bindScopePublic,
			wantAddrs: 2,
		},
		{
			name:      "no listener for port is unknown",
			ss:        "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*",
			port:      22,
			wantScope: bindScopeUnknown,
			wantAddrs: 0,
		},
		{
			name:      "custom port respected",
			ss:        "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*",
			port:      2222,
			wantScope: bindScopePublic,
			wantAddrs: 1,
		},
		{
			name:      "empty output is unknown",
			ss:        "",
			port:      22,
			wantScope: bindScopeUnknown,
			wantAddrs: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, addrs := parseListenScope(tc.ss, tc.port)
			if scope != tc.wantScope {
				t.Errorf("scope = %q, want %q", scope, tc.wantScope)
			}
			if len(addrs) != tc.wantAddrs {
				t.Errorf("addrs = %d (%v), want %d", len(addrs), addrs, tc.wantAddrs)
			}
		})
	}
}

func TestSSHPorts(t *testing.T) {
	cases := []struct {
		name    string
		sources []string
		want    []int
	}{
		{"default when unset", []string{"PasswordAuthentication no\n"}, []int{22}},
		{"explicit port", []string{"Port 2222\nPasswordAuthentication no\n"}, []int{2222}},
		{"multiple ports all kept", []string{"Port 22\nPort 2222\n"}, []int{22, 2222}},
		{"dedup across sources", []string{"Port 22\n", "Port 22\nPort 443\n"}, []int{22, 443}},
		{"comment ignored", []string{"#Port 9999\nPort 22\n"}, []int{22}},
		{"invalid ignored, fallback default", []string{"Port notanumber\n"}, []int{22}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sshPorts(tc.sources)
			if len(got) != len(tc.want) {
				t.Fatalf("sshPorts = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("sshPorts = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestParseListenScope_IPv6ZoneStripped(t *testing.T) {
	// Link-local with zone id must not be misclassified as public.
	scope, _ := parseListenScope("LISTEN 0 128 [fe80::1%eth0]:22 [::]:*", 22)
	if scope != bindScopePrivate {
		t.Errorf("scope = %q, want private (link-local)", scope)
	}
}
