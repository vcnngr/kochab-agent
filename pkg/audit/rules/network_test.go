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

func TestSSHPort(t *testing.T) {
	cases := []struct {
		name   string
		config string
		want   int
	}{
		{"default when unset", "PasswordAuthentication no\n", 22},
		{"explicit port", "Port 2222\nPasswordAuthentication no\n", 2222},
		{"last directive wins", "Port 2222\nPort 2022\n", 2022},
		{"comment ignored", "#Port 9999\nPort 22\n", 22},
		{"invalid ignored", "Port notanumber\n", 22},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sshPort(tc.config); got != tc.want {
				t.Errorf("sshPort = %d, want %d", got, tc.want)
			}
		})
	}
}
