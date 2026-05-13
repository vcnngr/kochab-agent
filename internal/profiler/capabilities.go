package profiler

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kochab-ai/kochab-agent/pkg/protocol"
)

// CommandRunner executes shell commands. Overridable for testing.
var CommandRunner func(name string, args ...string) ([]byte, error) = defaultRunner

func defaultRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// CollectOSInfo gathers OS details for enrollment.
func CollectOSInfo() protocol.OSInfo {
	info := protocol.OSInfo{
		Arch: runtime.GOARCH,
	}

	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ID=") {
				info.Distro = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				info.Version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
		}
	}

	if out, err := CommandRunner("uname", "-r"); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	return info
}

// CollectProfile gathers the full server profile including log metadata.
func CollectProfile(ctx context.Context, hostname string) (*protocol.ProfilePayload, error) {
	osInfo := CollectOSInfo()
	logMeta := CollectLogMetadata(ctx)

	payload := &protocol.ProfilePayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Profile: protocol.Profile{
			Hostname:    hostname,
			OS:          osInfo,
			Packages:    collectPackages(),
			Services:    collectServices(),
			Network:     collectNetwork(),
			Config:      collectConfig(),
			LogMetadata: &logMeta,
		},
	}

	return payload, nil
}

func collectPackages() protocol.PackagesInfo {
	info := protocol.PackagesInfo{}

	out, err := CommandRunner("dpkg", "-l")
	if err != nil {
		slog.Warn("profiler: dpkg not available", "error", err)
		return info
	}

	const maxPackageNames = 500

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ii ") {
			info.TotalCount++
			fields := strings.Fields(line)
			if len(fields) >= 2 && len(info.List) < maxPackageNames {
				info.List = append(info.List, fields[1])
			}
		}
	}

	// Count security updates
	out, err = CommandRunner("apt", "list", "--upgradable")
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "-security") {
				info.SecurityUpdates++
			}
		}
	}

	return info
}

func collectServices() protocol.ServicesInfo {
	info := protocol.ServicesInfo{}

	out, err := CommandRunner("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend")
	if err != nil {
		slog.Warn("profiler: systemctl not available", "error", err)
		return info
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			name := strings.TrimSuffix(fields[0], ".service")
			info.List = append(info.List, name)
			info.TotalRunning++
		}
	}

	return info
}

func collectNetwork() protocol.NetworkInfo {
	info := protocol.NetworkInfo{
		OpenPorts:  []int{},
		Interfaces: []string{},
	}

	// Ports
	out, err := CommandRunner("ss", "-tulpn")
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "LISTEN") {
				// Parse port from local address field (e.g., *:22 or 0.0.0.0:80)
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					addr := fields[3]
					if idx := strings.LastIndex(addr, ":"); idx >= 0 {
						portStr := addr[idx+1:]
						if port, err := strconv.Atoi(portStr); err == nil {
							info.OpenPorts = appendUnique(info.OpenPorts, port)
						}
					}
				}
			}
		}
	}

	// Interfaces
	entries, err := os.ReadDir("/sys/class/net")
	if err == nil {
		for _, e := range entries {
			info.Interfaces = append(info.Interfaces, e.Name())
		}
	}

	return info
}

func collectConfig() protocol.ConfigInfo {
	info := protocol.ConfigInfo{}

	// SSH config
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.HasPrefix(line, "AuthenticationMethods") || strings.HasPrefix(line, "PubkeyAuthentication") || strings.HasPrefix(line, "PasswordAuthentication") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					info.SSHAuthMethods = append(info.SSHAuthMethods, parts[1])
				}
			}
			if strings.HasPrefix(line, "Ciphers ") {
				parts := strings.SplitN(line, " ", 2)
				if len(parts) == 2 {
					info.SSHCiphers = strings.Split(strings.TrimSpace(parts[1]), ",")
				}
			}
		}
	}

	// Firewall (nftables)
	out, err := CommandRunner("nft", "list", "ruleset")
	if err == nil {
		rules := strings.Count(string(out), "rule ")
		info.FirewallEnabled = rules > 0
	}

	// User count
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		info.UsersCount = len(strings.Split(strings.TrimSpace(string(data)), "\n"))
	}

	// Container runtime
	if _, err := exec.LookPath("docker"); err == nil {
		rt := "docker"
		info.ContainerRuntime = &rt
	} else if _, err := exec.LookPath("podman"); err == nil {
		rt := "podman"
		info.ContainerRuntime = &rt
	}

	return info
}

func appendUnique(slice []int, val int) []int {
	for _, v := range slice {
		if v == val {
			return slice
		}
	}
	return append(slice, val)
}
