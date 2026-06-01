package rules

import (
	"context"
	"os/exec"
	"strings"
)

const RuleCodeDockerNoHostNetwork = "docker.no_host_network"

func init() {
	RegisterRuleWithPreflight(RuleCodeDockerNoHostNetwork, checkDockerNoHostNetwork, preflightDockerNoHostNetwork)
}

// preflightDockerNoHostNetwork is the READ-ONLY guardrail for the
// "no host-network container" fix (seed 007: `command -v docker ... || exit 2`).
// If docker isn't installed the fix is not applicable → skip (fix still shown,
// per contract). Otherwise the fix (recreate containers without --network=host)
// is always safe to suggest as copy-paste → pass. Read-only: only LookPath.
func preflightDockerNoHostNetwork(_ context.Context) (int, string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return PreflightExitSkip, "", nil
	}
	return PreflightExitPass, "", nil
}

// checkDockerNoHostNetwork iterates `docker ps` and reports any running
// container using the host network namespace. Hosts without Docker installed
// pass vacuously (skipped_reason). Hosts with Docker installed but daemon
// unreachable produce an info finding so ops can investigate.
func checkDockerNoHostNetwork(ctx context.Context) (bool, map[string]any, error) {
	out, code, err := cmdOutput(ctx, "docker", "ps", "--format", "{{.Names}}|{{.Networks}}")
	if isCmdNotFound(err) {
		return true, map[string]any{"skipped_reason": "docker not installed"}, nil
	}
	if err != nil {
		return false, nil, err
	}
	if code != 0 {
		return true, map[string]any{"skipped_reason": "docker present but daemon unreachable"}, nil
	}

	hostContainers := []string{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		networks := strings.Split(parts[1], ",")
		for _, n := range networks {
			if strings.TrimSpace(n) == "host" {
				hostContainers = append(hostContainers, strings.TrimSpace(parts[0]))
				break
			}
		}
	}

	if len(hostContainers) == 0 {
		return true, map[string]any{}, nil
	}
	return false, map[string]any{"host_network_containers": hostContainers}, nil
}
