package nse

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const DefaultTimeout = 2 * time.Minute

// Runner executes Nmap NSE scripts against a host.
type Runner struct {
	Binary string
}

// NewRunner creates a new NSE runner.
func NewRunner(binary string) Runner {
	if strings.TrimSpace(binary) == "" {
		binary = "nmap"
	}
	return Runner{Binary: binary}
}

// RunHostScripts runs NSE scripts for a host and returns raw Nmap output.
// If timeout is <= 0, DefaultTimeout is used.
func (r Runner) RunHostScripts(
	ctx context.Context,
	host string,
	ports []int,
	scriptExpr string,
	scriptArgs string,
	timeout time.Duration,
) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("context must not be nil")
	}
	if strings.TrimSpace(scriptExpr) == "" {
		return "", nil
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := buildArgs(host, ports, scriptExpr, scriptArgs)
	cmd := exec.CommandContext(runCtx, r.Binary, args...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output == "" {
			return "", fmt.Errorf("nse execution failed: %w", err)
		}
		return "", fmt.Errorf("nse execution failed: %w: %s", err, output)
	}
	return output, nil
}

func buildArgs(host string, ports []int, scriptExpr string, scriptArgs string) []string {
	args := []string{"-Pn", "-n", "--script", scriptExpr}
	if len(ports) > 0 {
		args = append(args, "-p", joinPorts(ports))
	}
	if strings.TrimSpace(scriptArgs) != "" {
		args = append(args, "--script-args", scriptArgs)
	}
	args = append(args, host)
	return args
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	strPorts := make([]string, 0, len(ports))
	for _, p := range ports {
		strPorts = append(strPorts, strconv.Itoa(p))
	}
	return strings.Join(strPorts, ",")
}
