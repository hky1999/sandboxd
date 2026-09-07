package firecracker

import (
	"fmt"
	"os/exec"
	"strings"
)

func validateVMMLogLevel(level string) error {
	switch strings.ToLower(level) {
	case "", "off", "trace", "debug", "info", "warn", "warning", "error":
		return nil
	default:
		return fmt.Errorf("invalid vmm_log_level %q", level)
	}
}

// vmmCommand keeps the configured executable as argv[0] and /proc/PID/exe.
// Both identities are required by firecrackerProcessMatches. A shell wrapper
// for startup flags breaks checkpoint ownership checks after exec.
func (handler *Handler) vmmCommand(apiPath, id string) *exec.Cmd {
	args := []string{"--api-sock", apiPath, "--id", id}
	if handler.vmmLogLevel != "" {
		args = append(args, "--level", handler.vmmLogLevel)
	}
	return exec.Command(handler.binary, args...)
}
