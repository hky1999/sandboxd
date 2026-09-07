package firecracker

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
)

func TestVMMCommandProcessIdentity(t *testing.T) {
	if os.Getenv("AKERNEL_VMM_COMMAND_CHILD") == "1" {
		_, _ = os.Stdout.WriteString("ready\n")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"", "Debug"} {
		t.Run("level="+level, func(t *testing.T) {
			handler := &Handler{binary: binary, vmmLogLevel: level}
			apiPath := filepath.Join(t.TempDir(), "api.sock")
			command := handler.vmmCommand(apiPath, "identity-test")
			// The test executable stands in for the VMM, with native arguments
			// after -- so Go's test flag parser leaves them untouched.
			command.Args = append([]string{binary, "-test.run=^TestVMMCommandProcessIdentity$", "--"}, command.Args[1:]...)
			command.Env = append(os.Environ(), "AKERNEL_VMM_COMMAND_CHILD=1")
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
			if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
				t.Fatalf("child readiness: %q %v", line, err)
			}
			if !firecrackerProcessMatches(command.Process.Pid, binary, apiPath, "identity-test") {
				t.Fatal("native startup arguments broke process identity")
			}
			if firecrackerProcessMatches(command.Process.Pid, binary+"-wrapper", apiPath, "identity-test") {
				t.Fatal("different configured executable passed identity check")
			}
		})
	}
}

func TestVMMLogLevelValidation(t *testing.T) {
	for _, level := range []string{"", "Off", "Trace", "Debug", "Info", "Warn", "Warning", "Error"} {
		if err := validateVMMLogLevel(level); err != nil {
			t.Fatal(err)
		}
	}
	var cfg config.Config
	cfg.RuntimeConfig.Firecracker.VMMLogLevel = "Debug --other-flag"
	if _, err := NewHandler(cfg, "", nil); err == nil || !strings.Contains(err.Error(), "invalid vmm_log_level") {
		t.Fatalf("invalid log level did not fail at validation: %v", err)
	}
}
