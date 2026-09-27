package config

import (
	"testing"

	"github.com/pelletier/go-toml"
)

// The REAL config decode chain: TOML carrying the observation-fault fields
// must populate NodeResourceConfig exactly (assembly into the Module is
// covered by resourcemanager.TestObservationFaultHTTPThroughRealModule).
func TestNodeResourceObservationFaultDecode(t *testing.T) {
	var cfg Config
	if err := toml.Unmarshal([]byte(
		"[node_resource]\nprovider = \"cgroup\"\nsock_path = \"/var/run/resource.sock\"\n"+
			"enable_observation_fault = true\nobservation_fault_path = \"/tmp/fault.json\"\n",
	), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !cfg.NodeResourceConfig.EnableObservationFault ||
		cfg.NodeResourceConfig.ObservationFaultPath != "/tmp/fault.json" {
		t.Fatalf("decode mismatch: %+v", cfg.NodeResourceConfig)
	}
	// absent fields decode to the default-off state
	var cfg2 Config
	if err := toml.Unmarshal([]byte("[node_resource]\nprovider = \"cgroup\"\n"), &cfg2); err != nil {
		t.Fatalf("decode default: %v", err)
	}
	if cfg2.NodeResourceConfig.EnableObservationFault || cfg2.NodeResourceConfig.ObservationFaultPath != "" {
		t.Fatalf("absent fields must stay off: %+v", cfg2.NodeResourceConfig)
	}
}
