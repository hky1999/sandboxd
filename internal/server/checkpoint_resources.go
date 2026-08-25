// checkpoint_resources.go — W7-P1.1: carry resource limits across park.
//
// A park (checkpoint leaveRunning=false) captures the sandbox at whatever
// limits it currently runs at — including limits changed after creation by
// the elastic ladder (runsc update --memory) or task variants. The restore
// path used to rebuild the sandbox from the caller's StartRequest, whose
// resources map carries the ORIGINAL booking (observed: 6G-at-park restored
// at 32G, forcing the ladder to re-enroll). The checkpoint now snapshots the
// effective cgroup limits into a sidecar next to the memory-state image, and
// the restore overrides the request's resource map with them.
package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
)

// resourceLimitsFile is written into the checkpoint directory next to the
// memory-state image.
const resourceLimitsFile = "resource-limits.json"

// resourceLimitsSnapshot is the sidecar schema (extensible: CPU can join
// later). MemoryLimitBytes mirrors cgroup memory.max at checkpoint time.
type resourceLimitsSnapshot struct {
	MemoryLimitBytes uint64 `json:"memory_limit_bytes"`
}

// captureResourceLimits reads the sandbox's effective cgroup limits and
// writes the sidecar into dir. Missing cgroup manager/path is not fatal —
// the restore simply falls back to the request's own resources.
func (h *sandboxService) captureResourceLimits(sandboxID, dir string) error {
	current, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		return fmt.Errorf("capture resource limits: get sandbox %s: %w", sandboxID, err)
	}
	if h.cgroupMgr == nil {
		return nil
	}
	resource, err := h.physicalResources(current.Metadata)
	if err != nil {
		return err
	}
	cgroupPath, ok := resource.Resources[config.ResourceNameCgroup]
	if !ok || cgroupPath == "" {
		return nil
	}
	stats, err := h.cgroupMgr.Stats(cgroupPath)
	if err != nil {
		return fmt.Errorf("capture resource limits: stat cgroup %s: %w", cgroupPath, err)
	}
	snapshot := resourceLimitsSnapshot{MemoryLimitBytes: stats.MemoryLimitBytes}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, resourceLimitsFile), data, 0o600)
}

// applyCheckpointResourceLimits overrides the restore request's resources
// with the limits snapshotted at checkpoint time. No sidecar (checkpoints
// taken before this change, or cgroup-less sandboxes) = unchanged behavior.
func applyCheckpointResourceLimits(startConfig *runtime.StartRequest, checkpointDir string) {
	data, err := os.ReadFile(filepath.Join(checkpointDir, resourceLimitsFile))
	if err != nil {
		return
	}
	var snapshot resourceLimitsSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil || snapshot.MemoryLimitBytes == 0 {
		return
	}
	mb := float64(snapshot.MemoryLimitBytes / (1024 * 1024))
	if mb < 1 {
		return
	}
	if startConfig.Resources == nil {
		startConfig.Resources = make(map[string]float64)
	}
	startConfig.Resources["Memory"] = mb
}
