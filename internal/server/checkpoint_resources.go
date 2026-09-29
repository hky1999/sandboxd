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
	"math"
	"os"
	"path/filepath"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/checkpoint"
)

// resourceLimitsFile is written into the checkpoint directory next to the
// memory-state image. New publications bind its size and digest in the manifest.
const resourceLimitsFile = checkpoint.ResourceLimitsName

// resourceLimitsSnapshot records effective cgroup limits at checkpoint time.
type resourceLimitsSnapshot struct {
	ElasticPolicy    string `json:"elastic_policy,omitempty"`
	CPUQuotaUsec     int64  `json:"cpu_quota_usec,omitempty"`
	CPUPeriodUsec    uint64 `json:"cpu_period_usec,omitempty"`
	CPULimitsKnown   bool   `json:"cpu_limits_known,omitempty"`
	MemoryLimitBytes uint64 `json:"memory_limit_bytes"`
	MemoryLimitKnown bool   `json:"memory_limit_known,omitempty"`
}

// captureResourceLimits reads the sandbox's effective cgroup limits and
// writes the sidecar into dir. Elastic sandboxes require complete cgroup data;
// older non-elastic requests retain their historical fallback behavior.
func (h *sandboxService) captureResourceLimits(sandboxID, dir string) error {
	current, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		return fmt.Errorf("capture resource limits: get sandbox %s: %w", sandboxID, err)
	}
	policy := current.Metadata.GetLabels()[elasticResourcesLabel]
	if h.cgroupMgr == nil {
		if policy != "" {
			return fmt.Errorf("elastic checkpoint requires cgroup statistics")
		}
		return nil
	}
	resource, err := h.physicalResources(current.Metadata)
	if err != nil {
		return err
	}
	cgroupPath, ok := resource.Resources[config.ResourceNameCgroup]
	if !ok || cgroupPath == "" {
		if policy != "" {
			return fmt.Errorf("elastic checkpoint requires a cgroup path")
		}
		return nil
	}
	stats, err := h.cgroupMgr.Stats(cgroupPath)
	if err != nil {
		return fmt.Errorf("capture resource limits: stat cgroup %s: %w", cgroupPath, err)
	}
	// A false MemoryLimitKnown carries only a legacy fallback number; elastic
	// capture must not publish it as an observed limit.
	if policy != "" && (!stats.CPULimitsKnown || !stats.MemoryLimitKnown || stats.CPUQuotaUsec <= 0 || stats.CPUPeriodUsec == 0 || stats.MemoryLimitBytes < 1024*1024) {
		return fmt.Errorf("elastic checkpoint requires known finite resource limits")
	}
	if policy != "" {
		captured := &runtime.StartRequest{
			Runtime: config.RuntimeNameRunsc,
			Labels:  map[string]string{elasticResourcesLabel: policy},
			Resources: map[string]float64{
				"CPU":    1000 * float64(stats.CPUQuotaUsec) / float64(stats.CPUPeriodUsec),
				"Memory": float64(stats.MemoryLimitBytes) / (1024 * 1024),
			},
		}
		if err := validateElasticResources(captured, h.config, true); err != nil {
			return fmt.Errorf("cannot checkpoint elastic limits outside policy: %w", err)
		}
	}
	snapshot := resourceLimitsSnapshot{ElasticPolicy: policy, MemoryLimitBytes: stats.MemoryLimitBytes, MemoryLimitKnown: stats.MemoryLimitKnown, CPUQuotaUsec: stats.CPUQuotaUsec, CPUPeriodUsec: stats.CPUPeriodUsec, CPULimitsKnown: stats.CPULimitsKnown}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, resourceLimitsFile), data, 0o600)
}

// applyCheckpointResourceLimits overrides the restore request's resources
// with the limits snapshotted at checkpoint time. No sidecar (checkpoints
// taken before this change, or cgroup-less sandboxes) preserves legacy behavior
// only for non-elastic requests. Elastic restore requires the saved policy.
func applyCheckpointResourceLimits(startConfig *runtime.StartRequest, checkpointDir string) error {
	if err := checkpoint.VerifyResourceLimitsAt(checkpointDir); err != nil {
		return err
	}
	_, elastic := startConfig.Labels[elasticResourcesLabel]
	data, err := os.ReadFile(filepath.Join(checkpointDir, resourceLimitsFile))
	if err != nil {
		if elastic {
			return fmt.Errorf("elastic restore requires resource limits sidecar: %w", err)
		}
		return nil
	}
	var snapshot resourceLimitsSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		if elastic {
			return fmt.Errorf("invalid elastic restore resource limits: %w", err)
		}
		return nil
	}
	if elastic || snapshot.ElasticPolicy != "" {
		// Legacy elastic sidecars without a saved memory_limit_known flag fail
		// closed: their number cannot be proven to be an observed limit.
		if snapshot.ElasticPolicy == "" || !snapshot.CPULimitsKnown || !snapshot.MemoryLimitKnown ||
			snapshot.CPUQuotaUsec <= 0 || snapshot.CPUPeriodUsec == 0 || snapshot.MemoryLimitBytes < 1024*1024 {
			return fmt.Errorf("elastic restore requires saved policy and finite CPU/memory limits")
		}
		if startConfig.Labels == nil {
			startConfig.Labels = make(map[string]string)
		}
		// The source's ceiling wins over a caller's newly supplied policy.
		startConfig.Labels[elasticResourcesLabel] = snapshot.ElasticPolicy
	}
	// Apply each known finite limit independently. Old memory-only sidecars
	// preserve their historical behavior; unknown CPU never becomes zero.
	if snapshot.CPULimitsKnown && snapshot.CPUQuotaUsec > 0 && snapshot.CPUPeriodUsec > 0 {
		if startConfig.Resources == nil {
			startConfig.Resources = make(map[string]float64)
		}
		startConfig.Resources["CPU"] = 1000 * float64(snapshot.CPUQuotaUsec) / float64(snapshot.CPUPeriodUsec)
	}
	mb := float64(snapshot.MemoryLimitBytes) / (1024 * 1024)
	if mb < 1 {
		return nil
	}
	if startConfig.Resources == nil {
		startConfig.Resources = make(map[string]float64)
	}
	// Trusted-restore ceiling admission: the scheduler reserves the elastic
	// CEILING for a named restore because restore loading (sentry page loads,
	// gofer, state deserialization) transiently needs more memory than the
	// steady-state working set; validateElasticResources already accepts any
	// effective limit within [initial, ceiling] for restores. The sidecar
	// records the SOURCE's checkpoint-time limit, which is typically the
	// initial floor — honoring it alone re-created the restore OOM this
	// feature exists to fix. For elastic restores keep the LARGER of the
	// caller's requested memory and the sidecar's, clamped to the (source's
	// winning) policy ceiling; the prepared-limit readback below still
	// records whatever is actually applied as birth evidence.
	if elastic {
		if caller, ok := startConfig.Resources["Memory"]; ok && caller > mb {
			var ceiling float64
			var policy elasticResourcePolicy
			if json.Unmarshal([]byte(startConfig.Labels[elasticResourcesLabel]), &policy) == nil &&
				policy.Memory.Ceiling >= mb && !math.IsNaN(policy.Memory.Ceiling) {
				ceiling = policy.Memory.Ceiling
			}
			if ceiling > 0 && caller > ceiling {
				caller = ceiling
			}
			if caller > mb {
				mb = caller
			}
		}
	}
	startConfig.Resources["Memory"] = mb
	return nil
}
