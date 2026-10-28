package server

import (
	"fmt"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// checkCheckpointResources runs with the original sandbox physical lock held.
func (h *sandboxService) checkCheckpointResources(id, generation string, revision uint64) error {
	actual, err := h.resourceStats(id)
	if err != nil {
		return fmt.Errorf("original checkpoint resource observation unavailable: %w: %v", errord.ErrFailedPrecondition, err)
	}
	if actual.ResourceGeneration != generation || !actual.ResourceRevisionKnown ||
		actual.ResourceRevision != revision || actual.ResourceOperationPending ||
		actual.MemoryCgroupPath == "" || !actual.FrozenKnown || actual.Frozen ||
		!actual.CpuLimitsKnown || !actual.MemoryLimitKnown {
		return fmt.Errorf("original checkpoint resource condition changed or unknown: %w", errord.ErrFailedPrecondition)
	}
	return nil
}
