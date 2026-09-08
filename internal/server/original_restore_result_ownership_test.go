package server

import (
	"context"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/require"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
)

type restoreWaitBoundaryContext struct {
	context.Context
	once    sync.Once
	atWait  func()
	entered bool
}

func (c *restoreWaitBoundaryContext) Done() <-chan struct{} {
	pcs := make([]uintptr, 16)
	n := goruntime.Callers(1, pcs)
	frames := goruntime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if strings.Contains(frame.Function, "checkpointstate.(*Attempt).Wait") {
			c.once.Do(func() { c.entered = true; c.atWait() })
			break
		}
		if !more {
			break
		}
	}
	return c.Context.Done()
}
func TestOriginalRestoreCompletionMustNotAdoptForeignPhysicalRecord(t *testing.T) {
	s, _ := newRestoreCleanupService(t)
	const id = "restore-result-owner"
	directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity("source", "source-generation", "result-checkpoint"))
	req := restoreCleanupRequest(directory, fact, id, t.TempDir())
	normalized, err := normalizeRestoreConfig(req.Config)
	require.NoError(t, err)
	fingerprint, err := restoreFingerprint(normalized, req.CheckpointID)
	require.NoError(t, err)
	attempt, execute, err := s.checkpointState.BeginRestore(id, fingerprint)
	require.NoError(t, err)
	require.True(t, execute)
	ctx := &restoreWaitBoundaryContext{Context: context.Background()}
	ctx.atWait = func() {
		require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{ID: id, RuntimeHandler: "runsc", Labels: map[string]string{resourceGenerationLabel: "foreign-generation"}, RestoreIdentity: &runtime.RestoreIdentity{CheckpointID: "foreign-checkpoint", RequestSha256: "foreign-fingerprint"}}))
		markSandboxRunning(t, s, id)
		s.checkpointState.Complete(attempt, nil)
	}
	response, err := s.Restore(ctx, req)
	require.True(t, ctx.entered, "test must reach the real attempt.Wait boundary")
	require.Error(t, err, "old restore completion must not adopt foreign generation")
	require.Nil(t, response)
	current, getErr := s.sandboxManager.Get(id)
	require.NoError(t, getErr)
	require.Equal(t, "foreign-generation", current.Metadata.Labels[resourceGenerationLabel])
}
