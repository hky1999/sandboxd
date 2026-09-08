package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// Compile in sandboxd/internal/server against real production methods.
// No artifact exists: lookup alone must never retire a physical record.
func TestRestoreLookupDoesNotDeleteWithoutArtifactProof(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "lookup-owned-source"
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID: id, RuntimeHandler: "runsc",
		PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
		Labels:        map[string]string{resourceGenerationLabel: "generation-one"},
	}))
	require.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
	dir := filepath.Join(s.config.RootDir, "containers", id)
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"ociVersion":"1.0.2","process":{"args":["/init"]},"root":{"path":"rootfs"},"linux":{}}`), 0644))
	_, _, _ = s.existingRestorePhysicalFact(context.Background(), &runtime.StartRequest{SandboxID: id, Runtime: "runsc"}, &runtime.RestoreIdentity{CheckpointID: "unverified-artifact", RequestSha256: "request-digest"})
	require.Zero(t, handler.calls, "a replay lookup must not invoke physical deletion")
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err, "lookup must retain the source record")
	require.Equal(t, "generation-one", current.Metadata.Labels[resourceGenerationLabel])
}

func TestRestoreLookupDoesNotReturnExitedReplayAsLiveSuccess(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	const id = "lookup-exited-replay"
	identity := &runtime.RestoreIdentity{CheckpointID: "checkpoint", RequestSha256: "digest"}
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID: id, RuntimeHandler: "runsc",
		PhysicalPhase:   runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
		RestoreIdentity: identity,
		Labels:          map[string]string{resourceGenerationLabel: "generation-two"},
	}))
	require.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
	response, _, err := s.existingRestorePhysicalFact(context.Background(), &runtime.StartRequest{SandboxID: id, Runtime: "runsc"}, identity)
	require.Error(t, err, "EXITED is not a live restore result")
	require.Nil(t, response)
}
