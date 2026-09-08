package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

// W7-P1.1: the resource-limits sidecar overrides the restore request's
// memory booking; missing/corrupt sidecar keeps legacy behavior.
func TestApplyCheckpointResourceLimits(t *testing.T) {
	dir := t.TempDir()
	req := &runtime.StartRequest{Resources: map[string]float64{"Memory": 32768}}

	// no sidecar: unchanged
	applyCheckpointResourceLimits(req, dir)
	assert.Equal(t, float64(32768), req.Resources["Memory"])

	// sidecar with 6GiB
	assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
		[]byte(`{"memory_limit_bytes":6442450944}`), 0o600))
	applyCheckpointResourceLimits(req, dir)
	assert.Equal(t, float64(6144), req.Resources["Memory"])

	// corrupt sidecar: no-op, no panic
	assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
		[]byte("not json"), 0o600))
	req.Resources["Memory"] = 32768
	applyCheckpointResourceLimits(req, dir)
	assert.Equal(t, float64(32768), req.Resources["Memory"])

	// sub-MiB value: no-op
	assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
		[]byte(`{"memory_limit_bytes":512}`), 0o600))
	applyCheckpointResourceLimits(req, dir)
	assert.Equal(t, float64(32768), req.Resources["Memory"])

	// nil resources map is created on demand
	req2 := &runtime.StartRequest{}
	assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
		[]byte(`{"memory_limit_bytes":6442450944}`), 0o600))
	applyCheckpointResourceLimits(req2, dir)
	assert.Equal(t, float64(6144), req2.Resources["Memory"])
}

// W7-P1.2, revised: the read-only lookup neither deletes a park leftover nor
// lets it replay. An EXITED record with a foreign restore identity is only
// reported as a cleanup candidate; deletion is deferred to the verified
// cleanup admission, so the record and its runtime are retained here.
func TestExistingRestorePhysicalFact_ParkLeftoverRetainedReadonly(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "sbox-park-leftover"
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
	}))
	assert.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))

	identity := &runtime.RestoreIdentity{CheckpointID: "ckpt-1", RequestSha256: "abc"}
	resp, found, err := s.existingRestorePhysicalFact(context.Background(), &runtime.StartRequest{SandboxID: id}, identity)
	assert.ErrorIs(t, err, errRestoreParkedSourceCandidate)
	assert.True(t, found)
	assert.Nil(t, resp, "a cleanup candidate must not be answered with a live fact")
	assert.Zero(t, handler.calls, "the read-only lookup must not delete")
	_, gerr := s.sandboxManager.Get(id)
	assert.NoError(t, gerr, "the parked record must stay for verified cleanup")
}

// W7-P1.2: an idempotent replay (same restore identity on a live sandbox)
// still returns the existing physical fact. RUNNING is staged as an explicit
// durable status, not the load-time default for a missing status file.
func TestExistingRestorePhysicalFact_IdempotentReplay(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	const id = "sbox-restored"
	identity := &runtime.RestoreIdentity{CheckpointID: "ckpt-1", RequestSha256: "abc"}
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:              id,
		RuntimeHandler:  "runsc",
		PhysicalPhase:   runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
		RestoreIdentity: identity,
	}))
	markSandboxRunning(t, s, id)
	resp, found, err := s.existingRestorePhysicalFact(context.Background(),
		&runtime.StartRequest{SandboxID: id, Runtime: "runsc"},
		proto.Clone(identity).(*runtime.RestoreIdentity))
	assert.NoError(t, err)
	assert.True(t, found)
	assert.NotNil(t, resp)
}

// W7-P1.2: a live sandbox with a never-restored record refuses the restore
// with a clear error instead of the old opaque replay-conflict message.
func TestExistingRestorePhysicalFact_LiveSandboxRefused(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	const id = "sbox-live"
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
	}))
	markSandboxRunning(t, s, id)
	identity := &runtime.RestoreIdentity{CheckpointID: "ckpt-1", RequestSha256: "abc"}
	_, found, err := s.existingRestorePhysicalFact(context.Background(), &runtime.StartRequest{SandboxID: id}, identity)
	assert.Error(t, err)
	assert.False(t, errors.Is(err, errRestoreParkedSourceCandidate),
		"a live sandbox is never a cleanup candidate")
	assert.True(t, found)
}

func TestCheckpointRestoresEffectiveCPULimit(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		want       float64
	}{
		{"initial-half-core", `{"cpu_quota_usec":50000,"cpu_period_usec":100000,"cpu_limits_known":true}`, 500},
		{"raised-fractional", `{"cpu_quota_usec":125000,"cpu_period_usec":100000,"cpu_limits_known":true}`, 1250},
		{"unknown-keeps-booking", `{"cpu_quota_usec":50000,"cpu_period_usec":100000}`, 8000},
		{"invalid-period", `{"cpu_quota_usec":50000,"cpu_period_usec":0,"cpu_limits_known":true}`, 8000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile), []byte(tc.data), 0600))
			req := &runtime.StartRequest{Resources: map[string]float64{"CPU": 8000, "Memory": 512}}
			applyCheckpointResourceLimits(req, dir)
			assert.Equal(t, tc.want, req.Resources["CPU"])
			assert.Equal(t, float64(512), req.Resources["Memory"])
		})
	}
}
