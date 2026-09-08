// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runtime

import (
	"context"
	"errors"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
)

// Handler is the lifecycle boundary implemented by sandbox runtimes.
type Handler interface {
	Start(context.Context, StartConfig) error
	Delete(context.Context, string) error
	List(context.Context) ([]*State, error)
	Wait(context.Context, string) (Exit, error)
}

// CheckpointHandler is an optional capability implemented by runtimes that
// can save and restore caller-owned checkpoint artifacts.
type CheckpointHandler interface {
	Checkpoint(context.Context, CheckpointConfig) error
	Restore(context.Context, StartConfig) error
}

// ErrStartCleanupPending is joined into the error a runtime returns from a
// Start or Restore that failed after it had already spawned its processes,
// when it could not confirm their exit while rolling back. Such a runtime
// keeps the instance and its artifacts — persisted state, writable layer,
// runtime files — in place, best-effort persisting the incarnation identity
// it holds, so the sandbox can be reconciled or retired later. Callers must
// not release the resources they allocated for the start (sandbox ID,
// network, cgroup, filesystems) as if the runtime side were gone: a live
// process may still survive under the recorded identity, and reusing the ID
// could create a second incarnation. Detection is through errors.Is.
//
// The sentinel is a positive indication only, and it is defined solely for
// the direct runtime return value. Its absence proves nothing: runtimes that
// do not participate, older runtime versions, and any error conversion or
// wrapping layer in between can return an equivalent failure without it, so
// a caller must never turn a missing sentinel into a generic "no process
// survives" guarantee.
var ErrStartCleanupPending = errors.New("start cleanup pending")

// StrictDeleteHandler is an optional capability implemented by runtimes whose
// delete can prove it retired the runtime state of one exact physical
// generation. DeleteStrict must compare expectedGeneration against the
// runtime's own persisted incarnation identity before any state change,
// guest request, or signal; it must fail when the runtime holds no state for
// the sandbox (absence attests nothing) and when its state carries no bound
// generation (pre-generation records support only legacy deletion), and a
// mismatch must not touch the recorded process or its artifacts.
// Conditional (generation-checked) deletion requires this capability;
// runtimes without it keep only the legacy idempotent Delete.
type StrictDeleteHandler interface {
	DeleteStrict(ctx context.Context, sandboxID, expectedGeneration string) error
}

// StartFailureCleanupProver is an optional capability implemented by runtimes
// with an explicit failed-start contract. Such a runtime, when Start or
// Restore returns an error that does not join ErrStartCleanupPending, has
// already confirmed the exit of every process it spawned and either removed
// its own state or retained it behind the sentinel; the plain error is then a
// positive statement that the caller may release the resources it allocated
// for the start. A runtime without this capability proves nothing by failing:
// absence of the sentinel is not evidence, a legacy Delete's idempotent nil
// is not an exit proof, and such failed starts must be retained for
// reconciliation instead of unwound.
type StartFailureCleanupProver interface {
	StartFailureCleanupProven() bool
}

// CheckpointRestoreCapabilities describes the optional application-facing
// handoff interface exposed inside a restored sandbox. Empty paths mean the
// runtime supports transparent checkpoint/restore without application help.
type CheckpointRestoreCapabilities struct {
	CheckpointHandoffPath string
	RestoreEnvPath        string
}

// CheckpointRestoreCapabilitiesProvider optionally describes the guest-facing
// application handoff exposed by a CheckpointHandler.
type CheckpointRestoreCapabilitiesProvider interface {
	CheckpointRestoreCapabilities() CheckpointRestoreCapabilities
}

type CheckpointConfig struct {
	ID        string
	Directory string
	// CgroupPath is the runtime-owned source cgroup. It is internal runtime
	// metadata rather than a public checkpoint option.
	CgroupPath   string
	Compress     bool
	LeaveRunning bool
	// SnapshotType requests a specific checkpoint flavor ("Full",
	// "Incremental", or "SoftDirty" for Firecracker); empty leaves the
	// runtime's automatic tier selection in charge. Runtimes without
	// incremental checkpoints ignore it.
	SnapshotType string
}

// HostResourcesProvider maps guest-visible resources to the host cgroup that
// encloses a runtime process. VM handlers use it to retain private VMM
// headroom without changing resources exposed to the guest.
type HostResourcesProvider interface {
	HostResources(*runtime.LinuxSandboxResources) *runtime.LinuxSandboxResources
}

// StartRequestValidator rejects unsupported request sources before sandboxd
// prepares images and runtime resources.
type StartRequestValidator interface {
	ValidateStartRequest(*runtime.StartRequest) error
}

type StartConfig struct {
	ID                      string
	Hostname                string
	Command                 []string
	Mounts                  []*runtime.Mount
	Rootfs                  string
	RootfsReadonly          bool
	Resources               *runtime.LinuxSandboxResources
	Envs                    []*runtime.KeyValue
	Stdout                  string
	Stderr                  string
	Cwd                     string
	CgroupPath              string
	Annotations             map[string]string
	Network                 *networkmanager.NetResource
	DisableCgroup           bool
	SpecUpdates             *SpecUpdates
	WritableLayerLimitBytes uint64
	ExtraConfig             string
	EnableKVM               bool
	CheckpointDir           string
	// ResourceGeneration is the daemon-assigned physical incarnation
	// identity for this sandbox. The server generates it on every Start
	// (including restores) and runtimes that support generation-checked
	// deletion bind it into their own persisted state.
	ResourceGeneration string
	// ExpectedCheckpointRoot is the server-verified content root of the
	// checkpoint directory this restore consumes, set only by an admitted
	// start operation (StartWithOperation) whose admission bound the
	// artifacts. The legacy Start leaves it empty and nothing enforces it;
	// a runtime that accepts it must implement CheckpointRootVerifier and
	// recompute the root from the manifest view it actually opens before
	// creating resources or starting the VMM, refusing on mismatch.
	ExpectedCheckpointRoot string
}

// CheckpointRootVerifier is the capability contract for runtimes that enforce
// a server-admitted checkpoint content root at their restore boundary. A
// restore operation carrying an expected root is refused for runtimes
// without the capability instead of silently ignoring the binding.
type CheckpointRootVerifier interface {
	// SupportsCheckpointRootVerification reports whether the runtime verifies
	// StartConfig.ExpectedCheckpointRoot when restoring.
	SupportsCheckpointRootVerification() bool
}

// SpecUpdates contains provider-resolved OCI changes. Device providers use
// this boundary so vendor-specific discovery and authorization do not leak
// into the runsc client.
type SpecUpdates struct {
	Envs        []*runtime.KeyValue
	Prestart    []Hook
	Annotations map[string]string
	// RequiresHostWritableRootfs requests a private writable rootfs view
	// before provider hooks execute. It is separate from the writable layer
	// visible to workloads after the sandbox starts.
	RequiresHostWritableRootfs bool
}

func NewFakeRuntimeHandler() *FakeRuntimeHandler {
	return &FakeRuntimeHandler{}
}

type FakeRuntimeHandler struct{}

func (f *FakeRuntimeHandler) Start(ctx context.Context, _ StartConfig) error {
	return getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) Delete(ctx context.Context, _ string) error {
	return getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) List(ctx context.Context) ([]*State, error) {
	return []*State{}, getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) Wait(ctx context.Context, _ string) (Exit, error) {
	return Exit{
		ExitedAt: time.Time{},
		ExitCode: 0,
	}, getErrorFromContext(ctx)
}

func getErrorFromContext(ctx context.Context) error {
	if errStr, ok := ctx.Value("ERROR").(string); ok {
		return errors.New(errStr)
	}
	return nil
}

var _ Handler = &FakeRuntimeHandler{}
