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
	"os"
	"path/filepath"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
)

// Handler is the lifecycle boundary implemented by sandbox runtimes.
type Handler interface {
	Start(context.Context, StartConfig) error
	Delete(context.Context, string) error
	List(context.Context) ([]*State, error)
	Wait(context.Context, string) (Exit, error)
}

// ManagedCheckpointHandler is an optional runtime capability. Keeping it out
// of Handler allows runtimes without native checkpoint support to remain
// unchanged and lets the server report Unimplemented explicitly.
type ManagedCheckpointHandler interface {
	Checkpoint(context.Context, string, string, CheckpointOptions) error
	Restore(context.Context, StartConfig, string) error
}

// PreparedStateCleaner is an optional runtime capability for removing local
// physical preparation after List confirms that no runtime exists. It avoids
// imposing absent-runtime Delete semantics on every Handler implementation.
type PreparedStateCleaner interface {
	CleanupPreparedState(context.Context, string) error
}

// CheckpointOptions describes physical checkpoint behavior. It is kept at
// the optional runtime capability boundary so runtimes without checkpoint
// support do not need to understand it.
type CheckpointOptions struct {
	LeaveRunning bool
	// IncludeFilesystem additionally captures the runtime writable layer
	// so a restore reproduces the workload's on-disk state. Both artifacts
	// are taken at one paused consistency point.
	IncludeFilesystem bool
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

func NewHandler(cfg config.Config, bin, runtimeName string) (Handler, error) {
	if _, err := os.Stat(bin); err != nil {
		return nil, err
	}

	sandboxRoot := filepath.Join(cfg.RootDir, "containers")
	switch runtimeName {
	case config.RuntimeNameRunsc:
		if cfg.RuntimeConfig.BasicSpec == nil {
			cfg.RuntimeConfig.BasicSpec = make(map[string]string)
		}
		loader, err := NewBundleLoader(cfg.RuntimeConfig.BasicSpec[config.RuntimeNameRunsc], sandboxRoot)
		if err != nil {
			return nil, err
		}
		return NewRunscHandler(cfg, bin, loader)
	case config.RuntimeNameKata:
		loader, err := NewBundleLoader("", sandboxRoot)
		if err != nil {
			return nil, err
		}
		return NewKataHandler(cfg, bin, loader)
	default:
		return nil, errord.ErrNotImplemented
	}
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

// ErrRestoreCleanupIncomplete marks a failed restore whose runtime deletion
// could not be confirmed. Callers must retain the physical intent and its
// prepared resources so reconciliation can still locate and remove the exact
// runtime after restart or retry.
var ErrRestoreCleanupIncomplete = errors.New("restore runtime cleanup is incomplete")
