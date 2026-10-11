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

package server

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareRequiredStartResourcesPreservesPartialOwnership(t *testing.T) {
	allocationErr := errors.New("allocation reply lost")
	resources, err := prepareRequiredStartResources("sbox-partial",
		[]string{"successful", "uncertain"},
		func(name string) (string, *networkmanager.NetResource, error) {
			if name == "uncertain" {
				return "uncertain-lease", nil, allocationErr
			}
			return "original-lease", nil, nil
		})
	require.ErrorIs(t, err, allocationErr)
	require.NotNil(t, resources, "an allocation error must not discard known ownership")
	require.Equal(t, map[string]string{"successful": "original-lease", "uncertain": "uncertain-lease"}, resources.Resources)
}

type partialPreparationCgroups struct {
	*resizeCgroups
	releases            int
	allocatedGeneration string
}

func (*partialPreparationCgroups) Allocate() (string, error) { return "/sandbox/partial-lease", nil }
func (m *partialPreparationCgroups) AllocateForGeneration(generation string) (string, error) {
	m.allocatedGeneration = generation
	return m.Allocate()
}
func (m *partialPreparationCgroups) RecycleForGeneration(path, _ string) error {
	return m.Recycle(path)
}
func (m *partialPreparationCgroups) Recycle(string) error {
	m.releases++
	return errors.New("cgroup cleanup failed")
}

func TestCreateSandboxPersistsPartialResourcesAfterPreparationFailure(t *testing.T) {
	handler := svc.NewFakeRuntimeHandler()
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	s.fsMgr = newFSManager(nil, store.NewStoreImp(filepath.Join(s.config.RootDir, "fs.db")))
	cgroups := &partialPreparationCgroups{resizeCgroups: &resizeCgroups{}}
	s.cgroupMgr = cgroups
	id := "sbox-partial-preparation"
	_, err := s.createSandbox(context.Background(), &runtime.StartRequest{
		SandboxID: id, Runtime: "runsc",
		Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL, Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
	}, createOptions{})
	require.ErrorContains(t, err, "interface manager not configured")
	require.Zero(t, cgroups.releases, "preparation failure must preserve resources for durable reconciliation")
	intents := s.sandboxManager.ListPhysicalIntents()
	require.Len(t, intents, 1)
	require.Equal(t, map[string]string{config.ResourceNameCgroup: "/sandbox/partial-lease"}, intents[0].ResourceFacts)
	require.NotEmpty(t, intents[0].Labels[resourceGenerationLabel])
	require.Equal(t, intents[0].Labels[resourceGenerationLabel], cgroups.allocatedGeneration)
	require.FileExists(t, filepath.Join(s.config.RootDir, "containers", id, config.SandboxMetaFile))
	_, reserveErr := s.sandboxManager.ReserveID(id)
	require.Error(t, reserveErr)

	// Reopening the real manager must recover the same ownership without
	// depending on the failed request's stack or a log message.
	reopened, openErr := sandbox.NewManager(s.config.RootDir, s.serviceHandler, make(chan bool, 10), nil, 1000)
	require.NoError(t, openErr)
	recovered := reopened.ListPhysicalIntents()
	require.Len(t, recovered, 1)
	require.Equal(t, intents[0].ResourceFacts, recovered[0].ResourceFacts)
	require.Equal(t, intents[0].Labels[resourceGenerationLabel], recovered[0].Labels[resourceGenerationLabel])
	reopenedFS := newFSManager(nil, store.NewStoreImp(filepath.Join(s.config.RootDir, "fs.db")))
	require.NoError(t, reopenedFS.Restore(reopened.HasPhysicalRecord))
	_, fsErr := reopenedFS.RootfsConfig(id)
	require.NoError(t, fsErr, "successful filesystem ownership must survive a peer allocation failure")
}

func TestRequiredStartResourcesWithoutCgroup(t *testing.T) {
	resources, err := requiredStartResources(config.RuntimeNameRunsc, true)
	require.NoError(t, err)
	assert.Equal(t, []string{config.ResourceNameInterface}, resources)
}

func TestRequiredStartResourcesWithCgroup(t *testing.T) {
	resources, err := requiredStartResources(config.RuntimeNameRunsc, false)
	require.NoError(t, err)
	assert.Equal(t, config.RuntimeResources[config.RuntimeNameRunsc], resources)
}

func TestFirecrackerRequiresCgroup(t *testing.T) {
	_, err := requiredStartResources(config.RuntimeNameFirecracker, true)
	require.ErrorContains(t, err, "requires cgroup management")

	resources, err := requiredStartResources(config.RuntimeNameFirecracker, false)
	require.NoError(t, err)
	assert.Equal(t, config.RuntimeResources[config.RuntimeNameFirecracker], resources)
}

func TestPrepareRequiredStartResourcesReturnsErrorInDeclaredOrder(t *testing.T) {
	secondFinished := make(chan struct{})
	resultCh := make(chan error, 1)

	go func() {
		_, err := prepareRequiredStartResources(
			"sandbox-id",
			[]string{"first", "second"},
			func(name string) (string, *networkmanager.NetResource, error) {
				if name == "first" {
					<-secondFinished
					return "", nil, errors.New("first error")
				}
				close(secondFinished)
				return "", nil, errors.New("second error")
			},
		)
		resultCh <- err
	}()

	select {
	case err := <-resultCh:
		require.ErrorContains(t, err, "allocate resource first failed: first error")
	case <-time.After(5 * time.Second):
		t.Fatal("resource allocations did not run concurrently")
	}
}

func TestPrepareRequiredStartResourcesReturnsSuccessfulAllocationsToOwner(t *testing.T) {
	var mu sync.Mutex
	allocated := make(map[string]struct{})

	resources, err := prepareRequiredStartResources(
		"sandbox-id",
		[]string{"successful", "broken"},
		func(name string) (string, *networkmanager.NetResource, error) {
			mu.Lock()
			allocated[name] = struct{}{}
			mu.Unlock()
			if name == "broken" {
				return "", nil, errors.New("allocation failed")
			}
			return "resource-value", nil, nil
		},
	)

	require.ErrorContains(t, err, "allocate resource broken failed: allocation failed")
	require.NotNil(t, resources)
	assert.Equal(t, map[string]struct{}{
		"successful": {},
		"broken":     {},
	}, allocated)
	assert.Equal(t, "sandbox-id", resources.ID)
	assert.Equal(t, map[string]string{"successful": "resource-value"}, resources.Resources)
}
