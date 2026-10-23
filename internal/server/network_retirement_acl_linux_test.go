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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

type networkRetirementRuntime struct {
	*runtimecore.FakeRuntimeHandler
	state *runtimecore.State
	err   error
}

func (h *networkRetirementRuntime) List(context.Context) ([]*runtimecore.State, error) {
	if h.err != nil {
		return nil, h.err
	}
	return []*runtimecore.State{h.state}, nil
}

func networklessACLFixture(t *testing.T) (*sandboxService, *networkRetirementRuntime) {
	t.Helper()
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		if os.Getenv("SANDBOXD_NETWORK_RETIREMENT_KERNEL_TEST") == "1" {
			t.Fatal("explicit cgroup-v2 proof test prerequisite missing", err)
		}
		t.Skip("automatic kernel retirement requires cgroup v2")
	}
	id := "sbox-acl-retired"
	provider := &networkRetirementRuntime{FakeRuntimeHandler: runtimecore.NewFakeRuntimeHandler(), state: &runtimecore.State{ID: id, InitProcessPid: 1 << 30, Status: runtimecore.SandboxStatusExited}}
	h := newTestService(t, map[string]runtimecore.Handler{config.RuntimeNameFirecracker: provider})
	t.Cleanup(h.sandboxManager.Stop)
	groupRoot := "/__sandboxd_retirement_test_" + filepath.Base(t.TempDir())
	group := groupRoot + "/old"
	_, err := os.Lstat(filepath.Join("/sys/fs/cgroup", groupRoot))
	require.True(t, os.IsNotExist(err), "proof fixture must never reference an existing cgroup")
	h.config.CgroupRootName = groupRoot
	h.cgroupMgr = &cgroupmanager.CgroupManager{}
	path := fixtureNetworkOwner(t, filepath.Join(h.config.RootDir, "containers"), id, fixtureNetworkLease())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	a := doc["annotations"].(map[string]any)
	delete(a, config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface)
	a[config.ResourceAnnotationKeyPrefix+config.ResourceNameCgroup] = group
	doc["linux"].(map[string]any)["cgroupsPath"] = group
	data, err = json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0640))
	require.NoError(t, h.sandboxManager.StoreMetadata(id, &runtimeapi.SandboxMetadata{ID: id, RuntimeHandler: config.RuntimeNameFirecracker}))
	return h, provider
}

func TestNetworkRetirementACLRestoresKnownExitedOwner(t *testing.T) {
	h, _ := networklessACLFixture(t)
	bindings, err := h.activeACLBindings()
	require.NoError(t, err, "a proven exited runtime with a retired network claim must not prevent ACL startup")
	require.Empty(t, bindings)
}

func TestNetworkRetirementACLPreservesUnknownAndLiveGuards(t *testing.T) {
	for _, mode := range []string{"live-process", "running-state", "list-error", "unmanaged"} {
		t.Run(mode, func(t *testing.T) {
			h, provider := networklessACLFixture(t)
			switch mode {
			case "live-process":
				provider.state.InitProcessPid = os.Getpid()
			case "running-state":
				provider.state.Status = runtimecore.SandboxStatusRunning
			case "list-error":
				provider.err = errors.New("injected unavailable runtime")
			case "unmanaged":
				h.config.DisableCgroup = true
			}
			_, err := h.activeACLBindings()
			require.ErrorContains(t, err, "has no network resource")
		})
	}
}
