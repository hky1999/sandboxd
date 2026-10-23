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

package cgroupmanager

import (
	"os"
	"path/filepath"
	"testing"

	cg "github.com/containerd/cgroups/v3/cgroup1"
	"github.com/stretchr/testify/require"
)

func TestV1DeleteSubsystemsCoMountedControllers(t *testing.T) {
	root := t.TempDir()
	name := "/sandbox/lease"
	shared := filepath.Join(root, "net_cls,net_prio")
	require.NoError(t, os.MkdirAll(filepath.Join(shared, name), 0755))
	for _, alias := range []string{"net_cls", "net_prio"} {
		require.NoError(t, os.Symlink(shared, filepath.Join(root, alias)))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(root, "memory", name), 0755))
	subsystems := []cg.Subsystem{
		cg.NewNetCls(root), cg.NewNetPrio(root), cg.NewMemory(root), cg.NewPids(root),
	}
	got, err := v1DeleteSubsystems(name, subsystems)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, cg.NetCLS, got[0].Name())
	require.Equal(t, cg.Memory, got[1].Name())
	// Simulate the first controller removal. The remaining memory controller
	// must still be reachable, and a retry must skip both missing aliases.
	require.NoError(t, os.Remove(filepath.Join(shared, name)))
	got, err = v1DeleteSubsystems(name, subsystems)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, cg.Memory, got[0].Name())
}

func TestV1DeleteSubsystemsKeepsSeparateHierarchies(t *testing.T) {
	root := t.TempDir()
	name := "/sandbox/lease"
	for _, controller := range []string{"net_cls", "net_prio"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, controller, name), 0755))
	}
	got, err := v1DeleteSubsystems(name, []cg.Subsystem{cg.NewNetCls(root), cg.NewNetPrio(root)})
	require.NoError(t, err)
	require.Len(t, got, 2)
}

func TestV1DeleteSubsystemsRejectsInvalidControllerPath(t *testing.T) {
	root := t.TempDir()
	name := "/sandbox/lease"
	path := filepath.Join(root, "pids", name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, nil, 0600))
	_, err := v1DeleteSubsystems(name, []cg.Subsystem{cg.NewPids(root)})
	require.ErrorContains(t, err, "not a directory")
}
