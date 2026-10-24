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
	"errors"
	"os"
	"path/filepath"
	"testing"

	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type recoveryLeaseOps struct {
	*fakeCgroupOps
	occupied  map[string]bool
	readError error
}

func (o recoveryLeaseOps) populated(id string) (bool, error) { return o.occupied[id], o.readError }

func TestRecoveryRetainsUnpersistedPopulatedCgroup(t *testing.T) {
	ops := recoveryLeaseOps{fakeCgroupOps: &fakeCgroupOps{}, occupied: map[string]bool{"/sandbox/live": true}}
	groups := cmap.New[struct{}]()
	groups.Set("/sandbox/live", struct{}{})
	groups.Set("/sandbox/empty", struct{}{})
	using, dirty, err := recoverUsingIDs(ops, "/sandbox", groups, nil)
	require.NoError(t, err)
	require.True(t, dirty)
	require.True(t, using.Has("/sandbox/live"))
	require.False(t, using.Has("/sandbox/empty"))
	require.Empty(t, ops.calls, "classification must not kill/reset an unrecorded live group")
}
func TestRecoveryPreservesPersistedOwnershipAndFiltersStaleIDs(t *testing.T) {
	ops := recoveryLeaseOps{fakeCgroupOps: &fakeCgroupOps{}}
	groups := cmap.New[struct{}]()
	groups.Set("/sandbox/owned", struct{}{})
	using, dirty, err := recoverUsingIDs(ops, "/sandbox", groups, []string{"/sandbox/owned", "/sandbox/gone", "/other/lease"})
	require.NoError(t, err)
	require.True(t, dirty)
	require.ElementsMatch(t, []string{"/sandbox/owned"}, using.Keys())
	require.Empty(t, ops.calls)
}
func TestRecoveryOccupancyFailureIsNotEmpty(t *testing.T) {
	failure := errors.New("cannot read process occupancy")
	ops := recoveryLeaseOps{fakeCgroupOps: &fakeCgroupOps{}, readError: failure}
	groups := cmap.New[struct{}]()
	groups.Set("/sandbox/unknown", struct{}{})
	_, _, err := recoverUsingIDs(ops, "/sandbox", groups, nil)
	require.ErrorIs(t, err, failure)
	require.Empty(t, ops.calls, "unknown state must fail before destructive cleanup")
}
func TestV2RecoveryOccupancyRequiresValidKernelState(t *testing.T) {
	for _, tc := range []struct {
		name, content              string
		exists, populated, wantErr bool
	}{
		{name: "empty", content: "populated 0\nfrozen 0\n", exists: true},
		{name: "live", content: "populated 1\nfrozen 0\n", exists: true, populated: true},
		{name: "missing file", wantErr: true},
		{name: "missing field", content: "frozen 0\n", exists: true, wantErr: true},
		{name: "invalid value", content: "populated 2\n", exists: true, wantErr: true},
		{name: "duplicate field", content: "populated 1\npopulated 0\n", exists: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mount := t.TempDir()
			group := filepath.Join(mount, "sandbox/live")
			require.NoError(t, os.MkdirAll(group, 0755))
			if tc.exists {
				require.NoError(t, os.WriteFile(filepath.Join(group, "cgroup.events"), []byte(tc.content), 0644))
			}
			occupied, err := (&cgroupV2{mountpoint: mount}).populated("/sandbox/live")
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.populated, occupied)
		})
	}
}
