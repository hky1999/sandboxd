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
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func fixtureNetworkLease() string {
	return (&networkmanager.NetResource{
		SchemaVersion: networkmanager.NetResourceSchemaVersion, EndpointType: networkmanager.EndpointTypeTap,
		GuestMAC: net.HardwareAddr{2, 0, 0, 0, 0, 5}, Interface: &net.Interface{Name: "tap.0a580005", Index: 7, HardwareAddr: net.HardwareAddr{2, 1, 0, 0, 0, 5}},
		Ip: net.ParseIP("10.88.0.5"), Mask: net.CIDRMask(16, 32), Gateway: net.ParseIP("10.88.0.1"), Type: "bridge",
	}).ToString()
}

func fixtureNetworkOwner(t *testing.T, root, id, lease string) string {
	t.Helper()
	bundle := filepath.Join(root, id)
	require.NoError(t, os.MkdirAll(bundle, 0700))
	meta, err := proto.Marshal(&runtimeapi.SandboxMetadata{ID: id, RuntimeHandler: config.RuntimeNameFirecracker})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bundle, config.SandboxMetaFile), meta, 0600))
	document := map[string]any{"ociVersion": "1.0.2", "futureExtension": map[string]any{"preserve": true}, "linux": map[string]any{"cgroupsPath": "/managed/old"}, "annotations": map[string]string{
		config.ResourceAnnotationKeyPrefix + config.ResourceNameInterface: lease,
		config.ResourceAnnotationKeyPrefix + config.ResourceNameCgroup:    "/managed/old", "caller.annotation": "preserved",
	}}
	data, err := json.Marshal(document)
	require.NoError(t, err)
	path := filepath.Join(bundle, config.SandboxSpecFile)
	require.NoError(t, os.WriteFile(path, data, 0640))
	return path
}

func fixtureNetworkPool(t *testing.T, db store.DbStore, leases ...string) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"items": leases, "futurePoolField": "preserved"})
	require.NoError(t, err)
	require.NoError(t, db.StoreRaw(config.BridgeIpBucket, data))
}

func poolLeases(t *testing.T, db store.DbStore) []string {
	t.Helper()
	data, err := db.LoadRaw(config.BridgeIpBucket)
	require.NoError(t, err)
	var doc struct {
		Items  []string `json:"items"`
		Future string   `json:"futurePoolField"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Equal(t, "preserved", doc.Future)
	return doc.Items
}

func ownerAnnotations(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc struct {
		Annotations map[string]string `json:"annotations"`
		Future      map[string]bool   `json:"futureExtension"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.True(t, doc.Future["preserve"])
	require.Equal(t, "preserved", doc.Annotations["caller.annotation"])
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0640), info.Mode().Perm())
	return doc.Annotations
}

func TestNetworkRetirementPreventsDelayedOldRelease(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "containers")
	lease := fixtureNetworkLease()
	old := fixtureNetworkOwner(t, root, "sbox-old", lease)
	db := store.NewMockStore()
	fixtureNetworkPool(t, db, lease)
	require.NoError(t, retireNetworkLeases(db, root, func(o networkLeaseOwner) bool { return o.id == "sbox-old" }, writeRetiredNetworkOwner))
	require.Empty(t, poolLeases(t, db))
	a := ownerAnnotations(t, old)
	require.NotContains(t, a, config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface)
	require.NotContains(t, a, retiredInterfaceAnnotation)
	require.Equal(t, "/managed/old", a[config.ResourceAnnotationKeyPrefix+config.ResourceNameCgroup])
	// The exact old network string can now be handed to a new owner. A late
	// cleanup reads the real OCI document through the sandbox manager.
	fixtureNetworkOwner(t, root, "sbox-new", lease)
	fixtureNetworkPool(t, db, lease)
	manager, err := sandbox.NewManager(parent, cmap.New[runtimecore.Handler](), make(chan bool, 1), nil, 10)
	require.NoError(t, err)
	defer manager.Stop()
	resources, err := manager.CollectResourceByID("sbox-old")
	require.NoError(t, err)
	require.NotContains(t, resources.Resources, config.ResourceNameInterface)
	checked := 0
	require.NoError(t, retireNetworkLeases(db, root, func(o networkLeaseOwner) bool { checked++; require.Equal(t, "sbox-new", o.id); return false }, writeRetiredNetworkOwner))
	require.Equal(t, 1, checked)
	require.Equal(t, []string{lease}, poolLeases(t, db))
}

type failingNetworkPool struct {
	store.DbStore
	failures int
}

func (db *failingNetworkPool) StoreRaw(key string, data []byte) error {
	if db.failures > 0 {
		db.failures--
		return errors.New("injected pool persistence failure")
	}
	return db.DbStore.StoreRaw(key, data)
}

func TestNetworkRetirementCrashBoundaries(t *testing.T) {
	for _, failure := range []string{"before-owner-write", "after-owner-write", "pool-write", "before-journal-finish", "after-journal-finish"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			lease := fixtureNetworkLease()
			path := fixtureNetworkOwner(t, root, "sbox-crash", lease)
			db := &failingNetworkPool{DbStore: store.NewMockStore()}
			fixtureNetworkPool(t, db, lease)
			if failure == "pool-write" {
				db.failures = 1
			}
			write := func(o networkLeaseOwner, retiring bool) error {
				if (retiring && failure == "before-owner-write") || (!retiring && failure == "before-journal-finish") {
					return errors.New("injected before write")
				}
				if err := writeRetiredNetworkOwner(o, retiring); err != nil {
					return err
				}
				if (retiring && failure == "after-owner-write") || (!retiring && failure == "after-journal-finish") {
					return errors.New("injected after durable write")
				}
				return nil
			}
			err := retireNetworkLeases(db, root, func(networkLeaseOwner) bool { return true }, write)
			require.Error(t, err)
			beforeCommit := failure == "before-owner-write" || failure == "after-owner-write" || failure == "pool-write"
			if beforeCommit {
				require.Equal(t, []string{lease}, poolLeases(t, db))
			} else {
				require.Empty(t, poolLeases(t, db))
			}
			ann := ownerAnnotations(t, path)
			if failure == "before-owner-write" {
				require.Equal(t, lease, ann[config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface])
			} else {
				require.NotContains(t, ann, config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface)
			}
			// Reconstruct from disk, not the previous call's maps. A committed
			// pool removal needs only journal finalization, not a new retirement.
			require.NoError(t, retireNetworkLeases(db, root, func(networkLeaseOwner) bool { require.True(t, beforeCommit); return true }, writeRetiredNetworkOwner))
			require.Empty(t, poolLeases(t, db))
			ann = ownerAnnotations(t, path)
			require.NotContains(t, ann, config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface)
			require.NotContains(t, ann, retiredInterfaceAnnotation)
		})
	}
}

func TestNetworkRetirementUnknownAndAmbiguousOwners(t *testing.T) {
	for _, mode := range []string{"unknown-runtime", "missing-metadata", "duplicate-owner", "malformed-spec"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			lease := fixtureNetworkLease()
			path := fixtureNetworkOwner(t, root, "sbox-one", lease)
			db := store.NewMockStore()
			fixtureNetworkPool(t, db, lease)
			switch mode {
			case "missing-metadata":
				require.NoError(t, os.Remove(filepath.Join(filepath.Dir(path), config.SandboxMetaFile)))
			case "duplicate-owner":
				fixtureNetworkOwner(t, root, "sbox-two", lease)
			case "malformed-spec":
				require.NoError(t, os.WriteFile(path, []byte("{"), 0640))
			}
			writes := 0
			err := retireNetworkLeases(db, root, func(networkLeaseOwner) bool { return false }, func(networkLeaseOwner, bool) error { writes++; return nil })
			if mode == "unknown-runtime" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Zero(t, writes)
			require.Equal(t, []string{lease}, poolLeases(t, db))
		})
	}
}

func TestNetworkRetirementKernelProofRequiresBothProcessAndGroup(t *testing.T) {
	for _, tc := range []struct {
		name, stat, events, group string
		gone, missingControllers  bool
		want                      bool
	}{
		{name: "gone process and missing group", group: "/managed/owned", gone: true, want: true},
		{name: "gone process empty group", group: "/managed/owned", gone: true, events: "populated 0\nfrozen 0\n", want: true},
		{name: "live process empty group", group: "/managed/owned", stat: "77 (vmm) S 1 2", events: "populated 0\n"},
		{name: "zombie and empty group", group: "/managed/owned", stat: "77 (vmm) Z 1 2", events: "populated 0\n", want: true},
		{name: "gone process live descendants", group: "/managed/owned", gone: true, events: "populated 1\n"},
		{name: "unknown events", group: "/managed/owned", gone: true, events: "frozen 0\n"},
		{name: "duplicate events", group: "/managed/owned", gone: true, events: "populated 0\npopulated 1\n"},
		{name: "foreign cgroup", group: "/other/owned", gone: true},
		{name: "root cgroup", group: "/managed", gone: true},
		{name: "v1 or inaccessible controllers", group: "/managed/owned", gone: true, missingControllers: true},
		{name: "unreadable process record", group: "/managed/owned", events: "populated 0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			proc := filepath.Join(base, "proc")
			cg := filepath.Join(base, "cgroup")
			require.NoError(t, os.MkdirAll(proc, 0700))
			require.NoError(t, os.MkdirAll(cg, 0700))
			if !tc.missingControllers {
				require.NoError(t, os.WriteFile(filepath.Join(cg, "cgroup.controllers"), []byte("cpu memory pids"), 0600))
			}
			if !tc.gone {
				require.NoError(t, os.MkdirAll(filepath.Join(proc, "77"), 0700))
				if tc.stat != "" {
					require.NoError(t, os.WriteFile(filepath.Join(proc, "77", "stat"), []byte(tc.stat), 0600))
				} else {
					require.NoError(t, os.Mkdir(filepath.Join(proc, "77", "stat"), 0700))
				}
			}
			if tc.events != "" {
				p := filepath.Join(cg, strings.TrimPrefix(tc.group, "/"), "cgroup.events")
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0700))
				require.NoError(t, os.WriteFile(p, []byte(tc.events), 0600))
			}
			require.Equal(t, tc.want, retiredRuntimeHasNoTasks(77, tc.group, "/managed", proc, cg))
		})
	}
	require.False(t, retiredRuntimeHasNoTasks(0, "/managed/owned", "/managed", t.TempDir(), t.TempDir()))
}
