// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/protobuf/proto"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/stretchr/testify/require"
)

func TestFSOwnershipRejectsDamagedJournalBeforeRecovery(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"source changed", func(j map[string]any) {
			j["items"].(map[string]any)["original"].(map[string]any)["oci"] = []string{"registry.example/replacement:latest"}
		}},
		{"generation changed", func(j map[string]any) {
			j["items"].(map[string]any)["original"].(map[string]any)["generation"] = "replacement-generation"
		}},
		{"owner changed", func(j map[string]any) {
			items := j["items"].(map[string]any)
			items["replacement"] = items["original"]
			delete(items, "original")
		}},
		{"source omitted", func(j map[string]any) {
			state := j["items"].(map[string]any)["original"].(map[string]any)
			delete(state, "oci")
			delete(state, "oci_phases")
		}},
		{"entire inventory omitted", func(j map[string]any) { j["items"] = map[string]any{} }},
		{"phase changed", func(j map[string]any) {
			j["items"].(map[string]any)["original"].(map[string]any)["rootfs_phase"] = "released"
		}},
		{"downgraded to legacy", func(j map[string]any) { j["schema_version"] = 0 }},
		{"schema omitted", func(j map[string]any) { delete(j, "schema_version") }},
		{"unknown field", func(j map[string]any) { j["unexpected_field"] = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newOwnershipStore(t)
			service := newOwnershipImageService()
			m := newFSManager(service, st)
			request := fsTestStartRequest("original")
			request.Labels = map[string]string{resourceGenerationLabel: "original-generation"}
			prepared, err := m.Prepare(request)
			require.NoError(t, err)
			require.NoError(t, m.Commit("original", prepared))
			original, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			var journal map[string]any
			require.NoError(t, json.Unmarshal(original, &journal))
			tc.mutate(journal)
			damaged, err := json.Marshal(journal)
			require.NoError(t, err)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, damaged))
			reopened := newFSManager(service, st)
			require.Error(t, reopened.Restore(func(string) bool { return false }), "invalid journal must not authorize reconstruction or orphan cleanup")
			reopened.Shutdown()
			current, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			require.Equal(t, damaged, current, "failed recovery and shutdown must preserve the original bytes")
			require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
			require.Equal(t, 1, service.mountCalls("registry.example/data:latest"))
			require.Zero(t, service.mountCalls("registry.example/replacement:latest"))
			require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
			require.Zero(t, service.umountCalls("registry.example/data:latest"))
		})
	}
}

func TestFSOwnershipRejectsDuplicateJSONKeys(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	prepared, err := m.Prepare(fsTestStartRequest("original"))
	require.NoError(t, err)
	require.NoError(t, m.Commit("original", prepared))
	original, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	damaged := bytes.Replace(original, []byte("{"), []byte(`{"schema_version":0,`), 1)
	require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, damaged))
	reopened := newFSManager(service, st)
	require.Error(t, reopened.Restore(func(string) bool { return true }))
	reopened.Shutdown()
	current, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	require.Equal(t, damaged, current)
	require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
}

func TestFSOwnershipLegacySourceMigrationKeepsGenerationUnknown(t *testing.T) {
	for _, explicitVersion := range []bool{false, true} {
		t.Run(map[bool]string{false: "original format", true: "explicit zero"}[explicitVersion], func(t *testing.T) {
			st := newOwnershipStore(t)
			service := newOwnershipImageService()
			request := fsTestStartRequest("legacy-owner")
			rootfs, err := proto.Marshal(request.Rootfs)
			require.NoError(t, err)
			item := map[string]any{"rootfs": rootfs, "oci": []string{"registry.example/data:latest"}}
			journal := map[string]any{"items": map[string]any{request.SandboxID: item}}
			if explicitVersion {
				journal["schema_version"] = 0
			}
			data, err := json.Marshal(journal)
			require.NoError(t, err)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, data))
			restored := newFSManager(service, st)
			require.NoError(t, restored.Restore(func(string) bool { return true }))
			require.Error(t, restored.ReleaseIfGeneration(request.SandboxID, "adopted-generation"))
			data, err = st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			decoded, err := decodeFSJournal(data)
			require.NoError(t, err)
			require.Equal(t, fsJournalSchema, decoded.SchemaVersion)
			require.Empty(t, decoded.Items[request.SandboxID].Generation)
			require.NotEmpty(t, decoded.Items[request.SandboxID].SourceFingerprint)
			reopened := newFSManager(service, st)
			require.NoError(t, reopened.Restore(func(string) bool { return true }))
			require.NoError(t, reopened.Release(request.SandboxID))
			require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
			require.Equal(t, 1, service.umountCalls("registry.example/data:latest"))
		})
	}
}

func TestFSOwnershipNonemptySchemaTwoRequiresIndependentMigration(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "active owner", true: "completed receipt"}[completed], func(t *testing.T) {
			st := newOwnershipStore(t)
			service := newOwnershipImageService()
			m := newFSManager(service, st)
			req := fsTestStartRequest("schema-two-owner")
			req.Labels = map[string]string{resourceGenerationLabel: "old-generation"}
			prepared, err := m.Prepare(req)
			require.NoError(t, err)
			require.NoError(t, m.Commit(req.SandboxID, prepared))
			if completed {
				require.NoError(t, m.ReleaseIfGeneration(req.SandboxID, "old-generation"))
			}
			data, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			var journal map[string]any
			require.NoError(t, json.Unmarshal(data, &journal))
			journal["schema_version"] = 2
			delete(journal, "integrity_sha256")
			for _, item := range journal["items"].(map[string]any) {
				delete(item.(map[string]any), "source_fingerprint")
			}
			data, err = json.Marshal(journal)
			require.NoError(t, err)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, data))
			reopened := newFSManager(service, st)
			require.Error(t, reopened.Restore(func(string) bool { return false }))
			require.Error(t, reopened.ReleaseIfGeneration(req.SandboxID, "old-generation"))
			reopened.Shutdown()
			current, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			require.Equal(t, data, current)
			require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
			require.Equal(t, map[bool]int{false: 0, true: 1}[completed], service.umountCalls("registry.example/rootfs:latest"))
		})
	}
}

func TestFSOwnershipEmptySchemaTwoCanUpgrade(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, []byte(`{"schema_version":2,"items":{},"completed":{}}`)))
	m := newFSManager(service, st)
	require.NoError(t, m.Restore(func(string) bool { return true }))
	data, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	_, err = decodeFSJournal(data)
	require.NoError(t, err)
	prepared, err := m.Prepare(fsTestStartRequest("new-owner"))
	require.NoError(t, err)
	require.NoError(t, m.Commit("new-owner", prepared))
}

func TestFSOwnershipSourceFingerprintRejectsChangedResealedSource(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	prepared, err := m.Prepare(fsTestStartRequest("original"))
	require.NoError(t, err)
	require.NoError(t, m.Commit("original", prepared))
	data, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	var journal storedSandboxFSStates
	require.NoError(t, json.Unmarshal(data, &journal))
	state := journal.Items["original"]
	state.OCI[0] = "registry.example/replacement:latest"
	journal.Items["original"] = state
	journal.IntegritySHA256, err = fsJournalIntegrity(journal)
	require.NoError(t, err)
	data, err = json.Marshal(journal)
	require.NoError(t, err)
	require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, data))
	reopened := newFSManager(service, st)
	require.Error(t, reopened.Restore(func(string) bool { return false }))
	require.Zero(t, service.mountCalls("registry.example/replacement:latest"))
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
}

func TestFSOwnershipReceiptIntegrityRejectsChangedOrMissingCompletion(t *testing.T) {
	for _, kind := range []string{"removed", "changed identity", "changed source"} {
		t.Run(kind, func(t *testing.T) {
			st := newOwnershipStore(t)
			service := newOwnershipImageService()
			m := newFSManager(service, st)
			req := fsTestStartRequest("retired")
			req.Labels = map[string]string{resourceGenerationLabel: "original-generation"}
			prepared, err := m.Prepare(req)
			require.NoError(t, err)
			require.NoError(t, m.Commit(req.SandboxID, prepared))
			require.NoError(t, m.ReleaseIfGeneration(req.SandboxID, "original-generation"))
			data, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			var journal storedSandboxFSStates
			require.NoError(t, json.Unmarshal(data, &journal))
			key := fsCompletionKey(req.SandboxID, "original-generation")
			receipt := journal.Completed[key]
			switch kind {
			case "removed":
				delete(journal.Completed, key)
			case "changed identity":
				delete(journal.Completed, key)
				receipt.Generation = "replacement-generation"
				journal.Completed[fsCompletionKey(req.SandboxID, receipt.Generation)] = receipt
			case "changed source":
				receipt.SourceFingerprint = strings.Repeat("0", 64)
				journal.Completed[key] = receipt
			}
			data, err = json.Marshal(journal)
			require.NoError(t, err)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, data))
			reopened := newFSManager(service, st)
			require.Error(t, reopened.Restore(func(string) bool { return true }))
			require.Error(t, reopened.ReleaseIfGeneration(req.SandboxID, "original-generation"))
			require.Error(t, reopened.ReleaseIfGeneration(req.SandboxID, "replacement-generation"))
			reopened.Shutdown()
			current, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			require.Equal(t, data, current)
			require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
			require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
		})
	}
}

func TestFSOwnershipInvalidSourceRejectedBeforeReservation(t *testing.T) {
	cases := []*runtime.RootfsConfig{
		{Type: runtime.RootfsSrcType_IMAGE, Source: &runtime.RootfsConfig_Path{Path: "/caller-owned"}},
		{Type: runtime.RootfsSrcType_IMAGE, Source: &runtime.RootfsConfig_ImageUrl{ImageUrl: " "}},
		{Type: runtime.RootfsSrcType_S3, Source: &runtime.RootfsConfig_S3Config{S3Config: &runtime.S3Config{Endpoint: "endpoint", Bucket: "bucket"}}},
		{Type: runtime.RootfsSrcType_LOCAL},
	}
	for i, rootfs := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			st := newOwnershipStore(t)
			service := newOwnershipImageService()
			m := newFSManager(service, st)
			req := fsTestStartRequest("invalid")
			req.Rootfs = rootfs
			prepared, err := m.Prepare(req)
			require.Error(t, err)
			require.Nil(t, prepared)
			_, err = st.LoadRaw(config.SandboxFSStateBucket)
			require.Error(t, err)
			require.Empty(t, m.sandboxState)
			require.Zero(t, service.mountCalls("registry.example/rootfs:latest"))
			require.Zero(t, service.mountCalls("registry.example/data:latest"))
		})
	}
}

func TestFSOwnershipLegacyRejectsNewOwnershipFields(t *testing.T) {
	for _, field := range []string{"generation", "rootfs_phase", "s3_phases", "oci_phases", "source_fingerprint"} {
		t.Run(field, func(t *testing.T) {
			st := newOwnershipStore(t)
			service := newOwnershipImageService()
			rootfs, err := proto.Marshal(fsTestStartRequest("legacy").Rootfs)
			require.NoError(t, err)
			item := map[string]any{"rootfs": rootfs, field: ""}
			data, err := json.Marshal(map[string]any{"items": map[string]any{"legacy": item}})
			require.NoError(t, err)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, data))
			m := newFSManager(service, st)
			require.Error(t, m.Restore(func(string) bool { return false }))
			m.Shutdown()
			current, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			require.Equal(t, data, current)
			require.Zero(t, service.mountCalls("registry.example/rootfs:latest"))
			require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
		})
	}
}

func TestFSOwnershipInvalidLegacySourceStopsAllReconstruction(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	valid, err := proto.Marshal(fsTestStartRequest("a-valid").Rootfs)
	require.NoError(t, err)
	invalid, err := proto.Marshal(&runtime.RootfsConfig{Type: runtime.RootfsSrcType_IMAGE, Source: &runtime.RootfsConfig_Path{Path: "/caller-owned"}})
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{"items": map[string]any{"a-valid": map[string]any{"rootfs": valid}, "z-invalid": map[string]any{"rootfs": invalid}}})
	require.NoError(t, err)
	require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, data))
	m := newFSManager(service, st)
	require.Error(t, m.Restore(func(string) bool { return false }))
	require.Empty(t, m.sandboxState, "validate every owner before accepting any")
	require.Zero(t, service.mountCalls("registry.example/rootfs:latest"))
	m.Shutdown()
	current, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	require.Equal(t, data, current)
}

func TestFSOwnershipDuplicateNestedSourceFieldsRejected(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	rootfs, err := proto.Marshal(fsTestStartRequest("legacy").Rootfs)
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{"items": map[string]any{"legacy": map[string]any{"rootfs": rootfs}}})
	require.NoError(t, err)
	data = bytes.Replace(data, []byte(`"legacy":{`), []byte(`"legacy":{"rootfs":"",`), 1)
	require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, data))
	m := newFSManager(service, st)
	require.Error(t, m.Restore(func(string) bool { return true }))
	require.Zero(t, service.mountCalls("registry.example/rootfs:latest"))
}
