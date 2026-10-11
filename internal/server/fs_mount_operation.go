// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"google.golang.org/protobuf/proto"
)

// Protocol 1 derives each operation from the immutable, persisted owner and
// ordered source slot. Keep this encoding stable across daemon upgrades.
func fsMountOperationID(s sandboxFSState, purpose string, index int) string {
	if s.MountOperationProtocol != 1 {
		return ""
	}
	if purpose == "rootfs" {
		var root runtime.RootfsConfig
		if proto.Unmarshal(s.Rootfs, &root) != nil || root.Type == runtime.RootfsSrcType_LOCAL {
			return ""
		}
	}
	raw, _ := json.Marshal(struct {
		Domain  string
		Owner   string
		Purpose string
		Index   int
	}{"akernel-filesystem-mount-operation-v1", s.SourceFingerprint, purpose, index})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func requireFSMountOperationService(svc imageapi.Service, id string) error {
	return imageapi.RequireMountOperationService(svc, id)
}

func verifyFSOperationReply(svc imageapi.Service, request any, id, kind, generation, target string, allowReleased bool) error {
	r, err := imageapi.QueryOriginalMountOperation(svc, request, id, kind, allowReleased)
	if err != nil {
		return err
	}
	if r.PhysicalGeneration != generation || r.MountPoint != target {
		return fmt.Errorf("original mount reply differs from its independent operation result")
	}
	return nil
}

func fsOSSMountRequest(s *runtime.S3Config) *imageapi.OSSMountRequest {
	return &imageapi.OSSMountRequest{Endpoint: s.Endpoint, Bucket: s.Bucket, Object: s.Object, AccessKeyID: s.AccessKeyID, AccessKeySecret: s.AccessKeySecret}
}

// Resolve every original operation before ANY shared-reference reconstruction.
// An unbound old acquisition remains unknown; it cannot gain a new operation ID.
func (m *fsManager) resolveFSOriginalOperationsLocked(state sandboxFSState) (sandboxFSState, error) {
	state = cloneFSState(state)
	if state.MountOperationProtocol != 1 {
		return state, validateFSRecoveryBindings(state)
	}
	resolve := func(svc imageapi.Service, request any, purpose, kind string, index int, phase fsLeasePhase, generation *string) error {
		if !needsFSReference(phase) {
			return nil
		}
		id := fsMountOperationID(state, purpose, index)
		result, err := imageapi.QueryOriginalMountOperation(svc, request, id, kind, state.ReleaseRequested || phase == fsReleasePending)
		if err != nil {
			return err
		}
		if *generation != "" && *generation != result.PhysicalGeneration {
			return fmt.Errorf("original filesystem operation generation changed")
		}
		*generation = result.PhysicalGeneration
		return nil
	}
	var root runtime.RootfsConfig
	if err := proto.Unmarshal(state.Rootfs, &root); err != nil {
		return state, err
	}
	switch root.Type {
	case runtime.RootfsSrcType_IMAGE:
		err := resolve(m.oci.svc, &imageapi.OCIMountRequest{ImageURL: root.GetImageUrl(), RequirePhysicalGeneration: true}, "rootfs", "oci", 0, state.RootfsPhase, &state.RootfsMountGeneration)
		if err != nil {
			return state, err
		}
	case runtime.RootfsSrcType_S3:
		err := resolve(m.s3.svc, fsOSSMountRequest(root.GetS3Config()), "rootfs", "oss", 0, state.RootfsPhase, &state.RootfsMountGeneration)
		if err != nil {
			return state, err
		}
	}
	for i, source := range state.S3 {
		if err := resolve(m.s3.svc, fsOSSMountRequest(source), "s3", "oss", i, state.S3Phases[i], &state.S3MountGenerations[i]); err != nil {
			return state, err
		}
	}
	for i, source := range state.OCI {
		if err := resolve(m.oci.svc, &imageapi.OCIMountRequest{ImageURL: source, RequirePhysicalGeneration: true}, "oci", "oci", i, state.OCIPhases[i], &state.OCIMountGenerations[i]); err != nil {
			return state, err
		}
	}
	return state, validateFSRecoveryBindings(state)
}
