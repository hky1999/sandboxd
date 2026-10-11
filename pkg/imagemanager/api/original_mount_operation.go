// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"path/filepath"
)

// RequireMountOperationService rejects unsupported producers before dispatch.
func RequireMountOperationService(svc Service, operationID string) error {
	if !validMountGeneration(operationID) {
		return fmt.Errorf("original mount operation identity is required")
	}
	if _, ok := svc.(MountOperationService); !ok {
		return fmt.Errorf("mount producer does not support original operation queries")
	}
	return nil
}

// QueryOriginalMountOperation validates the original request and physical
// binding even for in-process producers. It never dispatches a mount. Retired
// results are usable only by an explicitly authorized cleanup operation.
func QueryOriginalMountOperation(svc Service, request any, operationID, kind string, allowReleased bool) (*MountOperationResult, error) {
	if err := RequireMountOperationService(svc, operationID); err != nil {
		return nil, err
	}
	fingerprint, err := MountRequestFingerprint(request)
	if err != nil {
		return nil, err
	}
	r, err := svc.(MountOperationService).QueryMountOperation(&MountOperationQuery{OperationID: operationID, RequestFingerprint: fingerprint})
	if err != nil {
		return nil, err
	}
	if r == nil || r.OperationID != operationID || r.RequestFingerprint != fingerprint || r.Kind != kind {
		return nil, fmt.Errorf("original mount operation result identity changed or is unavailable")
	}
	if r.State != "ready" && !(allowReleased && (r.State == "released" || r.State == "release_pending")) {
		return nil, fmt.Errorf("original mount operation result is unresolved or retired")
	}
	if !validMountGeneration(r.PhysicalGeneration) || !filepath.IsAbs(r.MountPoint) || filepath.Clean(r.MountPoint) != r.MountPoint {
		return nil, fmt.Errorf("original mount operation physical binding is incomplete")
	}
	copy := *r
	return &copy, nil
}
