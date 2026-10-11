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
	if r.State == "not_allocated" {
		if !allowReleased || r.PhysicalGeneration != "" || r.MountPoint != "" {
			return nil, fmt.Errorf("original no-allocation proof cannot authorize acquisition or contain a physical binding")
		}
		copy := *r
		return &copy, nil
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

// Cleanup first requests a persistent fence, then independently reads back the
// original result. The request fingerprint never serializes raw credentials.
func RetireOriginalMountOperation(svc Service, request any, operationID, kind string) (*MountOperationResult, error) {
	if err := RequireMountOperationService(svc, operationID); err != nil {
		return nil, err
	}
	retirement, ok := svc.(MountOperationRetirementService)
	if !ok {
		return nil, fmt.Errorf("mount producer does not support persistent allocation retirement")
	}
	fp, err := MountRequestFingerprint(request)
	if err != nil {
		return nil, err
	}
	facade := ""
	if req, ok := request.(*OCIMountRequest); ok {
		facade = req.ImageURL
	}
	result, err := retirement.RetireMountOperation(&MountOperationRetirement{OperationID: operationID, RequestFingerprint: fp, Kind: kind, ImageURL: facade})
	if err != nil {
		return nil, err
	}
	confirmed, err := QueryOriginalMountOperation(svc, request, operationID, kind, true)
	if err != nil {
		return nil, err
	}
	if result == nil || *confirmed != *result {
		return nil, fmt.Errorf("original mount retirement readback changed")
	}
	return confirmed, nil
}
