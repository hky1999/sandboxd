// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"path/filepath"
)

func (w *HttpWorker) recoverDaemonMount(id, generation string, oss bool) (*MountInfo, error) {
	if !validMountGeneration(generation) || w.mgr == nil {
		return nil, fmt.Errorf("original daemon mount identity is required")
	}
	d := w.mgr.GetDaemon(id)
	if d == nil {
		return nil, fmt.Errorf("original daemon mount is missing")
	}
	phase, err := d.InspectPhysicalGeneration(generation)
	if err != nil {
		return nil, err
	}
	info := &MountInfo{PhysicalGeneration: generation, MountPoint: d.MountPoint(), Env: d.Env(), ImageProcess: d.ImageProcess(), Released: phase == "released", ReleasePending: phase == "releasing"}
	if oss {
		info.FilePath = filepath.Join(d.MountPoint(), d.Name())
	}
	if phase == "running" {
		if err := w.mgr.SetDaemonReferencedIfPhysicalGeneration(id, generation, true); err != nil {
			return nil, err
		}
	}
	return info, nil
}

// Caller owns the source route lock. Completed replay precedes current lookup.
func (w *HttpWorker) recoverOCIMount(req *OCIMountRequest) (*OCIMountResponse, error) {
	if w.mountStore == nil {
		return nil, fmt.Errorf("original image mount requires its persistent route")
	}
	completed, err := w.mountStore.Completed(req.ImageURL, req.PhysicalGeneration)
	if err != nil {
		return nil, err
	}
	if completed != nil {
		return &OCIMountResponse{MountPath: completed.MountPoint, PhysicalGeneration: completed.PhysicalGeneration, Released: true}, nil
	}
	route, err := w.mountStore.Get(req.ImageURL)
	if err != nil {
		return nil, err
	}
	if err := validateMountRoute(req.ImageURL, route); err != nil {
		return nil, err
	}
	if route.PhysicalGeneration != req.PhysicalGeneration {
		return nil, fmt.Errorf("original image mount generation changed")
	}
	if route.MountType != "nydus" {
		return nil, fmt.Errorf("OCI physical mount recovery is not supported yet")
	}
	info, err := w.recoverDaemonMount(generateNydusID(route.NydusImageURL), req.PhysicalGeneration, false)
	if err != nil {
		return nil, err
	}
	if info.MountPoint != route.MountPoint {
		return nil, fmt.Errorf("original image mount target changed")
	}
	return &OCIMountResponse{MountPath: route.MountPoint, PhysicalGeneration: info.PhysicalGeneration, Env: info.Env, ImageProcess: info.ImageProcess, Released: info.Released, ReleasePending: info.ReleasePending}, nil
}
