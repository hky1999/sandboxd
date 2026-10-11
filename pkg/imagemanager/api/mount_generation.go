// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"path/filepath"
)

func (w *HttpWorker) recoverDaemonMount(id, generation string, oss bool) (*MountInfo, error) {
	return w.recoverDaemonMountBound(id, "", generation, oss, nil)
}

func (w *HttpWorker) recoverDaemonMountBound(id, nydusURL, generation string, oss bool, bind mountBinding) (*MountInfo, error) {
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
	info := &MountInfo{PhysicalGeneration: generation, MountPoint: d.MountPoint(), Env: d.Env(), ImageProcess: d.ImageProcess(), Released: phase == "released", ReleasePending: phase == "releasing" || phase == "not_started"}
	if oss {
		info.FilePath = filepath.Join(d.MountPoint(), d.Name())
	}
	if bind != nil {
		if err := bind.Bind(id, nydusURL, generation, info.MountPoint); err != nil {
			return nil, err
		}
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
	return w.recoverOCIMountBound(req, nil)
}

func (w *HttpWorker) recoverOCIMountBound(req *OCIMountRequest, bind mountBinding) (*OCIMountResponse, error) {
	if w.mountStore == nil {
		return nil, fmt.Errorf("original image mount requires its persistent route")
	}
	completed, err := w.mountStore.Completed(req.ImageURL, req.PhysicalGeneration)
	if err != nil {
		return nil, err
	}
	if completed != nil {
		if bind != nil {
			if err := bind.Bind(generateNydusID(completed.NydusImageURL), completed.NydusImageURL, completed.PhysicalGeneration, completed.MountPoint); err != nil {
				return nil, err
			}
		}
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
	info, err := w.recoverDaemonMountBound(generateNydusID(route.NydusImageURL), route.NydusImageURL, req.PhysicalGeneration, false, bind)
	if err != nil {
		return nil, err
	}
	if info.MountPoint != route.MountPoint {
		return nil, fmt.Errorf("original image mount target changed")
	}
	return &OCIMountResponse{MountPath: route.MountPoint, PhysicalGeneration: info.PhysicalGeneration, Env: info.Env, ImageProcess: info.ImageProcess, Released: info.Released, ReleasePending: info.ReleasePending}, nil
}
