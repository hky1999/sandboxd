// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/langrtmanager"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
)

// Rootfs and additional mounts must use the same source reference authority.
// Image-manager unmount removes the source; it does not count these owners.
type fsImageMounter struct {
	manager *fsManager
	local   langrtmanager.ImageMounter
}

func (m *fsImageMounter) Mount(cfg langrtmanager.RootfsConfig) (string, []string, *imageconfig.Process, error) {
	path, env, process, _, err := m.MountWithPhysicalGeneration(cfg)
	return path, env, process, err
}

func (m *fsImageMounter) MountWithPhysicalGeneration(cfg langrtmanager.RootfsConfig) (string, []string, *imageconfig.Process, string, error) {
	var entry imageMountEntry
	var err error
	switch cfg.SrcType {
	case runtime.RootfsSrcType_LOCAL:
		path, env, process, err := m.local.Mount(cfg)
		return path, env, process, "", err
	case runtime.RootfsSrcType_IMAGE:
		entry, err = m.manager.oci.mountOCIGeneration(cfg.ImageUrl, cfg.PhysicalGeneration, cfg.RequirePhysicalGeneration, cfg.AllowReleasedMount)
	case runtime.RootfsSrcType_S3:
		source := fsS3Source(cfg)
		entry, err = m.manager.s3.mountS3Generation(source, cfg.PhysicalGeneration, cfg.RequirePhysicalGeneration, cfg.AllowReleasedMount)
	default:
		return "", nil, nil, "", fmt.Errorf("unsupported rootfs type")
	}
	if err != nil {
		return "", nil, nil, "", err
	}
	return entry.path, append([]string(nil), entry.env...), imageconfig.Clone(entry.imageProcess), entry.physicalGeneration, nil
}

func (m *fsImageMounter) ImageProcess(cfg langrtmanager.RootfsConfig) (*imageconfig.Process, error) {
	return m.local.ImageProcess(cfg)
}

func (m *fsImageMounter) Umount(cfg langrtmanager.RootfsConfig) error {
	return m.UmountIfPhysicalGeneration(cfg, cfg.PhysicalGeneration)
}

func (m *fsImageMounter) UmountIfPhysicalGeneration(cfg langrtmanager.RootfsConfig, generation string) error {
	if cfg.SrcType != runtime.RootfsSrcType_LOCAL && cfg.RequirePhysicalGeneration && !validFSPhysicalGeneration(generation) {
		return fmt.Errorf("original rootfs mount generation is unknown")
	}
	switch cfg.SrcType {
	case runtime.RootfsSrcType_LOCAL:
		return m.local.Umount(cfg)
	case runtime.RootfsSrcType_IMAGE:
		return m.manager.oci.unmountOCIGeneration(cfg.ImageUrl, generation)
	case runtime.RootfsSrcType_S3:
		return m.manager.s3.unmountS3Generation(fsS3Source(cfg), generation)
	default:
		return fmt.Errorf("unsupported rootfs type")
	}
}

func fsS3Source(cfg langrtmanager.RootfsConfig) *runtime.S3Config {
	return &runtime.S3Config{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Object: cfg.Object,
		AccessKeyID: cfg.AccessKeyID, AccessKeySecret: cfg.AccessKeySecret}
}
