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
	var entry imageMountEntry
	switch cfg.SrcType {
	case runtime.RootfsSrcType_LOCAL:
		return m.local.Mount(cfg)
	case runtime.RootfsSrcType_IMAGE:
		if _, err := m.manager.oci.mountOCI(cfg.ImageUrl); err != nil {
			return "", nil, nil, err
		}
		m.manager.oci.mu.Lock()
		entry = *m.manager.oci.entries[cfg.ImageUrl]
		m.manager.oci.mu.Unlock()
	case runtime.RootfsSrcType_S3:
		source := fsS3Source(cfg)
		if _, err := m.manager.s3.mountS3(source); err != nil {
			return "", nil, nil, err
		}
		m.manager.s3.mu.Lock()
		entry = *m.manager.s3.entries[s3MountKey(source)]
		m.manager.s3.mu.Unlock()
	default:
		return "", nil, nil, fmt.Errorf("unsupported rootfs type")
	}
	return entry.path, append([]string(nil), entry.env...), imageconfig.Clone(entry.imageProcess), nil
}

func (m *fsImageMounter) ImageProcess(cfg langrtmanager.RootfsConfig) (*imageconfig.Process, error) {
	return m.local.ImageProcess(cfg)
}

func (m *fsImageMounter) Umount(cfg langrtmanager.RootfsConfig) error {
	switch cfg.SrcType {
	case runtime.RootfsSrcType_LOCAL:
		return m.local.Umount(cfg)
	case runtime.RootfsSrcType_IMAGE:
		return m.manager.oci.unmountOCI(cfg.ImageUrl)
	case runtime.RootfsSrcType_S3:
		return m.manager.s3.unmountS3(fsS3Source(cfg))
	default:
		return fmt.Errorf("unsupported rootfs type")
	}
}

func fsS3Source(cfg langrtmanager.RootfsConfig) *runtime.S3Config {
	return &runtime.S3Config{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Object: cfg.Object,
		AccessKeyID: cfg.AccessKeyID, AccessKeySecret: cfg.AccessKeySecret}
}
