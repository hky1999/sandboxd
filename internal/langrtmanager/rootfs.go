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

package langrtmanager

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"

	runtime_api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
)

// ImageMounter abstracts rootfs mount/umount operations for testability.
type ImageMounter interface {
	Mount(cfg RootfsConfig) (path string, env []string, imageProcess *imageconfig.Process, err error)
	ImageProcess(cfg RootfsConfig) (*imageconfig.Process, error)
	Umount(cfg RootfsConfig) error
}

// PhysicalImageMounter returns the birth identity in the same mount operation
// and requires that identity when releasing the corresponding source reference.
type PhysicalImageMounter interface {
	MountWithPhysicalGeneration(cfg RootfsConfig) (string, []string, *imageconfig.Process, string, error)
	UmountIfPhysicalGeneration(cfg RootfsConfig, generation string) error
}

type RootFS struct {
	cfg                RootfsConfig
	path               string
	env                []string
	imageProcess       *imageconfig.Process
	mounter            ImageMounter
	cleanupFunc        func()
	mu                 sync.Mutex // mu protects fields below
	refcnt             int64
	deleted            bool
	releaseUnconfirmed bool
	physicalGeneration string
}

var ErrRootfsReleaseUnconfirmed = errors.New("rootfs release is unconfirmed")

type RootfsConfig struct {
	SrcType runtime_api.RootfsSrcType

	// OSS
	Endpoint        string
	Bucket          string
	Object          string
	AccessKeyID     string
	AccessKeySecret string

	// docker image
	ImageUrl string

	// local
	Path string

	PhysicalGeneration        string
	RequirePhysicalGeneration bool
	AllowReleasedMount        bool
}

func (cfg RootfsConfig) key() string {
	return fmt.Sprintf("%d:%s:%s:%s:%s:%s:%s:%s:%s:%t:%t",
		cfg.SrcType,
		cfg.Endpoint,
		cfg.Bucket,
		cfg.Object,
		cfg.AccessKeyID,
		cfg.AccessKeySecret,
		cfg.ImageUrl,
		cfg.Path,
		cfg.PhysicalGeneration, cfg.RequirePhysicalGeneration, cfg.AllowReleasedMount,
	)
}

func (rf *RootFS) Path() string {
	return rf.path
}

func (rf *RootFS) Env() []string {
	return rf.env
}

func (rf *RootFS) ImageProcess() *imageconfig.Process {
	return imageconfig.Clone(rf.imageProcess)
}

func (rf *RootFS) ResolveImageProcess() (*imageconfig.Process, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.imageProcess != nil {
		return imageconfig.Clone(rf.imageProcess), nil
	}
	imageProcess, err := rf.mounter.ImageProcess(rf.cfg)
	if err != nil {
		return nil, err
	}
	if imageProcess == nil {
		return nil, fmt.Errorf("image process config is unavailable")
	}
	rf.imageProcess = imageconfig.Clone(imageProcess)
	return imageconfig.Clone(rf.imageProcess), nil
}

func (rf *RootFS) Config() RootfsConfig {
	return rf.cfg
}

func (rf *RootFS) PhysicalGeneration() string { return rf.physicalGeneration }

func (rf *RootFS) MountImage() error {
	if rf.path != "" {
		return fmt.Errorf("already mounted")
	}
	var path, generation string
	var env []string
	var imageProcess *imageconfig.Process
	var err error
	if mounter, ok := rf.mounter.(PhysicalImageMounter); ok {
		path, env, imageProcess, generation, err = mounter.MountWithPhysicalGeneration(rf.cfg)
	} else if rf.cfg.RequirePhysicalGeneration || rf.cfg.PhysicalGeneration != "" {
		return fmt.Errorf("rootfs mounter cannot preserve the original physical generation")
	} else {
		path, env, imageProcess, err = rf.mounter.Mount(rf.cfg)
	}
	if err != nil {
		return err
	}
	if rf.cfg.SrcType != runtime_api.RootfsSrcType_LOCAL && (rf.cfg.RequirePhysicalGeneration || rf.cfg.PhysicalGeneration != "") {
		decoded, err := hex.DecodeString(generation)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != generation || rf.cfg.PhysicalGeneration != "" && generation != rf.cfg.PhysicalGeneration {
			return fmt.Errorf("original rootfs physical generation is missing or changed")
		}
	}
	rf.path = path
	rf.env = env
	rf.imageProcess = imageconfig.Clone(imageProcess)
	rf.physicalGeneration = generation
	return nil
}

func (rf *RootFS) UmountImage() error {
	if mounter, ok := rf.mounter.(PhysicalImageMounter); ok {
		return mounter.UmountIfPhysicalGeneration(rf.cfg, rf.physicalGeneration)
	}
	return rf.mounter.Umount(rf.cfg)
}

// defaultMounter is the production ImageMounter backed by the in-process
// image-manager Service. Production code constructs one via NewDefaultMounter.
type defaultMounter struct {
	svc api.Service
}

// NewDefaultMounter returns the production mounter, bound to the in-process
// image-manager Service that sandboxd hands down.
func NewDefaultMounter(svc api.Service) ImageMounter {
	return &defaultMounter{svc: svc}
}

func (d *defaultMounter) client() api.Service {
	if d.svc == nil {
		// Every production path must provide the in-process Service. A nil
		// service indicates a programming error rather than a recoverable mount
		// failure.
		panic("langrtmanager: defaultMounter used without an image-manager Service")
	}
	return d.svc
}

func (d *defaultMounter) Mount(cfg RootfsConfig) (string, []string, *imageconfig.Process, error) {
	path, env, process, _, err := d.MountWithPhysicalGeneration(cfg)
	return path, env, process, err
}

func (d *defaultMounter) MountWithPhysicalGeneration(cfg RootfsConfig) (string, []string, *imageconfig.Process, string, error) {
	switch cfg.SrcType {
	case runtime_api.RootfsSrcType_S3:
		mi, err := d.client().MountOSS(&api.OSSMountRequest{
			PhysicalGeneration: cfg.PhysicalGeneration,
			Endpoint:           cfg.Endpoint,
			Bucket:             cfg.Bucket,
			Object:             cfg.Object,
			AccessKeyID:        cfg.AccessKeyID,
			AccessKeySecret:    cfg.AccessKeySecret,
		})
		if err != nil {
			return "", nil, nil, "", err
		}
		if mi == nil || mi.FilePath == "" || (mi.Released || mi.ReleasePending) && (!cfg.AllowReleasedMount || cfg.PhysicalGeneration == "") {
			return "", nil, nil, "", fmt.Errorf("original S3 mount is unavailable")
		}
		return mi.FilePath, mi.Env, mi.ImageProcess, mi.PhysicalGeneration, nil

	case runtime_api.RootfsSrcType_IMAGE:
		resp, err := d.client().MountOCI(&api.OCIMountRequest{
			ImageURL:           cfg.ImageUrl,
			PhysicalGeneration: cfg.PhysicalGeneration, RequirePhysicalGeneration: cfg.RequirePhysicalGeneration,
		})
		if err != nil {
			return "", nil, nil, "", err
		}
		if resp == nil || resp.MountPath == "" || (resp.Released || resp.ReleasePending) && (!cfg.AllowReleasedMount || cfg.PhysicalGeneration == "") {
			return "", nil, nil, "", fmt.Errorf("original image mount is unavailable")
		}
		return resp.MountPath, resp.Env, resp.ImageProcess, resp.PhysicalGeneration, nil

	case runtime_api.RootfsSrcType_LOCAL:
		// LOCAL rootfs is a pre-existing host path; no image-manager Service
		// call is involved, so leaving d.svc nil (typical in tests) is fine.
		if _, err := os.Stat(cfg.Path); err != nil {
			return "", nil, nil, "", fmt.Errorf("failed to stat local rootfs path %s: %w", cfg.Path, err)
		}
		return cfg.Path, nil, nil, "", nil

	default:
		return "", nil, nil, "", fmt.Errorf("Unsupported image type: %v", cfg.SrcType.String())
	}
}

func (d *defaultMounter) ImageProcess(cfg RootfsConfig) (*imageconfig.Process, error) {
	if cfg.SrcType != runtime_api.RootfsSrcType_IMAGE {
		return nil, fmt.Errorf("image process config requires an image rootfs")
	}
	return d.client().ImageProcess(cfg.ImageUrl)
}

func (d *defaultMounter) Umount(cfg RootfsConfig) error {
	return d.UmountIfPhysicalGeneration(cfg, cfg.PhysicalGeneration)
}

func (d *defaultMounter) UmountIfPhysicalGeneration(cfg RootfsConfig, generation string) error {
	switch cfg.SrcType {
	case runtime_api.RootfsSrcType_S3:
		return d.client().UmountOSS(&api.OSSUmountRequest{
			PhysicalGeneration: generation,
			Endpoint:           cfg.Endpoint,
			Bucket:             cfg.Bucket,
			Object:             cfg.Object,
		})
	case runtime_api.RootfsSrcType_IMAGE:
		return d.client().UmountOCI(&api.OCIUmountRequest{
			PhysicalGeneration: generation,
			ImageURL:           cfg.ImageUrl,
		})
	case runtime_api.RootfsSrcType_LOCAL:
		return nil
	default:
		return fmt.Errorf("Unsupported image type: %v", cfg.SrcType.String())
	}
}

func (rf *RootFS) IncRef() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.deleted {
		return fmt.Errorf("this rootfs has already been deleted")
	}
	if rf.releaseUnconfirmed {
		return ErrRootfsReleaseUnconfirmed
	}
	rf.refcnt += 1
	return nil
}

func (rf *RootFS) DecRef() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.deleted || rf.refcnt <= 0 {
		return fmt.Errorf("rootfs reference is not owned")
	}
	if rf.refcnt == 1 {
		if err := rf.UmountImage(); err != nil {
			rf.releaseUnconfirmed = true
			return fmt.Errorf("unmount rootfs: %w", err)
		}
		rf.deleted = true
		rf.releaseUnconfirmed = false
		if rf.cleanupFunc != nil {
			rf.cleanupFunc()
		}
	}
	rf.refcnt--
	return nil
}

func NewRootFS(cfg RootfsConfig, mounter ImageMounter, cleanup func()) (*RootFS, error) {
	rootFS := &RootFS{
		cfg:         cfg,
		mounter:     mounter,
		cleanupFunc: cleanup,
	}

	if err := rootFS.MountImage(); err != nil {
		return nil, err
	}

	return rootFS, nil
}
