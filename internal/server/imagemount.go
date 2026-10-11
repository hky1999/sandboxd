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
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	imgApi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	"github.com/sirupsen/logrus"
)

// imageMountEntry tracks a shared image mount with reference counting.
// Multiple sandboxes using the same image share one mount point.
type imageMountEntry struct {
	refcount           int
	path               string // local mount path
	env                []string
	imageProcess       *imageconfig.Process
	releaseUnconfirmed bool
	physicalGeneration string
}

// requireReadOnlyMount enforces that S3/OCI-image mounts carry the "ro" option.
// The underlying FUSE source is read-only, so without an explicit "ro" the OCI
// spec would describe the mount as writable while writes silently fail at the
// FUSE layer.
func requireReadOnlyMount(m *runtime.Mount) error {
	if !hasReadOnlyOption(m.GetOptions()) {
		return fmt.Errorf("mount target %q must include the \"ro\" option: S3/image mounts are read-only", m.GetTarget())
	}
	return nil
}

// hasReadOnlyOption reports whether opts contains the "ro" mount option.
func hasReadOnlyOption(opts []string) bool {
	for _, opt := range opts {
		if opt == "ro" {
			return true
		}
	}
	return false
}

// s3UnmountFunc is the function type for unmounting S3 mounts.
type s3UnmountFunc func(endpoint, bucket, object string) error

// ociUnmountFunc is the function type for unmounting OCI image mounts.
type ociUnmountFunc func(imageURL string) error

// s3MountManager manages shared S3 FUSE mounts with reference counting.
// image-manager's FUSE daemon deduplicates by endpoint+bucket+object, but
// its UnmountOSS kills the daemon directly without ref counting. This manager
// ensures the daemon is only unmounted when no sandbox references it.
type s3MountManager struct {
	mu       sync.Mutex
	entries  map[string]*imageMountEntry // key: endpoint+bucket+object
	svc      imgApi.Service              // in-process image manager
	unmountF s3UnmountFunc               // test seam
}

func newS3MountManager(svc imgApi.Service) *s3MountManager {
	if svc == nil {
		// Production callers and tests must provide a Service explicitly.
		panic("server: newS3MountManager called without an image-manager Service")
	}
	return &s3MountManager{
		entries: make(map[string]*imageMountEntry),
		svc:     svc,
		unmountF: func(endpoint, bucket, object string) error {
			return svc.UmountOSS(&imgApi.OSSUmountRequest{
				Endpoint: endpoint,
				Bucket:   bucket,
				Object:   object,
			})
		},
	}
}

func s3MountKey(cfg *runtime.S3Config) string {
	return strings.Join([]string{cfg.Endpoint, cfg.Bucket, cfg.Object}, "\x00")
}

// mountS3 acquires a shared S3 mount. If the same S3 object is already mounted
// by another sandbox, the existing path is returned without calling image-manager.
func (m *s3MountManager) mountS3(cfg *runtime.S3Config) (string, error) {
	entry, err := m.mountS3Generation(cfg, "", false, false)
	return entry.path, err
}

func validFSPhysicalGeneration(g string) bool {
	b, err := hex.DecodeString(g)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == g
}

func validateMountEntry(entry imageMountEntry, expected string, required, allowReleased bool) error {
	if expected != "" && (!validFSPhysicalGeneration(expected) || entry.physicalGeneration != expected) {
		return fmt.Errorf("original mount generation changed")
	}
	if required && !validFSPhysicalGeneration(entry.physicalGeneration) {
		return fmt.Errorf("original mount generation is unknown")
	}
	if entry.releaseUnconfirmed && (!allowReleased || expected == "") {
		return fmt.Errorf("source release is unconfirmed")
	}
	return nil
}

// A nonempty expected generation queries the original lease and never creates
// a mount. A retiring lease may be reconstructed only for its pending cleanup.
func (m *s3MountManager) mountS3Generation(cfg *runtime.S3Config, expected string, required, allowReleased bool) (imageMountEntry, error) {
	if cfg == nil {
		return imageMountEntry{}, fmt.Errorf("s3_config is nil")
	}
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.Object == "" {
		return imageMountEntry{}, fmt.Errorf("s3_config missing required fields")
	}

	key := s3MountKey(cfg)
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.entries[key]; ok {
		if err := validateMountEntry(*entry, expected, required, allowReleased); err != nil {
			return imageMountEntry{}, err
		}
		entry.refcount++
		return *entry, nil
	}
	if m.svc == nil || expected != "" && !validFSPhysicalGeneration(expected) {
		return imageMountEntry{}, fmt.Errorf("original S3 mount service or identity is unavailable")
	}
	mi, err := m.svc.MountOSS(&imgApi.OSSMountRequest{
		PhysicalGeneration: expected,
		Endpoint:           cfg.Endpoint, Bucket: cfg.Bucket, Object: cfg.Object,
		AccessKeyID: cfg.AccessKeyID, AccessKeySecret: cfg.AccessKeySecret,
	})
	if err != nil {
		return imageMountEntry{}, fmt.Errorf("mount S3: %w", err)
	}
	if mi == nil || mi.FilePath == "" {
		return imageMountEntry{}, fmt.Errorf("S3 mount returned no path")
	}
	entry := imageMountEntry{refcount: 1, path: mi.FilePath,
		physicalGeneration: mi.PhysicalGeneration, releaseUnconfirmed: mi.Released || mi.ReleasePending,
		env: append([]string(nil), mi.Env...), imageProcess: imageconfig.Clone(mi.ImageProcess)}
	if err := validateMountEntry(entry, expected, required, allowReleased); err != nil {
		return imageMountEntry{}, err
	}
	m.entries[key] = &entry
	return entry, nil
}

// unmountS3 releases a reference to a shared S3 mount.
// The FUSE daemon is only unmounted when refcount reaches zero.
func (m *s3MountManager) unmountS3(cfg *runtime.S3Config) error {
	return m.unmountS3Generation(cfg, "")
}

func (m *s3MountManager) unmountS3Generation(cfg *runtime.S3Config, expected string) error {
	if cfg == nil {
		return fmt.Errorf("s3_config is nil")
	}

	key := s3MountKey(cfg)
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[key]
	if !ok || entry.refcount <= 0 {
		return fmt.Errorf("S3 mount reference is not owned")
	}
	if expected != "" && (!validFSPhysicalGeneration(expected) || entry.physicalGeneration != expected) {
		return fmt.Errorf("original S3 reference generation changed")
	}
	if entry.refcount == 1 {
		var err error
		if entry.physicalGeneration != "" && m.svc != nil {
			err = m.svc.UmountOSS(&imgApi.OSSUmountRequest{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Object: cfg.Object, PhysicalGeneration: entry.physicalGeneration})
		} else {
			err = m.unmountF(cfg.Endpoint, cfg.Bucket, cfg.Object)
		}
		if err != nil {
			entry.releaseUnconfirmed = true
			return err
		}
		delete(m.entries, key)
	} else {
		entry.refcount--
	}
	return nil
}

// cleanupAllS3Unmounts unmounts all remaining S3 mounts.
// Called during shutdown.
func (m *s3MountManager) cleanupAllS3Unmounts() {
	m.mu.Lock()
	entries := make(map[string]*imageMountEntry, len(m.entries))
	for k, v := range m.entries {
		entries[k] = v
	}
	m.entries = make(map[string]*imageMountEntry)
	m.mu.Unlock()

	for key, entry := range entries {
		parts := strings.Split(key, "\x00")
		if len(parts) != 3 {
			logrus.Warnf("s3mount: invalid key format, skipping: %q", key)
			continue
		}
		logrus.Infof("s3mount: cleanup remaining mount refcount=%d at %s", entry.refcount, entry.path)
		if err := m.unmountF(parts[0], parts[1], parts[2]); err != nil {
			logrus.Warnf("s3mount: cleanup failed for %s: %v", key, err)
		}
	}
}

// ociMountManager manages shared OCI image mounts with reference counting.
// Similar to s3MountManager, it ensures OCI images are only unmounted when
// no sandbox references them.
type ociMountManager struct {
	mu       sync.Mutex
	entries  map[string]*imageMountEntry // key: image URL
	svc      imgApi.Service              // in-process image-manager (nil falls back to HttpClient)
	unmountF ociUnmountFunc              // for testing injection
}

func newOciMountManager(svc imgApi.Service) *ociMountManager {
	if svc == nil {
		panic("server: newOciMountManager called without an image-manager Service")
	}
	return &ociMountManager{
		entries: make(map[string]*imageMountEntry),
		svc:     svc,
		unmountF: func(imageURL string) error {
			return svc.UmountOCI(&imgApi.OCIUmountRequest{
				ImageURL: imageURL,
			})
		},
	}
}

// mountOCI acquires a shared OCI image mount. If the same image is already mounted
// by another sandbox, the existing path is returned without calling image-manager.
func (m *ociMountManager) mountOCI(imageURL string) (string, error) {
	entry, err := m.mountOCIGeneration(imageURL, "", false, false)
	return entry.path, err
}

func (m *ociMountManager) mountOCIGeneration(imageURL, expected string, required, allowReleased bool) (imageMountEntry, error) {
	if imageURL == "" {
		return imageMountEntry{}, fmt.Errorf("image_url is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.entries[imageURL]; ok {
		if err := validateMountEntry(*entry, expected, required, allowReleased); err != nil {
			return imageMountEntry{}, err
		}
		entry.refcount++
		return *entry, nil
	}
	if m.svc == nil || expected != "" && !validFSPhysicalGeneration(expected) {
		return imageMountEntry{}, fmt.Errorf("original image mount service or identity is unavailable")
	}
	resp, err := m.svc.MountOCI(&imgApi.OCIMountRequest{ImageURL: imageURL, PhysicalGeneration: expected, RequirePhysicalGeneration: required})
	if err != nil {
		return imageMountEntry{}, fmt.Errorf("mount OCI image: %w", err)
	}
	if resp == nil || resp.MountPath == "" {
		return imageMountEntry{}, fmt.Errorf("OCI mount returned no path")
	}
	entry := imageMountEntry{refcount: 1, path: resp.MountPath,
		physicalGeneration: resp.PhysicalGeneration, releaseUnconfirmed: resp.Released || resp.ReleasePending,
		env: append([]string(nil), resp.Env...), imageProcess: imageconfig.Clone(resp.ImageProcess)}
	if err := validateMountEntry(entry, expected, required, allowReleased); err != nil {
		return imageMountEntry{}, err
	}
	m.entries[imageURL] = &entry
	return entry, nil
}

// unmountOCI releases a reference to a shared OCI image mount.
// The image is only unmounted when refcount reaches zero.
func (m *ociMountManager) unmountOCI(imageURL string) error {
	return m.unmountOCIGeneration(imageURL, "")
}

func (m *ociMountManager) unmountOCIGeneration(imageURL, expected string) error {
	if imageURL == "" {
		return fmt.Errorf("image_url is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[imageURL]
	if !ok || entry.refcount <= 0 {
		return fmt.Errorf("OCI mount reference is not owned")
	}
	if expected != "" && (!validFSPhysicalGeneration(expected) || entry.physicalGeneration != expected) {
		return fmt.Errorf("original OCI reference generation changed")
	}
	if entry.refcount == 1 {
		var err error
		if entry.physicalGeneration != "" && m.svc != nil {
			err = m.svc.UmountOCI(&imgApi.OCIUmountRequest{ImageURL: imageURL, PhysicalGeneration: entry.physicalGeneration})
		} else {
			err = m.unmountF(imageURL)
		}
		if err != nil {
			entry.releaseUnconfirmed = true
			return err
		}
		delete(m.entries, imageURL)
	} else {
		entry.refcount--
	}
	return nil
}

// cleanupAllOciUnmounts unmounts all remaining OCI image mounts.
// Called during shutdown.
func (m *ociMountManager) cleanupAllOciUnmounts() {
	m.mu.Lock()
	entries := make(map[string]*imageMountEntry, len(m.entries))
	for k, v := range m.entries {
		entries[k] = v
	}
	m.entries = make(map[string]*imageMountEntry)
	m.mu.Unlock()

	for key, entry := range entries {
		logrus.Infof("ocimount: cleanup remaining mount refcount=%d at %s", entry.refcount, entry.path)
		if err := m.unmountF(key); err != nil {
			logrus.Warnf("ocimount: cleanup failed for %s: %v", key, err)
		}
	}
}
