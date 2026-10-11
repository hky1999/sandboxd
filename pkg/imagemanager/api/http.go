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

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/nydus"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
)

const DefaultHttpSockPath = "/var/run/image_mgr.sock"

// API_VERSION is included in daemon ID generation to ensure backward incompatible
// changes (e.g., config format changes) naturally obsolete old daemons via GC.
// Increment this version when making breaking changes to distill_fs config format.
const API_VERSION = "v2"

func generateOSSID(Endpoint, Bucket, Object string) string {
	cs := sha256.Sum256([]byte(API_VERSION + ":" + Endpoint + Bucket + Object))
	return hex.EncodeToString(cs[:])
}

func generateNydusID(imageURL string) string {
	cs := sha256.Sum256([]byte(API_VERSION + ":nydus:" + imageURL))
	return hex.EncodeToString(cs[:])
}

// HttpWorkerConfig holds the configuration for creating an HttpWorker.
type HttpWorkerConfig struct {
	Manager     distillfs.Manager
	OCIManager  *oci.Manager
	NydusClient *nydus.RegistryClient
	NydusSuffix string
	DBPath      string // path to BoltDB mount store; empty to disable
}

func NewHttpWorker(cfg *HttpWorkerConfig) (*HttpWorker, error) {
	owner, _ := cfg.Manager.(distillfs.ManagerLifecycle)
	var releaseOwner func()
	if owner != nil {
		var err error
		releaseOwner, err = owner.RetainOwnership()
		if err != nil {
			return nil, err
		}
	}
	var mountStore *MountStore
	if cfg.DBPath != "" {
		var err error
		mountStore, err = OpenMountStore(cfg.DBPath)
		if err != nil {
			if releaseOwner != nil {
				releaseOwner()
			}
			return nil, fmt.Errorf("failed to open mount store: %w", err)
		}
	}
	return &HttpWorker{
		owner:        owner,
		releaseOwner: releaseOwner,
		ctx:          context.Background(),
		mgr:          cfg.Manager,
		ociMgr:       cfg.OCIManager,
		nydusClient:  cfg.NydusClient,
		nydusSuffix:  cfg.NydusSuffix,
		nydusCache:   NewNydusImageCache(),
		mountStore:   mountStore,
	}, nil
}

type HttpWorker struct {
	owner        distillfs.ManagerLifecycle
	releaseOwner func()
	lifecycleMu  sync.Mutex
	closed       bool
	active       sync.WaitGroup
	closeOnce    sync.Once
	closeDone    chan struct{}
	closeErr     error
	ctx          context.Context
	mgr          distillfs.Manager
	ociMgr       *oci.Manager
	nydusClient  *nydus.RegistryClient
	nydusSuffix  string
	nydusCache   *NydusImageCache
	mountStore   *MountStore

	nydusDetectSF    singleflight.Group
	routeLocksMu     sync.Mutex
	routeLocks       map[string]*mountRouteLock
	operationLocksMu sync.Mutex
	operationLocks   map[string]*mountRouteLock
}

// Close rejects new requests, drains admitted work, then closes the database.
func (w *HttpWorker) Close() {
	_ = w.CloseWithContext(context.Background())
}

// A caller timeout leaves the database and ownership lease with the drain.
func (w *HttpWorker) CloseWithContext(ctx context.Context) error {
	w.closeOnce.Do(func() {
		w.lifecycleMu.Lock()
		w.closed = true
		w.closeDone = make(chan struct{})
		w.lifecycleMu.Unlock()
		go func() {
			w.active.Wait()
			if w.mountStore != nil {
				w.closeErr = w.mountStore.Close()
			}
			if w.releaseOwner != nil {
				w.releaseOwner()
			}
			close(w.closeDone)
		}()
	})
	select {
	case <-w.closeDone:
		return w.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *HttpWorker) admit() (func(), error) {
	w.lifecycleMu.Lock()
	defer w.lifecycleMu.Unlock()
	if w.closed {
		return nil, fmt.Errorf("image worker is closing")
	}
	var releaseOwner func()
	if w.owner != nil {
		var err error
		releaseOwner, err = w.owner.RetainOwnership()
		if err != nil {
			return nil, err
		}
	}
	w.active.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			if releaseOwner != nil {
				releaseOwner()
			}
			w.active.Done()
		})
	}, nil
}

// SetContext sets the context for tracing (should be called after creation if tracing is enabled)
func (w *HttpWorker) SetContext(ctx context.Context) {
	w.ctx = ctx
}

func splitObject(object string) (string, string, error) {
	if object == "" {
		return "", "", fmt.Errorf("empty object")
	}
	if strings.HasSuffix(object, "/") {
		return "", "", fmt.Errorf("object should not end with '/'")
	}
	cleaned := path.Clean(object)
	if cleaned == "." || cleaned == "/" {
		return "", "", fmt.Errorf("invalid object: %s", object)
	}
	dir := path.Dir(cleaned)
	if dir == "." {
		dir = ""
	}
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	return prefix, path.Base(cleaned), nil
}

func (w *HttpWorker) MountOSS(req *OSSMountRequest) (*MountInfo, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if req != nil && req.OperationID != "" {
		return w.executeMountOperation(req.OperationID, "oss", "", req.PhysicalGeneration, req, func(bind mountBinding) (*MountInfo, error) { return w.mountOSS(req, bind) })
	}
	return w.mountOSS(req, nil)
}

func (w *HttpWorker) mountOSS(req *OSSMountRequest, bind mountBinding) (*MountInfo, error) {
	if req == nil {
		return nil, fmt.Errorf("mount source is required")
	}
	if req.PhysicalGeneration != "" {
		return w.recoverDaemonMountBound(generateOSSID(req.Endpoint, req.Bucket, req.Object), "", req.PhysicalGeneration, true, bind)
	}
	// Generate daemon ID first for tracing
	daemonID := generateOSSID(req.Endpoint, req.Bucket, req.Object)

	// Start API timing
	timing, _ := StartAPITimedOperation(w.ctx, "api.MountOSS", daemonID)
	defer timing.End()

	// Stage 1: Parse and validate request
	stageStart := time.Now()
	prefix, name, err := splitObject(req.Object)
	if err != nil {
		timing.Fail(err)
		return nil, fmt.Errorf("invalid object: %w", err)
	}
	timing.Stage("parse_request", time.Since(stageStart))

	// Stage 2: Create daemon options
	stageStart = time.Now()
	opts := &distillfs.DaemonCreateOpt{
		ID:              daemonID,
		Name:            name,
		MountPoint:      req.MountPoint,
		ObjectPrefix:    prefix,
		Endpoint:        req.Endpoint,
		Bucket:          req.Bucket,
		AccessKeyID:     req.AccessKeyID,
		AccessKeySecret: req.AccessKeySecret,
	}
	logrus.Infof("%s %s %s has ID %s", req.Endpoint, req.Bucket, req.Object, opts.ID)
	logrus.WithFields(logrus.Fields{
		"daemon_id":   opts.ID,
		"mount_point": req.MountPoint,
		"source_type": "oss",
		"endpoint":    req.Endpoint,
		"bucket":      req.Bucket,
		"object":      req.Object,
	}).Info("mount path daemon info")
	timing.Stage("prepare_options", time.Since(stageStart))

	// Stage 3: Create daemon
	stageStart = time.Now()
	err = w.mgr.CreateDaemon(opts)
	if err != nil {
		timing.Fail(err)
		return nil, fmt.Errorf("failed to create daemon: %w", err)
	}
	logrus.Infof("daemon %s is ready to mount", opts.ID)
	timing.Stage("create_daemon", time.Since(stageStart))

	// Stage 4: Get daemon
	stageStart = time.Now()
	d := w.mgr.GetDaemon(opts.ID)
	if d == nil {
		err := fmt.Errorf("can't find daemon, id = %s", opts.ID)
		timing.Fail(err)
		return nil, err
	}
	info := &MountInfo{
		MountPoint: d.MountPoint(),
		FilePath:   filepath.Join(d.MountPoint(), d.Name()),
	}
	timing.Stage("get_daemon", time.Since(stageStart))

	// Stage 5: Mount daemon (this will have its own detailed timing)
	stageStart = time.Now()
	logrus.WithFields(logrus.Fields{
		"daemon_id":   opts.ID,
		"mount_point": d.MountPoint(),
		"source_type": "oss",
	}).Info("mount path begin daemon mount")
	generation, mountErr := d.MountWithPhysicalBinding(nativeMountBinding(bind, daemonID, ""))
	if mountErr != nil {
		err = mountErr
		timing.Fail(err)
		return nil, fmt.Errorf("failed to mount %s: %w", opts.ID, err)
	}
	info.PhysicalGeneration = generation
	if err := w.mgr.SetDaemonReferencedIfPhysicalGeneration(opts.ID, generation, true); err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{
		"daemon_id":   opts.ID,
		"mount_point": d.MountPoint(),
		"file_path":   info.FilePath,
		"source_type": "oss",
	}).Info("mount path daemon mount completed")
	timing.Stage("daemon_mount", time.Since(stageStart))

	return info, nil
}

func (w *HttpWorker) UnmountOSS(req *OSSUmountRequest) (*MountInfo, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if req == nil || !validMountGeneration(req.PhysicalGeneration) {
		return nil, fmt.Errorf("original mount generation is required")
	}
	// Generate daemon ID
	id := generateOSSID(req.Endpoint, req.Bucket, req.Object)

	// Start API timing
	timing, _ := StartAPITimedOperation(w.ctx, "api.UnmountOSS", id)
	defer timing.End()

	// Stage 1: Get daemon
	stageStart := time.Now()
	d := w.mgr.GetDaemon(id)
	if d == nil {
		err := fmt.Errorf("no daemon %s", id)
		timing.Fail(err)
		return nil, err
	}
	timing.Stage("get_daemon", time.Since(stageStart))

	// Stage 2: Unmount daemon (this will have its own detailed timing)
	stageStart = time.Now()
	logrus.WithFields(logrus.Fields{
		"daemon_id":   id,
		"mount_point": d.MountPoint(),
		"source_type": "oss",
	}).Info("unmount path begin daemon unmount")
	err = d.UnmountIfPhysicalGeneration(req.PhysicalGeneration)
	if err != nil {
		timing.Fail(err)
		return nil, fmt.Errorf("failed to umount daemon %s: %w", id, err)
	}
	if err := w.mgr.SetDaemonReferencedIfPhysicalGeneration(id, req.PhysicalGeneration, false); err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{
		"daemon_id":   id,
		"mount_point": d.MountPoint(),
		"source_type": "oss",
	}).Info("unmount path daemon unmount completed")
	timing.Stage("daemon_unmount", time.Since(stageStart))

	return &MountInfo{MountPoint: d.MountPoint(), FilePath: filepath.Join(d.MountPoint(), d.Name())}, nil
}

func (w *HttpWorker) MountNydus(req *NydusMountRequest) (*MountInfo, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if req != nil && req.OperationID != "" {
		return w.executeMountOperation(req.OperationID, "nydus", "", req.PhysicalGeneration, req, func(bind mountBinding) (*MountInfo, error) { return w.mountNydus(req, bind) })
	}
	return w.mountNydus(req, nil)
}

func (w *HttpWorker) mountNydus(req *NydusMountRequest, bind mountBinding) (*MountInfo, error) {
	if req == nil {
		return nil, fmt.Errorf("mount source is required")
	}
	if req.PhysicalGeneration != "" {
		return w.recoverDaemonMountBound(generateNydusID(req.ImageURL), req.ImageURL, req.PhysicalGeneration, false, bind)
	}
	// Generate daemon ID
	id := generateNydusID(req.ImageURL)

	// Start API timing
	timing, _ := StartAPITimedOperation(w.ctx, "api.MountNydus", id)
	defer timing.End()

	// Stage 1: Validate
	stageStart := time.Now()
	if w.nydusClient == nil {
		err := fmt.Errorf("nydus client is not initialized")
		timing.Fail(err)
		return nil, err
	}
	if req.ImageURL == "" {
		err := fmt.Errorf("image_url is required")
		timing.Fail(err)
		return nil, err
	}
	timing.Stage("validate_request", time.Since(stageStart))

	// Stage 2: Check if daemon already exists
	stageStart = time.Now()
	d := w.mgr.GetDaemon(id)
	if d != nil {
		logrus.Infof("daemon %s for image %s already exists, reusing it", id, req.ImageURL)

		info := &MountInfo{
			MountPoint:   d.MountPoint(),
			FilePath:     "",
			Env:          d.Env(),
			ImageProcess: d.ImageProcess(),
		}
		timing.Stage("check_existing_daemon", time.Since(stageStart))

		// Mount if not already mounted
		stageStart = time.Now()
		generation, err := d.MountWithPhysicalBinding(nativeMountBinding(bind, id, req.ImageURL))
		if err != nil {
			timing.Fail(err)
			return nil, fmt.Errorf("failed to mount existing daemon %s: %w", id, err)
		}
		info.PhysicalGeneration = generation
		if err := w.mgr.SetDaemonReferencedIfPhysicalGeneration(id, generation, true); err != nil {
			return nil, err
		}
		timing.Stage("mount_existing_daemon", time.Since(stageStart))

		return info, nil
	}
	timing.Stage("check_existing_daemon", time.Since(stageStart))

	// Stage 3: Create daemon options
	stageStart = time.Now()
	opts := &distillfs.DaemonCreateOpt{
		ID:         id,
		Name:       strings.ReplaceAll(req.ImageURL, "/", "_"),
		MountPoint: req.MountPoint,
		SourceType: "nydus",
		ImageURL:   req.ImageURL,
	}
	logrus.WithFields(logrus.Fields{
		"daemon_id":   opts.ID,
		"mount_point": req.MountPoint,
		"source_type": "nydus",
		"image_url":   req.ImageURL,
	}).Info("mount path daemon info")
	timing.Stage("prepare_options", time.Since(stageStart))

	// Stage 4: Create daemon (bootstrap download happens here)
	stageStart = time.Now()
	if err := w.mgr.CreateDaemon(opts); err != nil {
		timing.Fail(err)
		return nil, fmt.Errorf("failed to create daemon: %w", err)
	}
	logrus.Infof("daemon %s is ready to mount", opts.ID)
	timing.Stage("create_daemon", time.Since(stageStart))

	// Stage 5: Get daemon
	stageStart = time.Now()
	d = w.mgr.GetDaemon(opts.ID)
	if d == nil {
		err := fmt.Errorf("can't find daemon, id = %s", opts.ID)
		timing.Fail(err)
		return nil, err
	}

	info := &MountInfo{
		MountPoint: d.MountPoint(),
		FilePath:   "",
	}
	timing.Stage("get_daemon", time.Since(stageStart))

	// Stage 6: Mount daemon
	stageStart = time.Now()
	logrus.WithFields(logrus.Fields{
		"daemon_id":   opts.ID,
		"mount_point": d.MountPoint(),
		"source_type": "nydus",
		"image_url":   req.ImageURL,
	}).Info("mount path begin daemon mount")
	generation, err := d.MountWithPhysicalBinding(nativeMountBinding(bind, id, req.ImageURL))
	if err != nil {
		timing.Fail(err)
		return nil, fmt.Errorf("failed to mount %s: %w", opts.ID, err)
	}
	info.PhysicalGeneration = generation
	if err := w.mgr.SetDaemonReferencedIfPhysicalGeneration(opts.ID, generation, true); err != nil {
		return nil, err
	}
	info.Env = d.Env()
	info.ImageProcess = d.ImageProcess()
	logrus.WithFields(logrus.Fields{
		"daemon_id":   opts.ID,
		"mount_point": d.MountPoint(),
		"source_type": "nydus",
		"image_url":   req.ImageURL,
	}).Info("mount path daemon mount completed")
	timing.Stage("daemon_mount", time.Since(stageStart))

	return info, nil
}

func (w *HttpWorker) UnmountNydus(req *NydusUmountRequest) (*MountInfo, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if req == nil || !validMountGeneration(req.PhysicalGeneration) {
		return nil, fmt.Errorf("original mount generation is required")
	}
	// Generate daemon ID
	id := generateNydusID(req.ImageURL)

	// Start API timing
	timing, _ := StartAPITimedOperation(w.ctx, "api.UnmountNydus", id)
	defer timing.End()

	// Stage 1: Validate
	stageStart := time.Now()
	if req.ImageURL == "" {
		err := fmt.Errorf("image_url is required")
		timing.Fail(err)
		return nil, err
	}
	timing.Stage("validate_request", time.Since(stageStart))

	// Stage 2: Get daemon
	stageStart = time.Now()
	d := w.mgr.GetDaemon(id)
	if d == nil {
		err := fmt.Errorf("no daemon %s", id)
		timing.Fail(err)
		return nil, err
	}
	timing.Stage("get_daemon", time.Since(stageStart))

	// Stage 3: Unmount daemon
	stageStart = time.Now()
	logrus.WithFields(logrus.Fields{
		"daemon_id":   id,
		"mount_point": d.MountPoint(),
		"source_type": "nydus",
		"image_url":   req.ImageURL,
	}).Info("unmount path begin daemon unmount")
	err = d.UnmountIfPhysicalGeneration(req.PhysicalGeneration)
	if err != nil {
		timing.Fail(err)
		return nil, fmt.Errorf("failed to umount daemon %s: %w", id, err)
	}
	if err := w.mgr.SetDaemonReferencedIfPhysicalGeneration(id, req.PhysicalGeneration, false); err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{
		"daemon_id":   id,
		"mount_point": d.MountPoint(),
		"source_type": "nydus",
		"image_url":   req.ImageURL,
	}).Info("unmount path daemon unmount completed")
	timing.Stage("daemon_unmount", time.Since(stageStart))

	return &MountInfo{MountPoint: d.MountPoint(), FilePath: ""}, nil
}

type nydusMountAttempt struct {
	physicalGeneration string
	mountPoint         string
	env                []string
	imageProcess       *imageconfig.Process
	detected           bool
}

// tryMountNydus attempts to mount an image as Nydus format.
// Returns mount point on success, or error if image is not Nydus or mount fails.
func (w *HttpWorker) tryMountNydus(imageURL string) (nydusMountAttempt, error) {
	return w.tryMountNydusWithBinding(imageURL, nil)
}

func (w *HttpWorker) tryMountNydusWithBinding(imageURL string, bind mountBinding) (nydusMountAttempt, error) {
	// Check cache first
	if isNydus, found := w.nydusCache.Get(imageURL); found {
		if isNydus {
			logrus.Infof("cache hit: %s is a Nydus image, routing to Nydus mount", imageURL)
			info, err := w.mountNydus(&NydusMountRequest{ImageURL: imageURL}, bind)
			if err != nil {
				return nydusMountAttempt{detected: true}, fmt.Errorf("failed to mount Nydus image: %w", err)
			}
			return nydusMountAttempt{physicalGeneration: info.PhysicalGeneration, mountPoint: info.MountPoint, env: info.Env, imageProcess: info.ImageProcess, detected: true}, nil
		} else {
			logrus.Debugf("cache hit: %s is not a Nydus image", imageURL)
			return nydusMountAttempt{}, fmt.Errorf("not a Nydus image (cached)")
		}
	}

	attempt := func() (nydusMountAttempt, error) {
		// Double-check cache inside singleflight.
		if isNydus, found := w.nydusCache.Get(imageURL); found {
			if !isNydus {
				return nydusMountAttempt{}, fmt.Errorf("not a Nydus image (cached)")
			}
			info, err := w.mountNydus(&NydusMountRequest{ImageURL: imageURL}, bind)
			if err != nil {
				return nydusMountAttempt{detected: true}, fmt.Errorf("failed to mount Nydus image: %w", err)
			}
			return nydusMountAttempt{physicalGeneration: info.PhysicalGeneration, mountPoint: info.MountPoint, env: info.Env, imageProcess: info.ImageProcess, detected: true}, nil
		}

		// Cache miss, fetch and check.
		logrus.Debugf("cache miss for %s, fetching from registry", imageURL)
		img, err := w.nydusClient.FetchImage(w.ctx, imageURL, "", false)
		if err != nil {
			return nydusMountAttempt{}, fmt.Errorf("failed to fetch image: %w", err)
		}

		isNydus, err := nydus.IsNydusImage(img)
		if err != nil {
			return nydusMountAttempt{}, fmt.Errorf("failed to check image format: %w", err)
		}
		w.nydusCache.Set(imageURL, isNydus)

		if !isNydus {
			return nydusMountAttempt{}, fmt.Errorf("not a Nydus image")
		}

		logrus.Infof("detected Nydus image at %s, routing to Nydus mount", imageURL)
		info, err := w.mountNydus(&NydusMountRequest{ImageURL: imageURL}, bind)
		if err != nil {
			return nydusMountAttempt{detected: true}, fmt.Errorf("failed to mount Nydus image: %w", err)
		}
		return nydusMountAttempt{physicalGeneration: info.PhysicalGeneration, mountPoint: info.MountPoint, env: info.Env, imageProcess: info.ImageProcess, detected: true}, nil
	}
	if bind != nil {
		return attempt()
	} // Every owner must execute its own binding.
	return w.mountNydusOnce(imageURL, attempt)
}

func (w *HttpWorker) mountNydusOnce(imageURL string, fn func() (nydusMountAttempt, error)) (nydusMountAttempt, error) {
	v, err, _ := w.nydusDetectSF.Do(imageURL, func() (interface{}, error) {
		return fn()
	})
	attempt, ok := v.(nydusMountAttempt)
	if ok {
		return attempt, err
	}
	if err != nil {
		return nydusMountAttempt{}, err
	}
	if v == nil {
		return nydusMountAttempt{}, nil
	}
	if !ok {
		return nydusMountAttempt{}, fmt.Errorf("invalid singleflight result type for nydus mount")
	}
	return nydusMountAttempt{}, nil
}

func (w *HttpWorker) MountOCI(req *OCIMountRequest) (*OCIMountResponse, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if req != nil && req.OperationID != "" {
		if !req.RequirePhysicalGeneration {
			return nil, fmt.Errorf("mount operation requires physical ownership")
		}
		info, err := w.executeMountOperation(req.OperationID, "oci", req.ImageURL, req.PhysicalGeneration, req, func(bind mountBinding) (*MountInfo, error) {
			response, err := w.mountOCI(req, bind)
			if err != nil {
				return nil, err
			}
			return &MountInfo{MountPoint: response.MountPath, Env: response.Env, ImageProcess: response.ImageProcess, PhysicalGeneration: response.PhysicalGeneration, Released: response.Released, ReleasePending: response.ReleasePending}, nil
		})
		if err != nil {
			return nil, err
		}
		return &OCIMountResponse{MountPath: info.MountPoint, Env: info.Env, ImageProcess: info.ImageProcess, PhysicalGeneration: info.PhysicalGeneration, Released: info.Released, ReleasePending: info.ReleasePending}, nil
	}
	return w.mountOCI(req, nil)
}

func (w *HttpWorker) mountOCI(req *OCIMountRequest, bind mountBinding) (*OCIMountResponse, error) {
	if req == nil || req.ImageURL == "" {
		return nil, fmt.Errorf("image_url is required")
	}
	unlock := w.acquireMountRouteLock(req.ImageURL)
	defer unlock()
	if req.PhysicalGeneration != "" {
		return w.recoverOCIMountBound(req, bind)
	}
	if req.RequirePhysicalGeneration && w.mountStore == nil {
		return nil, fmt.Errorf("original image mount requires its persistent route")
	}
	if w.ociMgr == nil {
		return nil, fmt.Errorf("oci manager is not initialized")
	}
	if req.ImageURL == "" {
		return nil, fmt.Errorf("image_url is required")
	}

	// Try to detect Nydus image if nydusClient is available
	if w.nydusClient != nil {
		// Try original URL
		if attempt, err := w.tryMountNydusWithBinding(req.ImageURL, bind); err == nil {
			if err := w.recordMountGeneration(req.ImageURL, "nydus", req.ImageURL, attempt.mountPoint, attempt.physicalGeneration); err != nil {
				return nil, err
			}
			return &OCIMountResponse{PhysicalGeneration: attempt.physicalGeneration, MountPath: attempt.mountPoint, Env: attempt.env, ImageProcess: attempt.imageProcess}, nil
		} else if attempt.detected {
			logrus.WithError(err).Warnf("detected Nydus image for %s but Nydus mount failed, skip OCI fallback", req.ImageURL)
			return nil, err
		}

		// Try with suffix if configured
		if w.nydusSuffix != "" {
			imageWithSuffix := req.ImageURL + w.nydusSuffix
			logrus.Infof("trying Nydus detection with suffix: %s", imageWithSuffix)
			if attempt, err := w.tryMountNydusWithBinding(imageWithSuffix, bind); err == nil {
				if err := w.recordMountGeneration(req.ImageURL, "nydus", imageWithSuffix, attempt.mountPoint, attempt.physicalGeneration); err != nil {
					return nil, err
				}
				return &OCIMountResponse{PhysicalGeneration: attempt.physicalGeneration, MountPath: attempt.mountPoint, Env: attempt.env, ImageProcess: attempt.imageProcess}, nil
			} else if attempt.detected {
				logrus.WithError(err).Warnf("detected Nydus image for %s via suffix %s but Nydus mount failed, skip OCI fallback", req.ImageURL, imageWithSuffix)
				return nil, err
			}
		}
	}

	if req.RequirePhysicalGeneration {
		return nil, fmt.Errorf("OCI physical mount ownership is not supported yet")
	}

	// Fallback to regular OCI mount flow.
	logrus.Infof("no Nydus image detected, using OCI overlay mount for %s", req.ImageURL)
	mountPoint, envVars, imageProcess, err := w.ociMgr.MountImageConfigWithContext(w.ctx, req.ImageURL)
	if err != nil {
		return nil, err
	}
	if err := w.recordMount(req.ImageURL, "oci", "", mountPoint); err != nil {
		return nil, err
	}
	return &OCIMountResponse{MountPath: mountPoint, Env: envVars, ImageProcess: imageProcess}, nil
}

// ImageProcess resolves process metadata for an already mounted OCI or Nydus
// image. It is separate from MountOCI so old cached mounts need registry access
// only when a caller explicitly requests inherited image startup.
func (w *HttpWorker) ImageProcess(imageURL string) (*imageconfig.Process, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if imageURL == "" {
		return nil, fmt.Errorf("image_url is required")
	}
	useOCI := false
	if w.mountStore != nil {
		record, err := w.mountStore.Get(imageURL)
		if err != nil {
			return nil, fmt.Errorf("read image mount record for %s: %w", imageURL, err)
		}
		if record != nil && record.MountType == "nydus" {
			if w.mgr == nil {
				return nil, fmt.Errorf("distillfs manager is not initialized")
			}
			nydusImageURL := record.NydusImageURL
			if nydusImageURL == "" {
				nydusImageURL = imageURL
			}
			d := w.mgr.GetDaemon(generateNydusID(nydusImageURL))
			if d == nil {
				return nil, fmt.Errorf("Nydus daemon for image %s is unavailable", imageURL)
			}
			return d.ResolveImageProcess(w.ctx)
		}
		if record != nil && record.MountType != "oci" {
			return nil, fmt.Errorf("unsupported mount type %q for image %s", record.MountType, imageURL)
		}
		useOCI = record != nil
	}

	// The mount store is optional. When disabled, discover an active Nydus
	// daemon using the same original/suffix candidates as MountOCI.
	if !useOCI && w.mgr != nil {
		candidates := []string{imageURL}
		if w.nydusSuffix != "" {
			candidates = append(candidates, imageURL+w.nydusSuffix)
		}
		for _, candidate := range candidates {
			if d := w.mgr.GetDaemon(generateNydusID(candidate)); d != nil {
				return d.ResolveImageProcess(w.ctx)
			}
		}
	}
	if w.ociMgr == nil {
		return nil, fmt.Errorf("oci manager is not initialized")
	}
	return w.ociMgr.ImageProcessWithContext(w.ctx, imageURL)
}

// Preserve the original routing record until both backend cleanup and the
// conditional durable removal succeed. This is not a mount-generation proof.
func (w *HttpWorker) recordMount(imageURL, mountType, nydusImageURL, mountPoint string) error {
	return w.recordMountGeneration(imageURL, mountType, nydusImageURL, mountPoint, "")
}

func (w *HttpWorker) recordMountGeneration(imageURL, mountType, nydusImageURL, mountPoint, generation string) error {
	if w.mountStore == nil {
		return nil
	}
	record := &MountRecord{PhysicalGeneration: generation, ImageURL: imageURL, MountType: mountType, NydusImageURL: nydusImageURL, MountPoint: mountPoint}
	if err := validateMountRoute(imageURL, record); err != nil {
		return err
	}
	existing, err := w.mountStore.Get(imageURL)
	if err != nil {
		return fmt.Errorf("read original image mount route: %w", err)
	}
	if existing != nil {
		if *existing != *record {
			return fmt.Errorf("image mount route changed before publication")
		}
	}
	if err := w.mountStore.Publish(imageURL, record); err != nil {
		return fmt.Errorf("persist image mount route: %w", err)
	}
	return nil
}

func validateMountRoute(imageURL string, r *MountRecord) error {
	if r == nil || r.ImageURL != imageURL || r.MountPoint == "" {
		return fmt.Errorf("image mount route is incomplete or changed")
	}
	if r.PhysicalGeneration != "" && (!validMountGeneration(r.PhysicalGeneration) || r.MountType != "nydus") {
		return fmt.Errorf("original image mount generation is invalid or unsupported")
	}
	switch r.MountType {
	case "nydus":
		if r.NydusImageURL == "" {
			return fmt.Errorf("Nydus mount route is incomplete")
		}
	case "oci":
		if r.NydusImageURL != "" {
			return fmt.Errorf("OCI mount route contains a foreign backend")
		}
	default:
		return fmt.Errorf("unknown image mount route")
	}
	return nil
}

func (w *HttpWorker) UnmountOCI(req *OCIUmountRequest) error {
	release, err := w.admit()
	if err != nil {
		return err
	}
	defer release()
	if req == nil || req.ImageURL == "" {
		return fmt.Errorf("image_url is required")
	}
	unlock := w.acquireMountRouteLock(req.ImageURL)
	defer unlock()
	if req.PhysicalGeneration != "" {
		if w.mountStore == nil {
			return fmt.Errorf("original mount requires its persistent route")
		}
		completed, err := w.mountStore.Completed(req.ImageURL, req.PhysicalGeneration)
		if err != nil {
			return err
		}
		if completed != nil {
			return nil
		}
	}
	if w.mountStore != nil {
		record, err := w.mountStore.Get(req.ImageURL)
		if err != nil {
			return fmt.Errorf("read original image mount route: %w", err)
		}
		if err := validateMountRoute(req.ImageURL, record); err != nil {
			return err
		}
		if record.PhysicalGeneration != req.PhysicalGeneration {
			return fmt.Errorf("original image mount generation changed or missing")
		}
		switch record.MountType {
		case "nydus":
			if w.mgr == nil {
				return fmt.Errorf("distillfs manager is not initialized")
			}
			_, err = w.UnmountNydus(&NydusUmountRequest{ImageURL: record.NydusImageURL, PhysicalGeneration: req.PhysicalGeneration})
		case "oci":
			if w.ociMgr == nil {
				return fmt.Errorf("oci manager is not initialized")
			}
			err = w.ociMgr.UnmountImageWithContext(w.ctx, req.ImageURL)
		}
		if err != nil {
			return err
		}
		if err := w.mountStore.DeleteIfRecord(req.ImageURL, record); err != nil {
			return fmt.Errorf("confirm original image mount route removal: %w", err)
		}
		return nil
	}
	if w.ociMgr == nil {
		return fmt.Errorf("oci manager is not initialized")
	}
	// Explicit legacy mode without a routing database retains its old API.
	return w.unmountOCILegacy(req)
}

// Serializes publication and removal for the same facade source. Backend GC,
// mount identity, deadlines and cross-process ownership are separate contracts.
type mountRouteLock struct {
	mu   sync.Mutex
	refs int
}

func (w *HttpWorker) acquireMountRouteLock(source string) func() {
	w.routeLocksMu.Lock()
	if w.routeLocks == nil {
		w.routeLocks = make(map[string]*mountRouteLock)
	}
	entry := w.routeLocks[source]
	if entry == nil {
		entry = &mountRouteLock{}
		w.routeLocks[source] = entry
	}
	entry.refs++
	w.routeLocksMu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		w.routeLocksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(w.routeLocks, source)
		}
		w.routeLocksMu.Unlock()
	}
}

// unmountOCILegacy is the original UnmountOCI logic, used when no mount store record exists.
func (w *HttpWorker) unmountOCILegacy(req *OCIUmountRequest) error {
	// Check if this image was mounted as Nydus
	if w.nydusClient != nil {
		// Check original URL
		nydusID := generateNydusID(req.ImageURL)
		if d := w.mgr.GetDaemon(nydusID); d != nil {
			logrus.Infof("legacy: image %s was mounted as Nydus, unmounting via Nydus", req.ImageURL)
			if err := d.Unmount(); err != nil {
				return err
			}
			w.mgr.SetDaemonReferenced(nydusID, false)
			return nil
		}

		// Check with suffix if configured
		if w.nydusSuffix != "" {
			imageWithSuffix := req.ImageURL + w.nydusSuffix
			nydusIDWithSuffix := generateNydusID(imageWithSuffix)
			if d := w.mgr.GetDaemon(nydusIDWithSuffix); d != nil {
				logrus.Infof("legacy: image %s (with suffix) was mounted as Nydus, unmounting via Nydus", imageWithSuffix)
				if err := d.Unmount(); err != nil {
					return err
				}
				w.mgr.SetDaemonReferenced(nydusIDWithSuffix, false)
				return nil
			}
		}
	}

	// Fallback to OCI manager unmount.
	logrus.Infof("unmounting image %s via OCI manager", req.ImageURL)
	return w.ociMgr.UnmountImageWithContext(w.ctx, req.ImageURL)
}

func (w *HttpWorker) CleanupDaemon(req *CleanupDaemonRequest) error {
	release, err := w.admit()
	if err != nil {
		return err
	}
	defer release()
	if req.DaemonID == "" {
		return fmt.Errorf("daemon_id is required")
	}
	return w.mgr.CleanupDaemon(req.DaemonID)
}

func (w *HttpWorker) ListDaemons() ([]distillfs.DaemonInfo, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	return w.mgr.ListDaemons(), nil
}

func (w *HttpWorker) ListMountedOCIImages() ([]string, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if w.ociMgr == nil {
		return nil, fmt.Errorf("oci manager is not initialized")
	}
	return w.ociMgr.ListMountedImageURLs()
}

func (w *HttpWorker) ListMountedOCIDetails() ([]oci.OciMountRecord, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if w.ociMgr == nil {
		return nil, fmt.Errorf("oci manager is not initialized")
	}
	return w.ociMgr.ListMountedDetails()
}

func (w *HttpWorker) prepareHttp() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/mount_operation_query", w.serveMountOperationQuery)
	mux.HandleFunc("/oss_mount", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("mount only support post method"))
			return
		}
		var req OSSMountRequest
		if err := decodeMountDispatch(request.Body, &req); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("invalid oss mount request format"))
			return
		}
		start := time.Now()
		info, err := w.MountOSS(&req)
		logrus.Infof("do mount take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to mount, err = %s", err)))
			return
		}
		body, _ := json.Marshal(info)
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})

	mux.HandleFunc("/oss_umount", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("unmount only support post method"))
			return
		}
		var req OSSUmountRequest
		if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("invalid oss unmount request format"))
			return
		}
		start := time.Now()
		info, err := w.UnmountOSS(&req)
		logrus.Infof("do umount take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to unmount, err = %s", err)))
			return
		}
		body, _ := json.Marshal(info)
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})

	mux.HandleFunc("/nydus_mount", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("nydus_mount only supports post method"))
			return
		}
		var req NydusMountRequest
		if err := decodeMountDispatch(request.Body, &req); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("invalid nydus mount request format"))
			return
		}
		start := time.Now()
		info, err := w.MountNydus(&req)
		logrus.Infof("do nydus_mount take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to mount nydus image, err = %s", err)))
			return
		}
		body, _ := json.Marshal(info)
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})

	mux.HandleFunc("/nydus_umount", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("nydus_umount only supports post method"))
			return
		}
		var req NydusUmountRequest
		if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("invalid nydus unmount request format"))
			return
		}
		start := time.Now()
		info, err := w.UnmountNydus(&req)
		logrus.Infof("do nydus_umount take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to unmount nydus image, err = %s", err)))
			return
		}
		body, _ := json.Marshal(info)
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})

	mux.HandleFunc("/oci_mount", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("oci_mount only supports post method"))
			return
		}
		var req OCIMountRequest
		if err := decodeMountDispatch(request.Body, &req); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("invalid oci mount request format"))
			return
		}
		start := time.Now()
		resp, err := w.MountOCI(&req)
		logrus.Infof("do oci_mount take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to mount oci image, err = %s", err)))
			return
		}
		body, _ := json.Marshal(resp)
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})

	mux.HandleFunc("/oci_umount", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("oci_umount only supports post method"))
			return
		}
		var req OCIUmountRequest
		if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("invalid oci umount request format"))
			return
		}
		start := time.Now()
		err := w.UnmountOCI(&req)
		logrus.Infof("do oci_umount take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to umount oci image, err = %s", err)))
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("ok"))
	})

	mux.HandleFunc("/cleanup_daemon", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("cleanup_daemon only supports post method"))
			return
		}
		var req CleanupDaemonRequest
		if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("invalid cleanup daemon request format"))
			return
		}
		start := time.Now()
		err := w.CleanupDaemon(&req)
		logrus.Infof("do cleanup_daemon take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to cleanup daemon, err = %s", err)))
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("ok"))
	})

	mux.HandleFunc("/list_daemons", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("list_daemons only supports GET method"))
			return
		}
		start := time.Now()
		daemons, err := w.ListDaemons()
		logrus.Infof("do list_daemons take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to list daemons, err = %s", err)))
			return
		}
		body, _ := json.Marshal(daemons)
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})

	mux.HandleFunc("/list_oci_mounts", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("list_oci_mounts only supports GET method"))
			return
		}
		start := time.Now()
		imageURLs, err := w.ListMountedOCIImages()
		logrus.Infof("do list_oci_mounts take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to list oci mounts, err = %s", err)))
			return
		}
		body, _ := json.Marshal(map[string][]string{"image_urls": imageURLs})
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})

	mux.HandleFunc("/list_oci_mount_details", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write([]byte("list_oci_mount_details only supports GET method"))
			return
		}
		start := time.Now()
		mounts, err := w.ListMountedOCIDetails()
		logrus.Infof("do list_oci_mount_details take %.6f s, err = %v", time.Since(start).Seconds(), err)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write([]byte(fmt.Sprintf("failed to list oci mount details, err = %s", err)))
			return
		}
		body, _ := json.Marshal(map[string][]oci.OciMountRecord{"mounts": mounts})
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})

	return mux
}

func (w *HttpWorker) ServeHttp(sockPath string) error {
	if sockPath == "" {
		return fmt.Errorf("empty socket path")
	}
	mux := w.prepareHttp()
	_, err := os.Stat(sockPath)
	if err == nil {
		os.Remove(sockPath)
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to create unix socket %s: %w", sockPath, err)
	}
	server := http.Server{
		Handler: mux,
	}
	return server.Serve(listener)
}

type HttpClient struct {
	clt *http.Client
}

func NewHttpClient(sockPath string) *HttpClient {
	if sockPath == "" {
		sockPath = DefaultHttpSockPath
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, "unix", sockPath)
			},
		},
	}
	return &HttpClient{clt: client}
}

func (c *HttpClient) MountOSS(req *OSSMountRequest) (*MountInfo, error) {
	body, _ := json.Marshal(req)
	resp, err := c.clt.Post("http://unix/oss_mount", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to mount oss: %s, err: %v", req, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to mount oss: %s, err: %s", req, string(errMsg))
	}
	mi := &MountInfo{}
	if err = json.NewDecoder(resp.Body).Decode(mi); err != nil {
		return nil, fmt.Errorf("invalid reply body format: %v", err)
	}
	return mi, nil
}

func (c *HttpClient) UmountOSS(req *OSSUmountRequest) error {
	body, _ := json.Marshal(req)
	resp, err := c.clt.Post("http://unix/oss_umount", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to umount oss: %s, err: %v", req, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to umount oss: %s, err: %s", req, string(errMsg))
	}
	return nil
}

func (c *HttpClient) MountOCI(req *OCIMountRequest) (*OCIMountResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := c.clt.Post("http://unix/oci_mount", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to mount oci image: %s, err: %v", req, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to mount oci image: %s, err: %s", req, string(errMsg))
	}
	var result OCIMountResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("invalid reply body format: %v", err)
	}
	if result.MountPath == "" {
		return nil, fmt.Errorf("mount_path not found in response")
	}
	return &result, nil
}

func (c *HttpClient) UmountOCI(req *OCIUmountRequest) error {
	body, _ := json.Marshal(req)
	resp, err := c.clt.Post("http://unix/oci_umount", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to umount oci image: %s, err: %v", req, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to umount oci image: %s, err: %s", req, string(errMsg))
	}
	return nil
}

func (c *HttpClient) CleanupDaemon(req *CleanupDaemonRequest) error {
	body, _ := json.Marshal(req)
	resp, err := c.clt.Post("http://unix/cleanup_daemon", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to cleanup daemon: %s, err: %v", req.DaemonID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to cleanup daemon: %s, err: %s", req.DaemonID, string(errMsg))
	}
	return nil
}

func (c *HttpClient) ListDaemons() ([]distillfs.DaemonInfo, error) {
	resp, err := c.clt.Get("http://unix/list_daemons")
	if err != nil {
		return nil, fmt.Errorf("failed to list daemons, err: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list daemons, err: %s", string(errMsg))
	}
	var daemons []distillfs.DaemonInfo
	if err = json.NewDecoder(resp.Body).Decode(&daemons); err != nil {
		return nil, fmt.Errorf("invalid reply body format: %v", err)
	}
	return daemons, nil
}

func (c *HttpClient) ListMountedOCIImages() ([]string, error) {
	resp, err := c.clt.Get("http://unix/list_oci_mounts")
	if err != nil {
		return nil, fmt.Errorf("failed to list oci mounts, err: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list oci mounts, err: %s", string(errMsg))
	}
	var result struct {
		ImageURLs []string `json:"image_urls"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("invalid reply body format: %v", err)
	}
	return result.ImageURLs, nil
}

func (c *HttpClient) ListMountedOCIDetails() ([]oci.OciMountRecord, error) {
	resp, err := c.clt.Get("http://unix/list_oci_mount_details")
	if err != nil {
		return nil, fmt.Errorf("failed to list oci mount details, err: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list oci mount details, err: %s", string(errMsg))
	}
	var result struct {
		Mounts []oci.OciMountRecord `json:"mounts"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("invalid reply body format: %v", err)
	}
	return result.Mounts, nil
}
