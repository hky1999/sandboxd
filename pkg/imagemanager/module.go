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

// Package imagemanager owns image and mount lifecycle state in-process.
package imagemanager

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/nydus"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
)

// Config corresponds to the [plugin.image] sandboxd configuration section.
type Config struct {
	ChunkDBSize       string // ChunkDB map capacity; empty uses the distill-fs default.
	Root              string
	DistillFsBin      string
	OSSTemplate       string
	NydusTemplate     string
	NydusSuffix       string
	OSSAuthsPath      string
	RegistryAuthsPath string
	CgroupMemoryLimit string // human-readable: "512MiB" / "2GiB" / raw bytes; "0" / "" = no limit
	DisableCgroup     bool
}

// Module owns the in-process distillfs Manager, OCI manager and HttpWorker.
// Lifecycle:
//
//	cfg := imagemanager.Config{...}
//	mod, err := imagemanager.NewModule(cfg)
//	mod.Start()              // currently a no-op
//	svc := mod.Service()     // hand to sandboxd consumers (langrtmanager, imagemount)
//	... use svc ...
//	mod.Stop()
type Module struct {
	cfg          Config
	mgr          distillfs.Manager
	ociMgr       *oci.Manager
	worker       *api.HttpWorker
	closedOnce   sync.Once
	owner        distillfs.ManagerLifecycle
	releaseOwner func()
	stopDone     chan struct{}
	stopErr      error
	healthy      atomic.Bool
}

// NewModule mirrors the standalone main.go setup: registry/nydus client
// init, distillfs manager init, OCI manager init, then HttpWorker over the
// shared mount_records.db. Failure of any stage is fatal — sandboxd cannot
// run sandboxes without image-mount plumbing.
func NewModule(cfg Config) (*Module, error) {
	if cfg.Root == "" {
		return nil, fmt.Errorf("imagemanager: Root is required")
	}
	if cfg.DistillFsBin == "" {
		cfg.DistillFsBin = "/usr/local/bin/distill_fs"
	}

	cgroupMemoryLimit, err := parseMemorySize(cfg.CgroupMemoryLimit)
	if err != nil {
		return nil, fmt.Errorf("imagemanager: parse cgroup_memory_limit %q: %w", cfg.CgroupMemoryLimit, err)
	}

	var sharedRegistryClient *imageregistry.Client
	var nydusClient *nydus.RegistryClient
	if cfg.RegistryAuthsPath != "" {
		var rerr error
		sharedRegistryClient, rerr = imageregistry.NewClient(cfg.RegistryAuthsPath)
		if rerr != nil {
			logrus.Warnf("imagemanager: registry client init failed (%v); proceeding without registry auth", rerr)
		} else {
			nydusClient = nydus.NewRegistryClientFromShared(sharedRegistryClient)
		}
	}

	mgr, err := distillfs.NewManager(&distillfs.ManagerConfig{
		ChunkDBSize:       cfg.ChunkDBSize,
		Context:           context.Background(),
		Root:              cfg.Root,
		OSSCfgPath:        cfg.OSSTemplate,
		NydusCfgPath:      cfg.NydusTemplate,
		BinPath:           cfg.DistillFsBin,
		NydusClient:       nydusClient,
		OSSAuthsPath:      cfg.OSSAuthsPath,
		RegistryAuthsPath: cfg.RegistryAuthsPath,
		CgroupMemoryLimit: cgroupMemoryLimit,
		DisableCgroup:     cfg.DisableCgroup,
	})
	if err != nil {
		return nil, fmt.Errorf("imagemanager: distillfs manager: %w", err)
	}
	owner := mgr.(distillfs.ManagerLifecycle)
	releaseOwner, err := owner.RetainOwnership()
	if err != nil {
		owner.StopAccepting()
		return nil, fmt.Errorf("imagemanager: retain root ownership: %w", err)
	}
	m := &Module{cfg: cfg, mgr: mgr, owner: owner, releaseOwner: releaseOwner}
	success := false
	defer func() {
		if !success {
			m.Stop()
		}
	}()

	ociMgr, err := oci.NewManager(cfg.Root, cfg.NydusTemplate, sharedRegistryClient)
	if err != nil {
		return nil, fmt.Errorf("imagemanager: oci manager: %w", err)
	}
	m.ociMgr = ociMgr

	// Mount records stay in the image-manager root, separate from sandbox
	// lifecycle metadata.
	dbPath := filepath.Join(cfg.Root, "mount_records.db")
	worker, err := api.NewHttpWorker(&api.HttpWorkerConfig{
		Manager:     mgr,
		OCIManager:  ociMgr,
		NydusClient: nydusClient,
		NydusSuffix: cfg.NydusSuffix,
		DBPath:      dbPath,
	})
	if err != nil {
		return nil, fmt.Errorf("imagemanager: http worker: %w", err)
	}

	m.worker = worker
	m.healthy.Store(true)
	success = true
	return m, nil
}

// Service returns the in-process Service implementation, satisfying the
// 4-call-site sandboxd contract previously fronted by api.NewHttpClient().
func (m *Module) Service() api.Service { return m.worker }

// Start currently has nothing to drive because the manager and worker start
// their background goroutines during NewModule.
func (m *Module) Start() error { return nil }

// ReconcileRecoveredDaemons removes distillfs daemons that were not claimed
// while sandbox filesystem state was restored.
func (m *Module) ReconcileRecoveredDaemons() error {
	return m.mgr.ReconcileRecoveredDaemons()
}

// Stop gives shutdown five seconds. A timeout retains ownership until the
// admitted work and backend workers have actually stopped.
func (m *Module) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.StopWithContext(ctx); err != nil {
		logrus.WithError(err).Warn("imagemanager shutdown has not completed")
	}
}

func (m *Module) StopWithContext(ctx context.Context) error {
	m.closedOnce.Do(func() {
		m.healthy.Store(false)
		m.stopDone = make(chan struct{})
		if m.owner != nil {
			m.owner.StopAccepting()
		}
		go func() {
			if m.worker != nil {
				m.stopErr = m.worker.CloseWithContext(context.Background())
			}
			if m.ociMgr != nil {
				if err := m.ociMgr.Close(); err != nil && m.stopErr == nil {
					m.stopErr = err
				}
			}
			if m.releaseOwner != nil {
				m.releaseOwner()
			}
			if m.owner != nil {
				if err := m.owner.Close(context.Background()); err != nil && m.stopErr == nil {
					m.stopErr = err
				}
			}
			close(m.stopDone)
		}()
	})
	select {
	case <-m.stopDone:
		return m.stopErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Healthy returns true while the module is constructed and not yet
// Stop()ped. A richer signal (e.g. distillfs daemon liveness aggregation)
// is left to a later iteration since Stop is the only well-defined unhealthy
// transition right now.
func (m *Module) Healthy() bool { return m.healthy.Load() }

// parseMemorySize mirrors the helper in the standalone main.go so that the
// flag's accepted values ("512MiB", "2GiB", "1024", "") behave identically.
func parseMemorySize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	re := regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?)\s*(B|KiB|MiB|GiB|TiB|KB|MB|GB|TB)$`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("unsupported format, use e.g. 512MiB, 2GiB, or plain bytes")
	}
	val, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, err
	}
	var multiplier float64
	switch strings.ToUpper(m[2]) {
	case "B":
		multiplier = 1
	case "KIB":
		multiplier = 1024
	case "MIB":
		multiplier = 1024 * 1024
	case "GIB":
		multiplier = 1024 * 1024 * 1024
	case "TIB":
		multiplier = 1024 * 1024 * 1024 * 1024
	case "KB":
		multiplier = 1000
	case "MB":
		multiplier = 1000 * 1000
	case "GB":
		multiplier = 1000 * 1000 * 1000
	case "TB":
		multiplier = 1000 * 1000 * 1000 * 1000
	}
	return int64(val * multiplier), nil
}
