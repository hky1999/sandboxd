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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// The journal lives in the existing OCI document, outside the resource- prefix
// read by CollectResourceByID. It survives a crash between owner retirement
// and pool persistence without authorizing a later Release of the old lease.
const retiredInterfaceAnnotation = "sandbox.akernel.dev/retired-interface"

type networkLeaseOwner struct {
	id, runtime, group, lease string
	specPath                  string
	document                  map[string]json.RawMessage
	annotations               map[string]string
	mode                      os.FileMode
}

func (h *sandboxService) retireStoppedNetworkLeases(sandboxRoot string) error {
	if h.config.DisableCgroup || h.cgroupMgr == nil {
		return nil
	}
	states := make(map[string]map[string]*runtimecore.State)
	for name, handler := range h.serviceHandler.Items() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		rows, err := handler.List(ctx)
		cancel()
		if err != nil {
			logrus.Warnf("retain network leases: runtime %s list failed: %v", name, err)
			continue
		}
		states[name] = make(map[string]*runtimecore.State)
		for _, row := range rows {
			if row == nil {
				continue
			}
			if _, duplicate := states[name][row.ID]; duplicate {
				return fmt.Errorf("ambiguous runtime identity %s during network recovery", row.ID)
			}
			states[name][row.ID] = row
		}
	}
	return retireNetworkLeases(h.store, sandboxRoot, func(owner networkLeaseOwner) bool {
		return h.networkOwnerStateStopped(owner, states[owner.runtime][owner.id])
	}, writeRetiredNetworkOwner)
}

func (h *sandboxService) networkOwnerStateStopped(owner networkLeaseOwner, state *runtimecore.State) bool {
	if h.config.DisableCgroup || h.cgroupMgr == nil || state == nil || state.ID != owner.id || state.Status != runtimecore.SandboxStatusExited {
		return false
	}
	root := h.config.CgroupRootName
	if root == "" {
		root = config.DefaultCgroupRoot
	}
	return retiredRuntimeHasNoTasks(state.InitProcessPid, owner.group, root, "/proc", "/sys/fs/cgroup")
}

// ACL recovery also sees the old sandbox before asynchronous exit cleanup.
// Re-prove its exit rather than treating an absent resource as implicit proof.
func (h *sandboxService) confirmNetworkOwnerStopped(owner networkLeaseOwner) bool {
	handler, ok := h.serviceHandler.Get(owner.runtime)
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	states, err := handler.List(ctx)
	if err != nil {
		return false
	}
	var match *runtimecore.State
	for _, state := range states {
		if state != nil && state.ID == owner.id {
			if match != nil {
				return false
			}
			match = state
		}
	}
	return h.networkOwnerStateStopped(owner, match)
}

// An exited status may precede process exit, and an empty cgroup alone says
// nothing about an unrecognized runtime. Require both kernel proofs, within
// the configured managed cgroup-v2 root. Unknowns retain the lease.
func retiredRuntimeHasNoTasks(pid int, group, configuredRoot, procRoot, cgroupMount string) bool {
	if pid <= 1 {
		return false
	}
	stat, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err == nil {
		end := strings.LastIndexByte(string(stat), ')')
		if end < 0 || len(stat) <= end+2 || (stat[end+2] != 'Z' && stat[end+2] != 'X') {
			return false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	if _, err := os.Stat(filepath.Join(cgroupMount, "cgroup.controllers")); err != nil {
		return false
	}
	root := filepath.Clean("/" + strings.TrimPrefix(configuredRoot, "/"))
	clean := filepath.Clean("/" + strings.TrimPrefix(group, "/"))
	if root == "/" || group == "" || !strings.HasPrefix(clean, root+"/") {
		return false
	}
	path := filepath.Join(cgroupMount, strings.TrimPrefix(clean, "/"))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	data, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
	if err != nil {
		return false
	}
	populated := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			if populated != "" {
				return false
			}
			populated = fields[1]
		}
	}
	return populated == "0"
}

func readNetworkLeaseOwners(root string) (map[string][]networkLeaseOwner, error) {
	owners := make(map[string][]networkLeaseOwner)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return owners, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !config.IsValidSandboxID(entry.Name()) {
			continue
		}
		if !entry.IsDir() {
			return nil, fmt.Errorf("unrecognized sandbox ownership entry %s", entry.Name())
		}
		bundle := filepath.Join(root, entry.Name())
		path := filepath.Join(bundle, config.SandboxSpecFile)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > 16<<20 {
			return nil, errors.New("invalid OCI document during network recovery")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(data, &document); err != nil {
			return nil, err
		}
		var annotations map[string]string
		if raw := document["annotations"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &annotations); err != nil {
				return nil, err
			}
		}
		active := annotations[config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface]
		retired := annotations[retiredInterfaceAnnotation]
		if active != "" && retired != "" {
			return nil, errors.New("ambiguous active/retired network owner")
		}
		lease := active
		if lease == "" {
			lease = retired
		}
		if lease == "" {
			continue
		}
		meta, err := os.ReadFile(filepath.Join(bundle, config.SandboxMetaFile))
		if err != nil {
			return nil, err
		}
		var metadata runtimeapi.SandboxMetadata
		if len(meta) > 1<<20 {
			return nil, errors.New("oversized sandbox metadata during network recovery")
		}
		if err := proto.Unmarshal(meta, &metadata); err != nil {
			return nil, err
		}
		if metadata.ID != entry.Name() || metadata.RuntimeHandler == "" {
			return nil, errors.New("inconsistent sandbox identity during network recovery")
		}
		group := annotations[config.ResourceAnnotationKeyPrefix+config.ResourceNameCgroup]
		var linux struct {
			Cgroup string `json:"cgroupsPath"`
		}
		if raw := document["linux"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &linux); err != nil {
				return nil, err
			}
		}
		if group == "" {
			group = linux.Cgroup
		} else if linux.Cgroup != "" && linux.Cgroup != group {
			return nil, errors.New("inconsistent cgroup ownership during network recovery")
		}
		owners[lease] = append(owners[lease], networkLeaseOwner{id: metadata.ID, runtime: metadata.RuntimeHandler, group: group, lease: lease, specPath: path, document: document, annotations: annotations, mode: info.Mode().Perm()})
	}
	return owners, nil
}

// Run before the interface pool and sandbox-manager monitors start. Retire
// the OCI claim first: a delayed old cleanup must not Release an identical
// resource string that has since been leased to a new sandbox.
func retireNetworkLeases(db store.DbStore, root string, stopped func(networkLeaseOwner) bool, writeOwner func(networkLeaseOwner, bool) error) error {
	data, err := db.LoadRaw(config.BridgeIpBucket)
	if errord.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	var leases []string
	if err := json.Unmarshal(document["items"], &leases); err != nil {
		return err
	}
	owners, err := readNetworkLeaseOwners(root)
	if err != nil {
		return fmt.Errorf("retain network leases: sandbox ownership unavailable: %w", err)
	}
	active := make(map[string]bool, len(leases))
	for _, lease := range leases {
		active[lease] = true
	}
	// A committed removal may have crashed before final journal cleanup.
	// Finish it before new allocations can reuse an identical lease string.
	for lease, claimants := range owners {
		if active[lease] {
			continue
		}
		for _, owner := range claimants {
			if owner.annotations[retiredInterfaceAnnotation] != "" {
				if err := writeOwner(owner, false); err != nil {
					return err
				}
			}
		}
	}
	kept := make([]string, 0, len(leases))
	var retired []networkLeaseOwner
	changed := false
	for _, lease := range leases {
		resource, err := networkmanager.NewNetResource(lease)
		if err != nil {
			return err
		}
		if resource.EndpointType != networkmanager.EndpointTypeTap || resource.SchemaVersion != networkmanager.NetResourceSchemaVersion {
			kept = append(kept, lease)
			continue
		}
		claimants := owners[lease]
		if len(claimants) > 1 {
			return errors.New("ambiguous sandbox owners for a pooled TAP lease; retaining all resources")
		}
		if len(claimants) != 1 || !stopped(claimants[0]) {
			kept = append(kept, lease)
			continue
		}
		if err := writeOwner(claimants[0], true); err != nil {
			return fmt.Errorf("retire network owner %s: %w", claimants[0].id, err)
		}
		retired = append(retired, claimants[0])
		changed = true
		logrus.Infof("retired stopped sandbox %s network lease before pool recovery", claimants[0].id)
	}
	if !changed {
		return nil
	}
	document["items"], err = json.Marshal(kept)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if err := db.StoreRaw(config.BridgeIpBucket, encoded); err != nil {
		return err
	}
	for _, owner := range retired {
		if err := writeOwner(owner, false); err != nil {
			return err
		}
	}
	return nil
}

func writeRetiredNetworkOwner(owner networkLeaseOwner, retiring bool) error {
	if owner.annotations == nil {
		return errors.New("missing network owner annotations")
	}
	if retiring {
		delete(owner.annotations, config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface)
		owner.annotations[retiredInterfaceAnnotation] = owner.lease
	} else {
		if owner.annotations[config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface] != "" {
			return errors.New("cannot finish retirement of an active network owner")
		}
		delete(owner.annotations, retiredInterfaceAnnotation)
	}
	encoded, err := json.Marshal(owner.annotations)
	if err != nil {
		return err
	}
	owner.document["annotations"] = encoded
	encoded, err = json.Marshal(owner.document)
	if err != nil {
		return err
	}
	if err := util.AtomicWriteFile(owner.specPath, encoded, owner.mode); err != nil {
		return err
	}
	// AtomicWriteFile syncs content; the rename also needs directory durability
	// before the corresponding pool entry can be removed durably.
	dir, err := os.Open(filepath.Dir(owner.specPath))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
