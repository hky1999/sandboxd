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
	"bufio"
	"os"
	"runtime"
	"strings"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointlocator"
	"github.com/inclusionAI/sandboxd/pkg/runtime/firecracker"
	"golang.org/x/sys/unix"
)

// buildCheckpointCatalogNode assembles the node record the catalog
// advertises at /api/v1/node: the node's identity and the software stack
// each enabled runtime restores with. The Firecracker face digests exactly
// the files its compatibility tuple seals, so a checkpoint that verifies
// locally also matches this node in the placement matrix.
func buildCheckpointCatalogNode(
	cfg config.Config,
	catalogCfg config.CheckpointCatalogConfig,
) (*checkpointlocator.NodeRecord, error) {
	id := catalogCfg.NodeID
	if id == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		id = hostname
	}
	record := &checkpointlocator.NodeRecord{ID: id}
	vendor, model := cpuFacts()
	record.CPUVendor, record.CPUModel = vendor, model
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		record.KernelRelease = unix.ByteSliceToString(uts.Release[:])
	}

	if firecrackerBinary, ok := cfg.RuntimeConfig.RuntimeBinary[config.RuntimeNameFirecracker]; ok {
		fc := cfg.RuntimeConfig.Firecracker
		face := checkpointlocator.RuntimeFace{Name: config.RuntimeNameFirecracker}
		face.Arch = runtime.GOARCH
		var err error
		if face.Firecracker, err = firecracker.StackFileDigest(firecrackerBinary); err != nil {
			return nil, err
		}
		if fc.KernelImagePath != "" {
			if face.Kernel, err = firecracker.StackFileDigest(fc.KernelImagePath); err != nil {
				return nil, err
			}
		}
		if fc.InitrdPath != "" {
			if face.Initrd, err = firecracker.StackFileDigest(fc.InitrdPath); err != nil {
				return nil, err
			}
		}
		face.KernelArgs = fc.KernelArgs
		record.Runtimes = append(record.Runtimes, face)
	}
	// Other runtimes (runsc, runc, kata) restore without a stack tuple
	// today; when they grow one, their faces join here.
	return record, nil
}

// cpuFacts reads the informational CPU identity from /proc/cpuinfo. Only
// the first processor is inspected, mirroring the fleet-homogeneity
// assumption other node-fact collectors make.
func cpuFacts() (vendor, model string) {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "vendor_id":
			vendor = strings.TrimSpace(value)
		case "model name":
			model = strings.TrimSpace(value)
		}
		if vendor != "" && model != "" {
			return vendor, model
		}
	}
	return vendor, model
}
