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
	"errors"
	"fmt"
	"sync"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/sirupsen/logrus"
)

type preparedStartResources struct {
	sandbox.OccupiedResource
	sandboxIP string
	network   *networkmanager.NetResource
}

// A preparation error after allocation cannot authorize an implicit rollback.
// The creation owner retains the intent and leases until durable reconciliation
// can confirm every cleanup step for the original physical generation.
var errPhysicalPreparationIncomplete = errors.New("physical preparation requires reconciliation")

func (h *sandboxService) prepareStartResources(runtimeName, sandboxID, generation string) (*preparedStartResources, error) {
	required, err := requiredStartResources(runtimeName, h.config.DisableCgroup)
	if err != nil {
		return nil, err
	}
	resources, err := prepareRequiredStartResources(
		sandboxID,
		required,
		func(name string) (string, *networkmanager.NetResource, error) {
			return h.allocateStartResource(runtimeName, sandboxID, generation, name)
		},
	)
	resources.Generation = generation
	return resources, err
}

func prepareRequiredStartResources(
	sandboxID string,
	required []string,
	allocate func(string) (string, *networkmanager.NetResource, error),
) (*preparedStartResources, error) {
	results := make([]resourceResult, len(required))
	var wg sync.WaitGroup
	for i, name := range required {
		wg.Go(func() {
			value, network, err := allocate(name)
			results[i] = resourceResult{name: name, value: value, network: network, err: err}
		})
	}
	wg.Wait()

	resources := &preparedStartResources{
		OccupiedResource: sandbox.OccupiedResource{
			ID:        sandboxID,
			Resources: make(map[string]string, len(required)),
		},
	}

	var allocationErrs []error
	for _, result := range results {
		if result.err != nil {
			allocationErrs = append(allocationErrs, fmt.Errorf("allocate resource %s failed: %w", result.name, result.err))
		}
		// A nonempty lease with an error is still owned. An allocator may
		// have applied the allocation before its final confirmation failed.
		if result.value != "" {
			resources.Resources[result.name] = result.value
		}
		if result.network != nil {
			resources.network = result.network
			resources.sandboxIP = result.network.Ip.String()
		}
	}
	return resources, errors.Join(allocationErrs...)
}

func requiredStartResources(runtimeName string, disableCgroup bool) ([]string, error) {
	configured := config.RuntimeResources[runtimeName]
	if configured == nil {
		return nil, fmt.Errorf("runtime %s is not supported when preparing resources", runtimeName)
	}
	if disableCgroup && runtimeName != config.RuntimeNameRunsc {
		return nil, fmt.Errorf("runtime %s requires cgroup management", runtimeName)
	}
	required := make([]string, 0, len(configured))
	for _, name := range configured {
		if disableCgroup && name == config.ResourceNameCgroup {
			continue
		}
		required = append(required, name)
	}
	return required, nil
}

type resourceResult struct {
	name    string
	value   string
	network *networkmanager.NetResource
	err     error
}

func (h *sandboxService) allocateStartResource(
	runtimeName,
	sandboxID,
	generation,
	name string,
) (string, *networkmanager.NetResource, error) {
	switch name {
	case config.ResourceNameCgroup:
		if h.cgroupMgr == nil {
			return "", nil, fmt.Errorf("cgroup manager not configured")
		}
		value, err := h.cgroupMgr.AllocateForGeneration(generation)
		return value, nil, err
	case config.ResourceNameInterface:
		if h.networkMgr == nil {
			return "", nil, fmt.Errorf("network manager not configured")
		}
		network, err := h.networkMgr.Prepare(runtimeName, sandboxID)
		if network == nil {
			return "", nil, err
		}
		return network.resource, network.config, err
	default:
		return "", nil, fmt.Errorf("resource %s is not registered", name)
	}
}

// deactivateStartNetwork disconnects a pooled TAP while retaining its lease.
// Runtime deletion must complete first, and ACL removal must happen afterward.
func (h *sandboxService) deactivateStartNetwork(resources sandbox.OccupiedResource) error {
	resource, ok := resources.Resources[config.ResourceNameInterface]
	if !ok || resource == "" {
		return nil
	}
	if h.networkMgr == nil {
		return fmt.Errorf("network manager not configured")
	}
	if err := h.networkMgr.Deactivate(resource); err != nil {
		return fmt.Errorf("deactivate sandbox network endpoint: %w", err)
	}
	return nil
}

func (h *sandboxService) releaseStartResources(resources sandbox.OccupiedResource) error {
	var errs []error
	for name, value := range resources.Resources {
		if err := h.releaseStartResource(name, value, resources.Generation); err != nil {
			errs = append(errs, fmt.Errorf("release resource %s[%s] failed: %w", name, value, err))
			continue
		}
		logrus.Infof("release resource %s[%s] success", name, value)
	}
	return errors.Join(errs...)
}

func (h *sandboxService) releaseStartResource(name, value, generation string) error {
	switch name {
	case config.ResourceNameCgroup:
		if h.cgroupMgr == nil {
			return fmt.Errorf("cgroup manager not configured")
		}
		if generation != "" {
			return h.cgroupMgr.RecycleForGeneration(value, generation)
		}
		return h.cgroupMgr.Recycle(value)
	case config.ResourceNameInterface:
		if h.networkMgr == nil {
			return fmt.Errorf("network manager not configured")
		}
		return h.networkMgr.Release(value)
	default:
		return fmt.Errorf("resource %s is not registered", name)
	}
}
