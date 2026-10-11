// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"fmt"
	"strings"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

const generationLeaseLimit = 65536

func validLeaseGeneration(generation string) bool {
	return generation != "" && len(generation) <= 128 &&
		strings.IndexFunc(generation, func(r rune) bool { return r <= ' ' || r >= 127 }) == -1
}

// AllocateForGeneration durably assigns a cgroup to one physical resource
// generation before handoff. A persistence error returns the original path
// with the error; the lease remains active and must be reconciled by its owner.
func (c *CgroupManager) AllocateForGeneration(generation string) (string, error) {
	if !validLeaseGeneration(generation) {
		return "", fmt.Errorf("invalid cgroup lease generation: %w", errord.ErrInvalidArgument)
	}
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if _, complete := c.completedGenerations[generation]; complete {
		return "", fmt.Errorf("cgroup lease generation is already retired: %w", errord.ErrFailedPrecondition)
	}
	for _, owner := range c.leaseOwners {
		if owner == generation {
			return "", fmt.Errorf("cgroup lease generation is already assigned: %w", errord.ErrFailedPrecondition)
		}
	}
	if len(c.leaseOwners)+len(c.completedGenerations) >= generationLeaseLimit {
		return "", fmt.Errorf("cgroup lease journal is full: %w", errord.ErrResourceExhausted)
	}
	if c.db == nil {
		return "", fmt.Errorf("cgroup lease store is unavailable: %w", errord.ErrUnavailable)
	}
	path, err := c.allocate()
	if err != nil {
		return path, err
	}
	if c.leaseOwners == nil {
		c.leaseOwners = make(map[string]string)
	}
	c.leaseOwners[path] = generation
	c.storeDirty.Store(true)
	if err := c.storeLeaseState("", ""); err != nil {
		return path, err
	}
	return path, nil
}

// RecycleForGeneration replays a durable original release without touching a
// later lease of the same path. Missing ownership is unknown, never a receipt.
func (c *CgroupManager) RecycleForGeneration(path, generation string) error {
	if !validLeaseGeneration(generation) || !belongsToRoot(path, c.rootName) {
		return fmt.Errorf("invalid generation-owned cgroup release: %w", errord.ErrInvalidArgument)
	}
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if completedPath, ok := c.completedGenerations[generation]; ok {
		if completedPath != path {
			return fmt.Errorf("cgroup release path differs from the original receipt: %w", errord.ErrFailedPrecondition)
		}
		return nil
	}
	if !c.usingID.Has(path) || c.leaseOwners[path] != generation {
		return fmt.Errorf("cgroup lease generation is missing or changed: %w", errord.ErrFailedPrecondition)
	}
	return c.recycle(path, generation)
}

func (c *CgroupManager) completeLeaseRelease(path, generation string) error {
	if generation != "" {
		if c.db == nil {
			return fmt.Errorf("cgroup lease store is unavailable: %w", errord.ErrUnavailable)
		}
		if err := c.storeLeaseState(path, generation); err != nil {
			return err
		}
		if c.completedGenerations == nil {
			c.completedGenerations = make(map[string]string)
		}
		c.completedGenerations[generation] = path
		delete(c.leaseOwners, path)
	}
	c.usingID.Pop(path)
	c.storeDirty.Store(true)
	return nil
}

// Called before workers start. Legacy active entries stay unowned; they are
// never silently assigned a generation or accepted by the conditional API.
func (c *CgroupManager) restoreGenerationLeases(state storedCgroupIDs) error {
	if (state.SchemaVersion != 0 && state.SchemaVersion != 2) ||
		(state.SchemaVersion == 0 && (len(state.LeaseOwners) != 0 || len(state.CompletedGenerations) != 0)) ||
		len(state.LeaseOwners)+len(state.CompletedGenerations) > generationLeaseLimit {
		return fmt.Errorf("cgroup lease journal schema or capacity is invalid: %w", errord.ErrFailedPrecondition)
	}
	owners := make(map[string]string, len(state.LeaseOwners))
	seen := make(map[string]bool, len(state.LeaseOwners))
	for path, generation := range state.LeaseOwners {
		if !belongsToRoot(path, c.rootName) || !c.usingID.Has(path) ||
			!validLeaseGeneration(generation) || seen[generation] {
			return fmt.Errorf("cgroup lease journal ownership is invalid: %w", errord.ErrFailedPrecondition)
		}
		owners[path] = generation
		seen[generation] = true
	}
	completed := make(map[string]string, len(state.CompletedGenerations))
	for generation, path := range state.CompletedGenerations {
		if !validLeaseGeneration(generation) || !belongsToRoot(path, c.rootName) || seen[generation] {
			return fmt.Errorf("cgroup lease journal completion is invalid: %w", errord.ErrFailedPrecondition)
		}
		completed[generation] = path
	}
	c.leaseOwners = owners
	c.completedGenerations = completed
	return nil
}
