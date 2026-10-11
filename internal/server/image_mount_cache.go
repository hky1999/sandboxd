// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"

	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
)

type imageMountIdentity struct {
	Source     string
	Generation string
}

// entries selects the current source for a new owner; generations retains all
// original cleanup references. A completed old generation never aliases a live
// replacement's reference count, even when their paths are identical.
func findImageMountEntry(entries map[string]*imageMountEntry, generations map[imageMountIdentity]*imageMountEntry, source, expected string) (*imageMountEntry, error) {
	if expected == "" {
		if imageMountSourceBlocked(entries, generations, source) {
			return nil, fmt.Errorf("source release is unconfirmed")
		}
		entry := entries[source]
		if entry != nil && entry.retirementConfirmed {
			return nil, nil
		}
		return entry, nil
	}
	if !validFSPhysicalGeneration(expected) {
		return nil, fmt.Errorf("original mount generation is invalid")
	}
	entry := generations[imageMountIdentity{Source: source, Generation: expected}]
	if entry == nil && entries[source] != nil && entries[source].physicalGeneration == expected {
		entry = entries[source]
	}
	if entry != nil && entry.physicalGeneration != expected {
		return nil, fmt.Errorf("original cached mount generation changed")
	}
	return entry, nil
}

func imageMountSourceBlocked(entries map[string]*imageMountEntry, generations map[imageMountIdentity]*imageMountEntry, source string) bool {
	blocked := func(entry *imageMountEntry) bool {
		return entry != nil && entry.releaseUnconfirmed && !entry.retirementConfirmed
	}
	if blocked(entries[source]) {
		return true
	}
	for identity, entry := range generations {
		if identity.Source == source && blocked(entry) {
			return true
		}
	}
	return false
}

func rememberImageMountEntry(entries map[string]*imageMountEntry, generations map[imageMountIdentity]*imageMountEntry, source string, entry *imageMountEntry) error {
	if entry.physicalGeneration != "" {
		if !validFSPhysicalGeneration(entry.physicalGeneration) {
			return fmt.Errorf("cached mount generation is invalid")
		}
		identity := imageMountIdentity{Source: source, Generation: entry.physicalGeneration}
		if previous := generations[identity]; previous != nil && previous != entry {
			return fmt.Errorf("original cached mount generation cannot be reused")
		}
		generations[identity] = entry
	}
	previous := entries[source]
	if previous == nil || previous.releaseUnconfirmed && !entry.releaseUnconfirmed {
		entries[source] = entry
	}
	return nil
}

func forgetImageMountEntry(entries map[string]*imageMountEntry, generations map[imageMountIdentity]*imageMountEntry, source string, entry *imageMountEntry) {
	identity := imageMountIdentity{Source: source, Generation: entry.physicalGeneration}
	if generations[identity] == entry {
		delete(generations, identity)
	}
	if entries[source] == entry {
		delete(entries, source)
	}
}

// The caller has independently verified operation ID, request fingerprint,
// source kind, original generation and target. This observation changes no
// reference count and performs no physical operation.
func observeImageMountResult(entries map[string]*imageMountEntry, generations map[imageMountIdentity]*imageMountEntry, source string, result *imageapi.MountOperationResult) error {
	entry, err := findImageMountEntry(entries, generations, source, result.PhysicalGeneration)
	if err != nil || entry == nil {
		return err
	}
	target := entry.mountPoint
	if target == "" {
		target = entry.path
	}
	if target != result.MountPoint {
		return fmt.Errorf("original cached mount target changed")
	}
	if entry.retirementConfirmed && result.State != "released" {
		return fmt.Errorf("original mount completion regressed")
	}
	if result.State == "released" || result.State == "release_pending" {
		entry.releaseUnconfirmed = true
		entry.retirementConfirmed = result.State == "released"
	}
	return nil
}

func (m *ociMountManager) observeOriginalResult(source string, result *imageapi.MountOperationResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return observeImageMountResult(m.entries, m.generations, source, result)
}

func (m *s3MountManager) observeOriginalResult(source string, result *imageapi.MountOperationResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return observeImageMountResult(m.entries, m.generations, source, result)
}
