// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import "fmt"

// MountWithPhysicalGeneration captures the result under the SAME lifecycle lock,
// rather than querying a possibly replaced generation after Mount returned.
func (d *Daemon) MountWithPhysicalGeneration() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.mountLocked(true); err != nil {
		return "", err
	}
	if err := d.ensurePhysicalPublication(); err != nil {
		return "", err
	}
	p := d.originalPhysicalIdentity()
	if p == nil || p.Phase != "running" || p.Process == nil || p.Mount == nil {
		return "", fmt.Errorf("mounted daemon lacks original physical identity")
	}
	return p.Generation, nil
}

// InspectPhysicalGeneration reattaches only a known original record. It NEVER
// starts a process, remounts a URL, or borrows a replacement generation.
func (d *Daemon) InspectPhysicalGeneration(generation string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.originalPhysicalIdentity()
	if generation == "" || p == nil || p.Generation != generation {
		return "", fmt.Errorf("original mount generation is missing or changed")
	}
	if err := d.ensurePhysicalPublication(); err != nil {
		return "", err
	}
	switch p.Phase {
	case "released", "releasing":
		return p.Phase, nil
	case "running":
		if !d.IsAlive() {
			return "", fmt.Errorf("original mount process is unconfirmed")
		}
		if err := d.verifyOriginalMountForRemoval(); err != nil {
			return "", err
		}
		return p.Phase, nil
	default:
		return "", fmt.Errorf("original mount acquisition is unresolved")
	}
}
