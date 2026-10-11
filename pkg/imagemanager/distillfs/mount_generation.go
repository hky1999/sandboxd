// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import "fmt"

// MountWithPhysicalGeneration captures the result under the SAME lifecycle lock,
// rather than querying a possibly replaced generation after Mount returned.
func (d *Daemon) MountWithPhysicalGeneration() (string, error) {
	return d.MountWithPhysicalBinding(nil)
}

// The binding must become durable before a new process is dispatched. Each
// shared owner also binds the existing generation under the lifecycle lock.
func (d *Daemon) MountWithPhysicalBinding(bind func(generation, target string) error) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.mountLockedWithBinding(true, bind); err != nil {
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

func (d *Daemon) bindOriginalMount(bind func(generation, target string) error) error {
	if bind == nil {
		return nil
	}
	if err := d.ensurePhysicalPublication(); err != nil {
		return err
	}
	p := d.originalPhysicalIdentity()
	if p == nil || (p.Phase != "launching" && p.Phase != "running") {
		return fmt.Errorf("original physical binding is unresolved")
	}
	return bind(p.Generation, p.Target)
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
	case "released", "releasing", "not_started":
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
