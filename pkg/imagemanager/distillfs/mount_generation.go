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
	release, err := d.ownership.acquire()
	if err != nil {
		return "", err
	}
	defer release()
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
	return d.inspectPhysicalGeneration(generation, false)
}

// This read-only capability grants only an original cleanup handle. The caller
// must first persist its bound operation retirement fence. It never starts or
// stops a process, mounts a source, or claims release completion.
func (d *Daemon) InspectPhysicalGenerationForRetirement(generation string) (string, error) {
	return d.inspectPhysicalGeneration(generation, true)
}

func (d *Daemon) inspectPhysicalGeneration(generation string, retirement bool) (string, error) {
	release, err := d.ownership.acquire()
	if err != nil {
		return "", err
	}
	defer release()
	if !d.mu.TryLock() {
		return "", fmt.Errorf("original mount lifecycle is currently active")
	}
	defer d.mu.Unlock()
	if !d.physicalMu.TryLock() {
		return "", fmt.Errorf("original mount publication is currently active")
	}
	p := clonePhysicalIdentity(d.meta.PhysicalIdentity)
	preparation := clonePreparation(d.meta.Preparation)
	pending := d.preparationPublicationPending
	d.physicalMu.Unlock()
	if p == nil {
		if generation == "" || preparation == nil || preparation.Generation != generation {
			return "", fmt.Errorf("original mount generation is missing or changed")
		}
		if pending {
			return "", fmt.Errorf("original preparation publication is unresolved")
		}
		if preparation.Phase == "released" {
			return "released", nil
		}
		return "releasing", nil // Prepared is a cleanup-only acquisition, never ready.
	}
	if generation == "" || p.Generation != generation {
		return "", fmt.Errorf("original mount generation is missing or changed")
	}
	if err := d.ensurePhysicalPublication(); err != nil {
		return "", err
	}
	if retirement && p.Phase != "released" {
		return "releasing", nil
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
