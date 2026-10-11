// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"fmt"
	"os/exec"
	"strings"
)

// The final identity check and Start share physicalMu with durable release
// publication. A release that wins this lock prevents late exec; a Start that
// wins keeps an interrupted birth unresolved until the original facts arrive.
func (d *Daemon) startOriginalDaemonCommand(command *exec.Cmd, expected *physicalIdentity) error {
	release, err := d.ownership.acquire()
	if err != nil {
		return err
	}
	defer release()
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	if err := d.verifyPreparationForLaunchLocked(); err != nil {
		return err
	}
	current := d.meta.PhysicalIdentity
	if expected == nil || current == nil || current.Generation != expected.Generation || current.Phase != "launching" || current.Process != nil || current.Mount != nil || current.NoDispatchConfirmed || d.physicalPublicationPending {
		return fmt.Errorf("original daemon dispatch is fenced or unresolved")
	}
	if !samePhysicalLaunch(current, expected) || d.meta.PidFilePath != expected.PIDFile {
		return fmt.Errorf("original daemon dispatch identity changed")
	}
	if command == nil || command.Path != d.binPath || metadataSHA([]byte(strings.Join(command.Args, "\x00")+"\x00")) != expected.ArgumentsSHA256 {
		return fmt.Errorf("original daemon dispatch command changed")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != expected.Scope {
		return fmt.Errorf("original daemon dispatch scope changed")
	}
	source, err := d.sourceIdentitySHA()
	if err != nil || source != expected.SourceSHA256 {
		return fmt.Errorf("original daemon dispatch source changed")
	}
	executable, err := readPhysicalFile(command.Path, 256<<20)
	if err != nil || metadataSHA(executable) != expected.ExecutableSHA256 {
		return fmt.Errorf("original daemon dispatch executable changed")
	}
	if current.BirthProtocol == 1 {
		directory, err := d.openPhysicalBirthDirectory(current)
		if err != nil {
			return err
		}
		directory.Close()
	}
	files, err := d.managedLaunchFiles(current)
	if err != nil {
		return err
	}
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	if current.ManagedLaunch != nil {
		if len(command.ExtraFiles) != 0 || command.Cancel != nil || d.managedChild != nil {
			return fmt.Errorf("original direct-child dispatch state changed")
		}
		command.ExtraFiles = files
	}
	dispatched, err := d.ownership.dispatch(command.Start)
	if err != nil {
		if !dispatched {
			return err // An owner rejection does not prove an attempted Start failed.
		}
		failed := clonePhysicalIdentity(current)
		failed.Phase = "not_started"
		failed.NoDispatchConfirmed = true
		if persistErr := d.publishPhysicalIdentityLocked(failed); persistErr != nil {
			return persistErr
		}
		return err
	}
	if current.ManagedLaunch != nil {
		child := &managedLaunchChild{Generation: current.Generation, Command: command, Done: make(chan struct{})}
		d.managedChild = child
		go func() {
			child.Err = command.Wait()
			close(child.Done)
		}()
	}
	return nil
}
