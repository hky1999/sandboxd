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
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	current := d.meta.PhysicalIdentity
	if expected == nil || current == nil || current.Generation != expected.Generation || current.Phase != "launching" || current.Process != nil || current.Mount != nil || current.NoDispatchConfirmed || d.physicalPublicationPending {
		return fmt.Errorf("original daemon dispatch is fenced or unresolved")
	}
	if current.Scope != expected.Scope || current.Target != expected.Target || current.PIDFile != expected.PIDFile || current.ExecutableSHA256 != expected.ExecutableSHA256 || current.ArgumentsSHA256 != expected.ArgumentsSHA256 || current.SourceSHA256 != expected.SourceSHA256 || d.meta.PidFilePath != expected.PIDFile {
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
	if err := command.Start(); err != nil {
		failed := clonePhysicalIdentity(current)
		failed.Phase = "not_started"
		failed.NoDispatchConfirmed = true
		if persistErr := d.publishPhysicalIdentityLocked(failed); persistErr != nil {
			return persistErr
		}
		return err
	}
	return nil
}
