// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"encoding/json"
	"errors"
	"path/filepath"
)

const (
	nativeNotDispatched  = "not_dispatched"
	nativeDispatching    = "dispatching"
	nativeBirthPublished = "birth_published"
)

func validateNativeLaunchStages(state *containerState, requireSentry bool) error {
	if state.ProcessLaunchVersion == 0 {
		if state.GoferLaunchState != "" || state.SentryLaunchState != "" {
			return errors.New("legacy native owner contains unsupported launch-stage facts")
		}
		return nil
	}
	if state.ProcessLaunchVersion != 1 {
		return errors.New("native process launch protocol is unsupported")
	}
	valid := func(stage string) bool {
		return stage == nativeNotDispatched || stage == nativeDispatching || stage == nativeBirthPublished
	}
	if !valid(state.GoferLaunchState) || !valid(state.SentryLaunchState) ||
		state.RuntimeDispatched != (state.GoferLaunchState != nativeNotDispatched || state.SentryLaunchState != nativeNotDispatched) ||
		state.GoferRequired != (state.GoferLaunchState != nativeNotDispatched) {
		return errors.New("native launch facts are missing or contradict dispatch ownership")
	}
	if state.GoferLaunchState == nativeDispatching || state.SentryLaunchState == nativeDispatching {
		return errors.New("native process dispatch lacks published birth; outcome remains unknown")
	}
	if requireSentry && state.SentryLaunchState != nativeBirthPublished {
		return errors.New("native control operation requires a published original sentry")
	}
	return nil
}

// Only the retirement verifier accepts producer-issued preparation or a
// published gofer with a provably undispatched Sentry. Control operations keep
// the existing complete state and birth requirements. This read authorizes no
// signal; generation-conditional native deletion still checks original pidfds.
func (c *Client) loadNativeRetirementState(id string) (*containerState, error) {
	if !runtimeInventoryID(id) {
		return nil, errors.New("native retirement container ID is invalid")
	}
	directory, original, err := openRuntimeIdentityDirectory(c.RootDir)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	data, err := readPrivateRuntimeJSON(directory, filepath.Base(c.stateFilePath(id)))
	if err != nil {
		return nil, err
	}
	state, err := decodeNativeRetirementState(data, id)
	if err != nil {
		return nil, err
	}
	if err := verifyRuntimeIdentityDirectory(c.RootDir, original); err != nil {
		return nil, err
	}
	return state, nil
}

func decodeNativeRetirementState(data []byte, id string) (*containerState, error) {
	var state containerState
	if err := json.Unmarshal(data, &state); err != nil || state.ID != id {
		return nil, errors.New("native retirement source is malformed or belongs to another container")
	}
	if state.Sandbox.ID != "" {
		complete, err := decodeNativeState(data, id)
		if err != nil {
			return nil, err
		}
		if err := validateNativeLaunchStages(complete, true); err != nil {
			return nil, err
		}
		return complete, nil
	}
	if state.ProcessBirthVersion != 1 || state.ProcessLaunchVersion != 1 || state.Status != "creating" ||
		!runtimeInventoryID(state.ResourceGeneration) || state.Spec.Annotations[runtimeResourceGenerationAnnotation] != state.ResourceGeneration ||
		state.Sandbox.Pid != 0 || state.Sandbox.ProcessBirth != nil || state.Sandbox.ResourceGeneration != "" || state.Sandbox.ControlSocketPath != "" ||
		state.SentryLaunchState != nativeNotDispatched {
		return nil, errors.New("native partial source is not an original undispatched sentry")
	}
	if err := validateNativeLaunchStages(&state, false); err != nil {
		return nil, err
	}
	if state.GoferRequired {
		if err := state.GoferBirth.validate(id, state.ResourceGeneration, "gofer", state.GoferPID); err != nil {
			return nil, err
		}
	} else if state.GoferBirth != nil || state.GoferPID != 0 {
		return nil, errors.New("native undispatched preparation contains process facts")
	}
	return &state, nil
}
