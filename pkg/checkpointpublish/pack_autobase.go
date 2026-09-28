// Copyright 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkpointpublish

// Auto-base: resolve the sealed manifest's base_memory field as a pack
// baseline hint. The hint is a DIRECTORY NAME recorded by the checkpoint
// handler at seal time (checkpoint_handler.go:547,
// `manifest.BaseMemory = filepath.Base(filepath.Dir(base))`) — it names the
// parent generation's checkpoint directory, which equals the artifact ID
// cn-publish uses (`filepath.Base(checkpointDir)`). It is a HINT, never a
// proof: the existing loadPackBaseline chain verifies everything at
// consumption time, and a wrong hint degrades reuse (digests do not match)
// rather than producing incorrect data (pack objects are content-addressed
// by their own sha256).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AutoBaseReason is a stable enum for why auto-base was or was not used.
const (
	autoBaseUsed        = "used"
	autoBaseNoHint      = "no_hint"
	autoBaseInvalidID   = "invalid_id"
	autoBaseExplicit    = "explicit_override"
	autoBasePlainLayout = "plain_layout"
	autoBaseUnavailable = "parent_unavailable"
)

// AutoBaseDecision records the auto-base resolution for one attempt. It is
// emitted ONLY when Options.PackAutoBase is enabled; nil otherwise.
type AutoBaseDecision struct {
	// Candidate is the raw base_memory value from the sealed manifest
	// (empty when no hint was present or we never read it).
	Candidate string `json:"candidate,omitempty"`
	// Used reports whether the hint was adopted as this attempt's BaseID.
	Used bool `json:"used"`
	// Reason is a stable enum: used / no_hint / invalid_id /
	// explicit_override / plain_layout.
	Reason string `json:"reason"`
}

// readAutoBaseHint reads the sealed Firecracker manifest's base_memory
// field. Returns ("", nil) when the field is absent — a Full generation
// has no parent by design. The file is the same one runPacked reads for
// packedMemoryClosure; re-reading a KB-sized JSON is cheaper than plumbing
// it through the call chain.
func readAutoBaseHint(checkpointDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(checkpointDir, "manifest.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // no manifest: memory-only artifact, no hint
		}
		return "", err
	}
	var hint struct {
		BaseMemory string `json:"base_memory,omitempty"`
	}
	if err := json.Unmarshal(raw, &hint); err != nil {
		return "", nil // unreadable manifest: no hint, not a failure
	}
	return hint.BaseMemory, nil
}

// resolveAutoBase returns the effective Options (with BaseID set from the
// hint when adopted, plus the autoBaseOrigin marker) and the decision
// record. Called ONLY when we know whether the attempt is entering the
// packed stage; a plain-layout attempt never reads the manifest. This
// function does NO store I/O: the hint is validated syntactically only
// (validPackedID); the actual parent availability is proven by the ONE
// loadPackBaseline call inside runPacked, under the attempt's own ctx —
// no preflight, no TOCTOU, no extra requests.
func resolveAutoBase(opts Options, checkpointDir, id string, goingToPack bool) (Options, *AutoBaseDecision) {
	if opts.BaseID != "" {
		// Explicit -base-id is authoritative; the auto hint is not even
		// read. The decision records the override for observability.
		return opts, &AutoBaseDecision{Used: false, Reason: autoBaseExplicit}
	}
	if !goingToPack {
		return opts, &AutoBaseDecision{Used: false, Reason: autoBasePlainLayout}
	}
	hint, err := readAutoBaseHint(checkpointDir)
	if err != nil || hint == "" {
		return opts, &AutoBaseDecision{Used: false, Reason: autoBaseNoHint}
	}
	// Same security gate as an explicit -base-id: the hint is a directory
	// name that becomes part of a store key, so path separators and other
	// dangerous characters are rejected before any store interaction.
	if !validPackedID(hint) || hint == id {
		return opts, &AutoBaseDecision{Candidate: hint, Used: false, Reason: autoBaseInvalidID}
	}
	// Adopt the hint: BaseID is set and autoBaseOrigin marks it for the
	// loadPackBaseline failure semantics (auto falls back to no-base;
	// explicit keeps its hard error). Used is set optimistically here and
	// confirmed only when loadPackBaseline actually succeeds inside
	// runPacked — on fallback, runPacked flips it to false and updates
	// the reason.
	newOpts := opts
	newOpts.BaseID = hint
	newOpts.autoBaseOrigin = true
	return newOpts, &AutoBaseDecision{Candidate: hint, Used: true, Reason: autoBaseUsed}
}

// validateAutoBaseOptions rejects combinations that would silently disable
// or bypass the feature at validation time (before any state or store IO).
func validateAutoBaseOptions(opts Options) error {
	if !opts.PackAutoBase {
		return nil
	}
	if opts.PackBytes == 0 {
		return fmt.Errorf("auto-base requires packing to be configured (pack-mib defines the pack size)")
	}
	// PackAutoBase + explicit BaseID is ALLOWED: explicit wins, the auto
	// hint is ignored (decision reason records the override). PackAutoBase
	// + adaptive is ALLOWED: layout is chosen first; plain skips the base
	// entirely, pack resolves the hint.
	return nil
}
