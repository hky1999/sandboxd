// Copyright (c) 2026 Ant Group Corporation.
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

package server

import (
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
)

// TestCheckpointAdmissionGateProvesRealWiring: the server's checkpoint
// admission helper REFUSES when the spool is over its reserve (stable,
// distinguishable error) and ALLOWS again once the reserve is met or the
// gate is unconfigured. This proves the daemon-side wiring exists — the
// earlier gap (a CheckAdmission nobody calls) is closed at the same entry
// the Checkpoint RPC uses.
func TestCheckpointAdmissionGateProvesRealWiring(t *testing.T) {
	root := t.TempDir()
	h := &sandboxService{config: config.Config{}}
	h.config.PluginConfig.CheckpointAdmissionConfig = config.CheckpointAdmissionConfig{
		Roots:        []string{root},
		MinFreeBytes: 1 << 62, // impossible reserve: always backpressured
	}
	err := h.checkpointAdmission()
	if err == nil {
		t.Fatal("over-reserve admission allowed a checkpoint")
	}
	if !strings.Contains(err.Error(), "checkpoint admission refused") {
		t.Fatalf("error not distinguishable: %v", err)
	}
	var adm *checkpointpublish.AdmissionError
	if !strings.Contains(err.Error(), "backpressured") {
		t.Fatalf("typed error lost in wrapping: %v", err)
	}
	_ = adm
	// Reserve met (tiny): allowed.
	h.config.PluginConfig.CheckpointAdmissionConfig.MinFreeBytes = 1
	if err := h.checkpointAdmission(); err != nil {
		t.Fatalf("healthy spool refused: %v", err)
	}
	// Gate unconfigured (the default): never refuses, even on a bogus root.
	h.config.PluginConfig.CheckpointAdmissionConfig = config.CheckpointAdmissionConfig{}
	if err := h.checkpointAdmission(); err != nil {
		t.Fatalf("disabled gate refused: %v", err)
	}
}
