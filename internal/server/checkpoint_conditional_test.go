// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/checkpoint"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// writeReplayCheckpointImage publishes the minimal image a replayed artifact
// needs; the store hands the builder the staging image path.
func writeReplayCheckpointImage(imagePath string) error {
	return os.WriteFile(imagePath, []byte("checkpoint"), 0o600)
}

func conditionalCheckpointRequest(directory, generation string) *runtime.CheckpointIfGenerationRequest {
	return &runtime.CheckpointIfGenerationRequest{
		ExpectedGeneration: generation,
		Checkpoint:         &runtime.CheckpointRequest{ID: "elastic", CheckpointID: "case", CheckpointDir: directory},
	}
}

func TestCheckpointIfGenerationValidatesRequestShape(t *testing.T) {
	h, _, _ := newResizeService(t)
	directory := filepath.Join(h.config.RootDir, "checkpoints", "case")
	cases := map[string]func(*runtime.CheckpointIfGenerationRequest){
		"missing generation":   func(r *runtime.CheckpointIfGenerationRequest) { r.ExpectedGeneration = "" },
		"blank generation":     func(r *runtime.CheckpointIfGenerationRequest) { r.ExpectedGeneration = "   " },
		"oversized generation": func(r *runtime.CheckpointIfGenerationRequest) { r.ExpectedGeneration = strings.Repeat("g", 257) },
		"missing checkpoint":   func(r *runtime.CheckpointIfGenerationRequest) { r.Checkpoint = nil },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			request := conditionalCheckpointRequest(directory, "generation-1")
			modify(request)
			_, err := h.CheckpointIfGeneration(context.Background(), request)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	_, err := h.CheckpointIfGeneration(context.Background(), nil)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// A stale expectation must be rejected before the source rootfs is read, so a
// nil filesystem manager proves no rootfs access happened on rejection.
func TestCheckpointIfGenerationRejectsStaleExpectationBeforeRootfs(t *testing.T) {
	h, _, _ := newResizeService(t)
	h.fsMgr = nil
	directory := filepath.Join(h.config.RootDir, "checkpoints", "case")
	request := conditionalCheckpointRequest(directory, "generation-2")
	_, err := h.CheckpointIfGeneration(context.Background(), request)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	// 256 bytes is the largest accepted expectation; it still reaches the
	// stale check instead of failing validation.
	request.ExpectedGeneration = strings.Repeat("g", 256)
	_, err = h.CheckpointIfGeneration(context.Background(), request)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// A live replacement of a reused ID keeps its own generation even when a
// completed artifact still matches the caller's expectation; the rejection
// must happen before the replacement's rootfs is read.
func TestCheckpointIfGenerationRejectsLiveReplacementOverMatchingArtifact(t *testing.T) {
	h, _, _ := newResizeService(t)
	h.fsMgr = nil
	directory := filepath.Join(h.config.RootDir, "checkpoints", "case")
	_, err := checkpoint.PublishAt(directory, checkpoint.SourceIdentity{
		CheckpointID: "case", SourceID: "elastic", SourceGeneration: "old-gen",
		Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64),
	}, writeReplayCheckpointImage)
	require.NoError(t, err)
	_, err = h.CheckpointIfGeneration(context.Background(), conditionalCheckpointRequest(directory, "old-gen"))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// With the source sandbox absent, a conditional request may only replay the
// artifact published by its own generation.
func TestCheckpointIfGenerationReplaysAbsentSourceByGeneration(t *testing.T) {
	base := checkpoint.SourceIdentity{
		CheckpointID: "case", SourceID: "missing", SourceGeneration: "old-gen",
		Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64),
	}
	publish := func(t *testing.T, source checkpoint.SourceIdentity) (*sandboxService, *runtime.CheckpointIfGenerationRequest) {
		t.Helper()
		h := newTestService(t, map[string]svc.Handler{})
		directory := filepath.Join(h.config.RootDir, "checkpoints", "case")
		_, err := checkpoint.PublishAt(directory, source, writeReplayCheckpointImage)
		require.NoError(t, err)
		request := conditionalCheckpointRequest(directory, source.SourceGeneration)
		request.Checkpoint.ID = source.SourceID
		return h, request
	}
	t.Run("matching generation replays", func(t *testing.T) {
		h, request := publish(t, base)
		response, err := h.CheckpointIfGeneration(context.Background(), request)
		require.NoError(t, err)
		require.True(t, response.GetSuccess())
		require.Equal(t, "old-gen", response.GetSourceGeneration())
		require.Equal(t, filepath.Join(request.Checkpoint.CheckpointDir, checkpoint.ImageName), response.GetArtifactPath())
	})
	t.Run("different generation rejects", func(t *testing.T) {
		h, request := publish(t, base)
		request.ExpectedGeneration = "new-gen"
		_, err := h.CheckpointIfGeneration(context.Background(), request)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
	t.Run("legacy manifest without generation rejects", func(t *testing.T) {
		legacy := base
		legacy.SourceGeneration = ""
		h, request := publish(t, legacy)
		request.ExpectedGeneration = "old-gen"
		_, err := h.CheckpointIfGeneration(context.Background(), request)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
}

// The in-flight checkpoint fingerprint binds the checkpoint key to one
// physical source generation.
func TestCheckpointSourceFingerprintBindsGeneration(t *testing.T) {
	request := &runtime.CheckpointRequest{ID: "elastic", CheckpointID: "case", CheckpointDir: "checkpoints/case"}
	stable, err := checkpointSourceFingerprint(request, "checkpoints/case", "generation-1")
	require.NoError(t, err)
	repeat, err := checkpointSourceFingerprint(request, "checkpoints/case", "generation-1")
	require.NoError(t, err)
	require.Equal(t, stable, repeat)
	changed, err := checkpointSourceFingerprint(request, "checkpoints/case", "generation-2")
	require.NoError(t, err)
	require.NotEqual(t, stable, changed)
}

// One checkpoint key cannot merge attempts captured across different source
// generations, while the same fingerprint still coalesces.
func TestCheckpointBeginRejectsFingerprintChangeForSameKey(t *testing.T) {
	h := newTestService(t, map[string]svc.Handler{})
	// newTestService does not wire the checkpoint coordinator; the in-flight
	// fingerprint contract under test needs a real one.
	h.checkpointState = checkpointstate.NewCoordinator()
	request := &runtime.CheckpointRequest{ID: "elastic", CheckpointID: "case", CheckpointDir: "checkpoints/case"}
	oldGeneration, err := checkpointSourceFingerprint(request, "checkpoints/case", "old-gen")
	require.NoError(t, err)
	newGeneration, err := checkpointSourceFingerprint(request, "checkpoints/case", "new-gen")
	require.NoError(t, err)
	require.NotEqual(t, oldGeneration, newGeneration)
	key := checkpointstate.CheckpointKey{SandboxID: "elastic", CheckpointID: "case"}
	first, execute, err := h.checkpointState.BeginCheckpoint(key, oldGeneration)
	require.NoError(t, err)
	require.True(t, execute)
	merged, executeAgain, err := h.checkpointState.BeginCheckpoint(key, oldGeneration)
	require.NoError(t, err)
	require.False(t, executeAgain)
	_, _, err = h.checkpointState.BeginCheckpoint(key, newGeneration)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	// The rejected attempt must not have merged into or disturbed the
	// in-flight one: the executor still decides its outcome.
	h.checkpointState.Complete(first, nil)
	require.NoError(t, first.Wait(context.Background()))
	require.NoError(t, merged.Wait(context.Background()))
}
