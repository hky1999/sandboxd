package server

import (
	"context"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/checkpoint"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointDeleteRefusesInFlightProducer(t *testing.T) {
	h := newTestService(t, map[string]svc.Handler{})
	h.checkpointState = checkpointstate.NewCoordinator()
	directory := filepath.Join(h.config.RootDir, "checkpoints", "case")
	fact, err := checkpoint.PublishAt(directory, checkpoint.SourceIdentity{CheckpointID: "case", SourceID: "missing", SourceGeneration: "original", Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64)}, writeReplayCheckpointImage)
	require.NoError(t, err)
	attempt, execute, err := h.checkpointState.BeginCheckpoint(checkpointstate.CheckpointKey{SandboxID: "missing", CheckpointID: "case"}, "producer")
	require.NoError(t, err)
	require.True(t, execute)
	defer h.checkpointState.Complete(attempt, nil)
	_, err = h.DeleteCheckpoint(context.Background(), &runtime.DeleteCheckpointRequest{CheckpointDir: directory, CheckpointID: "case", SourceSandboxID: "missing", ExpectedSize: fact.Manifest.ImageSize, ExpectedSha256: fact.Manifest.ImageSHA256})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = checkpoint.InspectAt(directory, "case")
	require.NoError(t, err)
}

func TestCheckpointDeleteRejectsDifferentSourceGeneration(t *testing.T) {
	h := newTestService(t, map[string]svc.Handler{})
	h.checkpointState = checkpointstate.NewCoordinator()
	directory := filepath.Join(h.config.RootDir, "checkpoints", "generation")
	fact, err := checkpoint.PublishAt(directory, checkpoint.SourceIdentity{CheckpointID: "generation", SourceID: "missing", SourceGeneration: "original", Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64)}, writeReplayCheckpointImage)
	require.NoError(t, err)
	request := &runtime.DeleteCheckpointRequest{CheckpointDir: directory, CheckpointID: "generation", SourceSandboxID: "missing", ExpectedSourceGeneration: "replacement", ExpectedSize: fact.Manifest.ImageSize, ExpectedSha256: fact.Manifest.ImageSHA256}
	_, err = h.DeleteCheckpoint(context.Background(), request)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	request.ExpectedSourceGeneration = "original"
	_, err = h.DeleteCheckpoint(context.Background(), request)
	require.NoError(t, err)
	_, err = h.DeleteCheckpoint(context.Background(), request)
	require.NoError(t, err)
}
