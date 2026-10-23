package checkpointstate

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestArtifactCollectionExcludesProducerRestoreAndReaders(t *testing.T) {
	c := NewCoordinator()
	producer, run, err := c.BeginCheckpoint(CheckpointKey{SandboxID: "s", CheckpointID: "cp"}, "fp")
	require.NoError(t, err)
	require.True(t, run)
	_, err = c.BeginArtifactDelete("cp")
	require.Error(t, err)
	c.Complete(producer, nil)
	reader, err := c.PinArtifact("cp")
	require.NoError(t, err)
	_, err = c.BeginArtifactDelete("cp")
	require.Error(t, err)
	attempt, run, err := c.BeginRestoreArtifact("target", "cp", "restore")
	require.NoError(t, err)
	require.True(t, run)
	reader()
	_, err = c.BeginArtifactDelete("cp")
	require.Error(t, err)
	c.Complete(attempt, nil)
	require.NoError(t, attempt.Wait(context.Background()))
	release, err := c.BeginArtifactDelete("cp")
	require.NoError(t, err)
	_, _, err = c.BeginCheckpoint(CheckpointKey{SandboxID: "s", CheckpointID: "cp"}, "fp")
	require.Error(t, err)
	_, err = c.PinArtifact("cp")
	require.Error(t, err)
	release()
	release()
	release, err = c.BeginArtifactDelete("cp")
	require.NoError(t, err)
	release()
}
