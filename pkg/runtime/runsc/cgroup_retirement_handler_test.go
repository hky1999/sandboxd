// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"errors"
	"os"
	"testing"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

type cgroupRetirementClient struct {
	nativeDeletionClient
	verifications, leaves, parents int
	identity                       OriginalCgroupIdentity
	proof                          *os.File
}

func (c *cgroupRetirementClient) VerifyRuntimeGenerationForCgroupRetirement(_ context.Context, id, generation string, identity OriginalCgroupIdentity) error {
	c.verifications++
	c.id, c.generation, c.identity = id, generation, identity
	return nil
}
func (c *cgroupRetirementClient) DeleteIfGenerationAfterCgroupOffline(_ context.Context, id, generation string, proof *os.File) error {
	c.leaves++
	c.id, c.generation, c.proof = id, generation, proof
	return errors.New("leaf result unknown")
}
func (c *cgroupRetirementClient) DeleteIfGenerationAfterCgroupParentOffline(_ context.Context, id, generation string, proof *os.File, identity OriginalCgroupIdentity) error {
	c.parents++
	c.id, c.generation, c.proof, c.identity = id, generation, proof, identity
	return errors.New("parent result unknown")
}

func TestRunscHandlerClosedCgroupRoutesExactBorrowedProofWithoutFallback(t *testing.T) {
	client := &cgroupRetirementClient{}
	handler := &Handler{runsc: client, sandboxRoot: t.TempDir()}
	identity := runtimecore.CgroupRuntimeIdentity{Path: "/sandbox/original", Device: 7, Inode: 31}
	require.NoError(t, handler.VerifyRuntimeCgroupGeneration(context.Background(), "original", "original-generation", identity))
	require.Equal(t, OriginalCgroupIdentity{Path: identity.Path, Device: identity.Device, Inode: identity.Inode}, client.identity)
	file, err := os.Open(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { file.Close() })
	for _, leaf := range []bool{true, false} {
		proof := runtimecore.CgroupRuntimeProof{Identity: identity, Parent: file}
		if leaf {
			proof.Directory = file
		}
		err := handler.DeleteRuntimeAfterCgroupClosed(context.Background(), "original", "original-generation", proof)
		require.ErrorContains(t, err, "result unknown")
		require.Same(t, file, client.proof)
		require.Equal(t, "original", client.id)
		require.Equal(t, "original-generation", client.generation)
		_, err = file.Stat()
		require.NoError(t, err, "borrowed descriptor remains caller-owned")
	}
	require.Equal(t, 1, client.leaves)
	require.Equal(t, 1, client.parents)
	require.Zero(t, client.nativeCalls)
	require.Zero(t, client.legacyCalls)
}

func TestRunscHandlerClosedCgroupMissingCapabilityCannotUseOrdinaryDeletion(t *testing.T) {
	client := &nativeDeletionClient{}
	handler := &Handler{runsc: client, sandboxRoot: t.TempDir()}
	identity := runtimecore.CgroupRuntimeIdentity{Path: "/sandbox/original", Device: 7, Inode: 31}
	require.ErrorContains(t, handler.VerifyRuntimeCgroupGeneration(context.Background(), "original", "generation", identity), "cannot verify")
	file, err := os.Open(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { file.Close() })
	for _, proof := range []runtimecore.CgroupRuntimeProof{
		{Identity: identity, Directory: file}, {Identity: identity, Parent: file},
		{Identity: identity}, {Directory: file},
	} {
		require.Error(t, handler.DeleteRuntimeAfterCgroupClosed(context.Background(), "original", "generation", proof))
	}
	require.Zero(t, client.nativeCalls)
	require.Zero(t, client.legacyCalls)
}
