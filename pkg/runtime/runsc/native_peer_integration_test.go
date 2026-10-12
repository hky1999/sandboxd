// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func verifyNativeServingPeerRefusal(t *testing.T, ctx context.Context, client *Client, args StartArgs, original, peer *containerState, save func(string, any)) {
	t.Helper()
	originalBytes, err := os.ReadFile(client.stateFilePath(original.ID))
	require.NoError(t, err)
	peerBytes, err := os.ReadFile(client.stateFilePath(peer.ID))
	require.NoError(t, err)
	dial := client.connectControl
	client.connectControl = func(string) (controlRPC, error) { return dial(peer.Sandbox.ControlSocketPath) }
	defer func() { client.connectControl = dial }()
	err = client.Start(ctx, args)
	require.ErrorContains(t, err, "not from the original serving process")
	for _, state := range []*containerState{original, peer} {
		verifyNativePhysicalBirth(t, state.Sandbox.ProcessBirth)
		verifyNativePhysicalBirth(t, state.GoferBirth)
	}
	data, err := os.ReadFile(client.stateFilePath(original.ID))
	require.NoError(t, err)
	require.Equal(t, originalBytes, data)
	data, err = os.ReadFile(client.stateFilePath(peer.ID))
	require.NoError(t, err)
	require.Equal(t, peerBytes, data)
	save("native-control-peer-refusal.json", map[string]any{
		"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration,
		"operation_id":        "native-control-active-peer-refusal",
		"expected_sentry_pid": original.Sandbox.Pid, "wrong_peer_sentry_pid": peer.Sandbox.Pid,
		"wrong_peer_reply_refused": true, "both_original_states_unchanged": true, "all_four_original_processes_live": true,
		"scope": "Controlled dial substitution to this fixture's real live peer before TAP or mutable RPCs. No node-budget acceptance.",
	})
}
