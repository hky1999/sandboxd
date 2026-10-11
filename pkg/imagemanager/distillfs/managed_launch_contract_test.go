// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This uses only pre-existing APIs, so the fixed original source compiles the
// counterexample. It never executes the configured identity-only program.
func TestDaemonManagedLaunchPreparedContractRequiresDirectChildAndDurableIntent(t *testing.T) {
	config := ownershipManagerConfig(t)
	config.BinPath = "/bin/true"
	require.NoError(t, os.Chmod(config.Root, 0700))
	m := ownedManager(t, config)
	id := strings.Repeat("a", 64)
	require.NoError(t, m.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "controlled.erofs"}, preparationOwner(), func(string, string) error { return nil }))
	d := m.GetDaemon(id)
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	args := d.buildMountArgs()
	require.NotContains(t, args, "--daemon", "managed confirmation must retain the original direct child")
	for _, name := range []string{"--scheduler-launch-manifest-fd", "--scheduler-owner-lock-fd", "--scheduler-owner-directory-fd", "--scheduler-journal-directory-fd"} {
		require.Contains(t, args, name)
	}
	data, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	var record map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &record))
	var physical map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(record["physical_identity"], &physical))
	require.NotEmpty(t, physical["managed_launch"], "full original launch intent must be durable before dispatch")
}
