// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunscStateCannotAdoptForeignContainerOrSandboxIdentity(t *testing.T) {
	for _, state := range []string{
		`{"id":"replacement","status":"created","sandbox":{"id":"original","pid":123,"controlSocketPath":"/replacement/control.sock"}}`,
		`{"id":"original","status":"created","sandbox":{"id":"replacement","pid":123,"controlSocketPath":"/replacement/control.sock"}}`,
	} {
		client := NewClient("unused", t.TempDir())
		require.NoError(t, os.Chmod(client.RootDir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(client.RootDir, "original_sandbox:original.state"), []byte(state), 0600))
		_, err := client.loadState("original")
		require.Error(t, err, "the requested container must never borrow another container or sandbox control socket")
	}
}
