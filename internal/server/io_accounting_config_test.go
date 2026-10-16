// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCgroupIOAccountingInvalidConfigStopsBeforeOwnedStateInitialization(t *testing.T) {
	for _, resource := range []string{
		"cgroup_io_accounting=true\ndisable_cgroup=true\ncgroup_cache_size=1\n",
		"cgroup_io_accounting=true\ncgroup_cache_size=0\n",
	} {
		root := t.TempDir()
		store := filepath.Join(root, "store")
		cfg := filepath.Join(root, "sandboxd.toml")
		text := fmt.Sprintf("rootDir=%q\nstoreDir=%q\n[plugin.resource]\n%s", filepath.Join(root, "owned-state"), store, resource)
		require.NoError(t, os.WriteFile(cfg, []byte(text), 0600))
		service, err := NewSandboxService(filepath.Join(root, "runtime"), cfg)
		require.ErrorContains(t, err, "cgroup_io_accounting")
		require.Nil(t, service)
		require.NoDirExists(t, store)
	}
}
