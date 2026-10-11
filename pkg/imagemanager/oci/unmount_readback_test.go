// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMountRoutingOCIReadbackFailureKeepsMetadataAndReferences(t *testing.T) {
	for _, mode := range []string{"still mounted", "unavailable", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			m := newTestManager(t)
			t.Cleanup(func() { _ = m.store.close() })
			record := &OciMountRecord{ImageURL: "registry.example/original:tag", MountID: "original", MountPath: filepath.Join(m.mountsDir, "original", "merged"), LayerDigests: []string{"sha256:original"}}
			require.NoError(t, m.store.putMount(record))
			require.NoError(t, m.store.putLayer(&LayerRecord{Digest: "sha256:original", RefCount: 2}))
			calls := 0
			m.unmountFn = func(string) error { calls++; return nil }
			m.readMnts = func() (map[string]struct{}, bool, error) {
				switch mode {
				case "still mounted":
					return map[string]struct{}{record.MountPath: {}}, true, nil
				case "unavailable":
					return nil, true, errors.New("mount table unavailable")
				default:
					return nil, false, nil
				}
			}
			require.Error(t, m.UnmountImageWithContext(context.Background(), record.ImageURL))
			current, err := m.store.getMount(record.ImageURL)
			require.NoError(t, err)
			require.Equal(t, record, current)
			layer, err := m.store.getLayer("sha256:original")
			require.NoError(t, err)
			require.Equal(t, 2, layer.RefCount)
			require.Equal(t, 1, calls)
		})
	}
}

func TestMountRoutingOCIRetryConfirmsAbsenceWithoutSecondUnmount(t *testing.T) {
	m := newTestManager(t)
	t.Cleanup(func() { _ = m.store.close() })
	record := &OciMountRecord{ImageURL: "registry.example/original:tag", MountID: "original", MountPath: filepath.Join(m.mountsDir, "original", "merged")}
	require.NoError(t, m.store.putMount(record))
	calls := 0
	m.unmountFn = func(string) error { calls++; return nil }
	m.readMnts = func() (map[string]struct{}, bool, error) { return map[string]struct{}{record.MountPath: {}}, true, nil }
	require.Error(t, m.UnmountImageWithContext(context.Background(), record.ImageURL))
	require.Error(t, m.UnmountImageWithContext(context.Background(), record.ImageURL), "a target observed after successful unmount cannot authorize another syscall")
	_, _, _, err := m.MountImageConfigWithContext(context.Background(), record.ImageURL)
	require.Error(t, err, "do not hand out a source whose unmount is unresolved")
	require.Equal(t, 1, calls)
	m.readMnts = func() (map[string]struct{}, bool, error) { return map[string]struct{}{}, true, nil }
	require.NoError(t, m.UnmountImageWithContext(context.Background(), record.ImageURL))
	require.Equal(t, 1, calls)
	current, err := m.store.getMount(record.ImageURL)
	require.NoError(t, err)
	require.Nil(t, current)
}
