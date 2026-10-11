// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestImageManagerOwnershipOCICloseWaitsForActiveCacheMaintenance(t *testing.T) {
	m := newTestManager(t)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var enteredOnce, unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	m.diskUsage = func(string) (float64, error) {
		enteredOnce.Do(func() { close(entered) })
		<-proceed
		return 0, nil
	}
	m.pruneWG.Add(1)
	gcFinished := make(chan error, 1)
	go func() { defer m.pruneWG.Done(); gcFinished <- m.gcLayers() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("cache maintenance did not enter its controlled observation")
	}
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("backend close crossed active cache maintenance: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	unblock.Do(func() { close(proceed) })
	select {
	case err := <-gcFinished:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("cache maintenance did not finish")
	}
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("backend close did not finish")
	}
}
