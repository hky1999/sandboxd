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
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/assert"
)

func TestFirecrackerCheckpointHeadroom(t *testing.T) {
	assert.Zero(t, firecrackerCheckpointHeadroom(0))
	assert.Equal(t, minimumFirecrackerCheckpointHeadroom, firecrackerCheckpointHeadroom(64<<20))
	assert.Equal(t, int64(6<<30), firecrackerCheckpointHeadroom(4<<30))
	assert.Equal(t, int64(math.MaxInt64), firecrackerCheckpointHeadroom(math.MaxInt64))
}

func TestAddResourceMemory(t *testing.T) {
	resources := &runtime.LinuxSandboxResources{
		MemoryLimitInBytes:     4 << 30,
		MemorySwapLimitInBytes: 4 << 30,
	}
	addResourceMemory(resources, 6<<30)
	assert.Equal(t, int64(10<<30), resources.MemoryLimitInBytes)
	assert.Equal(t, int64(10<<30), resources.MemorySwapLimitInBytes)

	resources.MemoryLimitInBytes = math.MaxInt64 - 1
	addResourceMemory(resources, 2)
	assert.Equal(t, int64(math.MaxInt64), resources.MemoryLimitInBytes)
}

func TestFirecrackerCheckpointMemorySlotHonorsCancellation(t *testing.T) {
	service := &sandboxService{}
	release, err := service.acquireFirecrackerCheckpointMemorySlot(
		context.Background(),
	)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = service.acquireFirecrackerCheckpointMemorySlot(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	release()
	release, err = service.acquireFirecrackerCheckpointMemorySlot(
		context.Background(),
	)
	assert.NoError(t, err)
	release()
}

func TestWithTransientFirecrackerCheckpointMemoryFailsClosedOnMissingResources(t *testing.T) {
	h := &sandboxService{
		firecrackerCheckpointMemorySlot: nil,
	}
	// The wrapper must fail closed when it cannot determine the memory limit,
	// instead of silently skipping the expansion.
	err := h.withTransientFirecrackerCheckpointMemory(
		context.Background(),
		"firecracker",
		"test-sandbox",
		"/nonexistent/cgroup",
		nil, // guestResources
		nil, // handler without HostResourcesProvider
		func() error { return errors.New("should not reach here") },
	)
	if err == nil {
		t.Fatal("expected error when memory limit is undeterminable")
	}
	if !strings.Contains(err.Error(), "guest memory limit") && !strings.Contains(err.Error(), "managed cgroup") {
		t.Fatalf("error should mention the memory limit: %v", err)
	}
}
