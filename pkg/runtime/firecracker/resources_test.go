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

package firecracker

import (
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

func TestFirecrackerHostResourcesAddsRuntimeMemoryOverhead(t *testing.T) {
	const requested = int64(256 * 1024 * 1024)
	if firecrackerHostMemoryOverheadBytes != 64*1024*1024 {
		t.Fatalf("Firecracker host memory overhead = %d", firecrackerHostMemoryOverheadBytes)
	}
	original := &runtime.LinuxSandboxResources{
		CpuQuota:               50000,
		CpuPeriod:              100000,
		MemoryLimitInBytes:     requested,
		MemorySwapLimitInBytes: requested,
	}
	host := firecrackerHostResources(original)
	if host.MemoryLimitInBytes != requested+firecrackerHostMemoryOverheadBytes {
		t.Fatalf("host memory limit = %d", host.MemoryLimitInBytes)
	}
	if host.MemorySwapLimitInBytes != requested+firecrackerHostMemoryOverheadBytes {
		t.Fatalf("host swap limit = %d", host.MemorySwapLimitInBytes)
	}
	if host.CpuQuota != original.CpuQuota || host.CpuPeriod != original.CpuPeriod {
		t.Fatalf("host CPU resources = %+v", host)
	}
	if original.MemoryLimitInBytes != requested ||
		original.MemorySwapLimitInBytes != requested {
		t.Fatal("firecrackerHostResources mutated the guest resource request")
	}
}
