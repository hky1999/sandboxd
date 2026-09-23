// Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
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

package resourcemanager

import (
	"encoding/json"
	"strings"
	"testing"
)

// marshalResourceInfo renders the wire payload the way the /resource handler
// does, so the protocol tests exercise the exact JSON tags.
func marshalResourceInfo(t *testing.T, info resourceInfo) string {
	t.Helper()
	body, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(body)
}

func TestResourceInfoZeroUsageIsPresent(t *testing.T) {
	// A genuinely idle node reports zero usage; omitempty would drop the
	// fields and push consumers back onto the legacy available-as-usage
	// interpretation.
	body := marshalResourceInfo(t, resourceInfo{})
	for _, field := range []string{`"totalCpu":0`, `"totalMem":0`, `"usedCpu":0`, `"usedMem":0`, `"usedKnown":false`} {
		if !strings.Contains(body, field) {
			t.Fatalf("zero-value field missing from payload %s: want %s", body, field)
		}
	}
}

func TestResourceInfoUnknownIsExplicit(t *testing.T) {
	body := marshalResourceInfo(t, resourceInfo{TotalCpu: 104, TotalMem: 1, UsedKnown: false})
	if !strings.Contains(body, `"usedKnown":false`) {
		t.Fatalf("unknown sample must carry usedKnown=false, got %s", body)
	}
	// Reserved stays optional/informational.
	if strings.Contains(body, "reservedCpu") {
		t.Fatalf("reserved fields should stay omitted when unset, got %s", body)
	}
}

func TestResourceInfoReservedSeparateFromUsed(t *testing.T) {
	body := marshalResourceInfo(t, resourceInfo{
		TotalCpu: 104, TotalMem: 200 << 30,
		UsedCpu: 2.5, UsedMem: 8 << 30, UsedKnown: true,
		ReservedCpu: 4.1, ReservedMem: 6 << 30,
	})
	if !strings.Contains(body, `"usedCpu":2.5`) || !strings.Contains(body, `"reservedCpu":4.1`) {
		t.Fatalf("used and reserved must be separate wire fields, got %s", body)
	}
	if !strings.Contains(body, `"usedKnown":true`) {
		t.Fatalf("known sample must carry usedKnown=true, got %s", body)
	}
}

func TestSelfUsageUnknownWithoutCgroup(t *testing.T) {
	s := &selfUsage{unifiedRoot: "/nonexistent-path-for-test"}
	if _, err := s.MemoryUsage(); err == nil {
		t.Fatal("memory read failure must be an error, not zero")
	}
	if _, err := s.CPUUsageCores(); err == nil {
		t.Fatal("cpu read failure must be an error, not zero")
	}
}

func TestSelfUsageCPUNeedsWindow(t *testing.T) {
	if detectUnifiedRoot() == "" {
		t.Skip("no cgroup v2 in this environment")
	}
	s := newSelfUsage()
	if _, err := s.CPUUsageCores(); err == nil {
		t.Fatal("first cpu read has no window and must report unknown")
	}
}

func TestSelfUsageDomainRootIsNamespaceMount(t *testing.T) {
	s := newSelfUsage()
	if detectUnifiedRoot() == "" && s.unifiedRoot == "" {
		t.Skip("no cgroup v2 mount in this environment")
	}
	// The domain root must be the namespace mount itself, not the daemon's
	// service slice: /akernel sandboxes are siblings of system.slice.
	if got := detectUnifiedRoot(); got != "/sys/fs/cgroup" {
		t.Fatalf("domain root = %q, want the namespace mount /sys/fs/cgroup", got)
	}
}

func TestSelfUsageDomainCapacitySentinels(t *testing.T) {
	s := &selfUsage{unifiedRoot: "/nonexistent"}
	if _, _, err := s.DomainCPUQuotaUsec(); err == nil {
		t.Fatal("unreadable domain must error, not zero")
	}
	if _, err := s.DomainCapacityBytes(); err == nil {
		t.Fatal("unreadable domain must error, not zero")
	}
}
