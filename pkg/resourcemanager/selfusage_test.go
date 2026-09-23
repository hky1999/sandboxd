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
	"os"
	"path/filepath"
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
	if _, err := s.DomainCPUMilli(); err == nil {
		t.Fatal("unreadable domain must error, not zero")
	}
	if _, err := s.DomainCapacityBytes(); err == nil {
		t.Fatal("unreadable domain must error, not zero")
	}
}

// On a live cgroup v2 domain the CPU normalization must divide by the
// period: cpu.max "2000000 100000" is 20 cores = 20000 millicores, not
// 2000000*1000.
func TestSelfUsageDomainCPUNormalizesByPeriod(t *testing.T) {
	if detectUnifiedRoot() == "" {
		t.Skip("no cgroup v2 mount in this environment")
	}
	s := newSelfUsage()
	milli, err := s.DomainCPUMilli()
	if err != nil {
		t.Fatalf("domain cpu read: %v", err)
	}
	if milli < 0 || milli > 100*1000*1000 {
		t.Fatalf("domain cpu millicores out of plausible range: %d", milli)
	}
}

func TestDomainCPUMilliFixtures(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(dir, "cpu.max")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		content string
		want    int64
	}{
		{"2000000 100000\n", 20000},
		{"100000 100000\n", 1000},
		{"50000 50000\n", 1000},
		{"max 100000\n", 0},
		{"garbage\n", 0},
		{"0 100000\n", 0},
		{"100000 0\n", 0},
	}
	for _, tc := range cases {
		got, err := domainCPUMilliFrom(write(tc.content))
		if err != nil {
			t.Fatalf("content %q: %v", tc.content, err)
		}
		if got != tc.want {
			t.Fatalf("content %q: got %d millicores, want %d", tc.content, got, tc.want)
		}
	}
	if _, err := domainCPUMilliFrom(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must error")
	}
}
