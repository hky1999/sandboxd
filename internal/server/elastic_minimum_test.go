// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0
package server

import (
	"fmt"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
)

func minimumRequest(t *testing.T, minimum string) {
	t.Helper()
	req := elasticTestRequest(t)
	req.Labels[elasticResourcesLabel] = fmt.Sprintf(`{"version":2,"CPU":{"initial":500,"ceiling":500},"Memory":{"initial":2048,"ceiling":2048},"memory_minimum_mib":%s}`, minimum)
	req.Resources["Memory"] = 2048
	if err := validateElasticResources(req, config.DefaultConfig(), false); err != nil {
		t.Fatalf("ordinary birth changed or minimum rejected: %v", err)
	}
	req.Resources["Memory"] = 640
	if err := validateElasticResources(req, config.DefaultConfig(), true); err != nil {
		t.Fatalf("valid effective shrink/restore limit rejected: %v", err)
	}
	req.Resources["Memory"] = 639
	if err := validateElasticResources(req, config.DefaultConfig(), true); err == nil {
		t.Fatal("effective limit below the persisted minimum accepted")
	}
	req.Resources["Memory"] = 640
	if err := validateElasticResources(req, config.DefaultConfig(), false); err == nil {
		t.Fatal("ordinary birth silently adopted shrink minimum")
	}
}
func TestIndependentMemoryMinimumPreservesBirthAndBounds(t *testing.T) { minimumRequest(t, "640") }
func TestIndependentMemoryMinimumRejectsMalformedPolicies(t *testing.T) {
	for _, minimum := range []string{"0", "-1", "2049", "640.5", "null", "true", "1e30"} {
		t.Run(minimum, func(t *testing.T) {
			req := elasticTestRequest(t)
			req.Labels[elasticResourcesLabel] = fmt.Sprintf(`{"version":2,"CPU":{"initial":500,"ceiling":500},"Memory":{"initial":2048,"ceiling":2048},"memory_minimum_mib":%s}`, minimum)
			req.Resources["Memory"] = 2048
			if err := validateElasticResources(req, config.DefaultConfig(), false); err == nil {
				t.Fatal("invalid minimum accepted")
			}
		})
	}
	for _, raw := range []string{
		`{"version":1,"CPU":{"initial":500,"ceiling":500},"Memory":{"initial":2048,"ceiling":2048},"memory_minimum_mib":640}`,
		`{"version":2,"CPU":{"initial":500,"ceiling":500},"Memory":{"initial":2048,"ceiling":2048}}`,
	} {
		req := elasticTestRequest(t)
		req.Labels[elasticResourcesLabel] = raw
		req.Resources["Memory"] = 2048
		if err := validateElasticResources(req, config.DefaultConfig(), false); err == nil {
			t.Fatal("ambiguous policy version accepted")
		}
	}
}
