// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestCgroupIOAccountingDefaultsDisabled(t *testing.T) {
	if DefaultConfig().CgroupIOAccounting {
		t.Fatal("I/O accounting must be opt-in")
	}
}

func TestCgroupIOAccountingRequiresEnabledPool(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  ResourceConfig
		fail bool
	}{
		{"legacy-disabled-cgroups", ResourceConfig{DisableCgroup: true}, false},
		{"legacy-no-pool", ResourceConfig{}, false},
		{"enabled", ResourceConfig{CgroupIOAccounting: true, CgroupCacheSize: 1}, false},
		{"disabled-cgroups", ResourceConfig{CgroupIOAccounting: true, DisableCgroup: true, CgroupCacheSize: 1}, true},
		{"no-pool", ResourceConfig{CgroupIOAccounting: true}, true},
		{"negative-pool", ResourceConfig{CgroupIOAccounting: true, CgroupCacheSize: -1}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.cfg.ValidateCgroupIOAccounting()
			if (err != nil) != test.fail {
				t.Fatalf("validation error = %v, want failure %v", err, test.fail)
			}
		})
	}
}
