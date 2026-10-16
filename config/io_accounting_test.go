// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/pelletier/go-toml"
)

func TestCgroupIOAccountingTOMLIsNotIgnored(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			var cfg ResourceConfig
			if err := toml.Unmarshal([]byte("cgroup_io_accounting="+strconv.FormatBool(enabled)+"\n"), &cfg); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			raw, present := fields["cgroupIOAccounting"]
			if !present {
				t.Fatal("cgroup_io_accounting was silently ignored")
			}
			var actual bool
			if err := json.Unmarshal(raw, &actual); err != nil {
				t.Fatal(err)
			}
			if actual != enabled {
				t.Fatalf("I/O accounting = %v, want %v", actual, enabled)
			}
		})
	}
}

func TestCgroupIOAccountingRejectsNonBooleanTOML(t *testing.T) {
	for _, value := range []string{"1", "\"true\""} {
		var cfg ResourceConfig
		if err := toml.Unmarshal([]byte("cgroup_io_accounting="+value+"\n"), &cfg); err == nil {
			t.Fatalf("non-boolean I/O accounting %s accepted", value)
		}
	}
}
