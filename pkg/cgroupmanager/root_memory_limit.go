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

package cgroupmanager

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/sirupsen/logrus"
)

func configureRootMemoryLimit(
	ops cgroupOps, root string, cfg config.MemoryLimitConfig, distillReserve []int64,
	meminfo string, writeMax func(string, int64) error,
) (int64, int64, error) {
	if !cfg.Enabled {
		return 0, 0, nil
	}
	v2, ok := ops.(*cgroupV2)
	if !ok {
		return 0, 0, errors.New("memory_limit requires cgroup v2")
	}
	normalized, err := validateMemoryLimitRoot(root)
	if err != nil {
		return 0, 0, err
	}
	if len(distillReserve) != 1 || distillReserve[0] <= 0 {
		return 0, 0, errors.New("memory_limit requires a positive finite distill-fs memory reserve")
	}
	page := int64(os.Getpagesize())
	distill := distillReserve[0]
	if distill > math.MaxInt64-(page-1) {
		return 0, 0, errors.New("distill-fs memory reserve overflows page rounding")
	}
	distill = ((distill + page - 1) / page) * page
	group := filepath.Join(v2.mountpoint, normalized)
	total, err := rootMemoryCapacity(v2.mountpoint, group, meminfo)
	if err != nil {
		return 0, 0, err
	}
	reserves := []struct {
		name, value string
		positive    bool
	}{
		{"system_reserve", cfg.SystemReserve, true},
		{"control_reserve", cfg.ControlReserve, true},
		{"other_reserve", cfg.OtherReserve, false},
		{"safety_buffer", cfg.SafetyBuffer, true},
		{"runtime_headroom", cfg.RuntimeHeadroom, false},
	}
	values := make([]int64, len(reserves))
	for i, reserve := range reserves {
		if reserve.name == "control_reserve" && reserve.value == "auto" {
			values[i], err = readMemoryMax(filepath.Join(v2.mountpoint, "system.slice", "memory.max"))
		} else if reserve.value == "" && !reserve.positive {
			values[i] = 0
		} else {
			values[i], err = parseMemoryBytes(reserve.value)
		}
		if err != nil {
			return 0, 0, fmt.Errorf("invalid memory_limit.%s %q: %w", reserve.name, reserve.value, err)
		}
		if reserve.positive && values[i] <= 0 {
			return 0, 0, fmt.Errorf("memory_limit.%s must be positive and finite", reserve.name)
		}
	}
	// Subtract independently, avoiding overflow from adding reserves first.
	candidate := total
	for _, reserve := range append(values[:4:4], distill) {
		if reserve >= candidate {
			return 0, 0, errors.New("memory_limit reserves exhaust effective memory capacity")
		}
		candidate -= reserve
	}
	candidate = candidate / page * page
	if candidate == 0 {
		return 0, 0, errors.New("memory_limit leaves less than one page")
	}
	computed := candidate
	existing, err := readMemoryMax(filepath.Join(group, "memory.max"))
	if err != nil {
		return 0, 0, err
	}
	if existing > 0 && existing < candidate {
		candidate = existing
	}
	if values[4] >= candidate {
		return 0, 0, errors.New("memory_limit.runtime_headroom must be below the effective parent limit")
	}
	if existing == 0 || candidate < existing {
		if err := checkRootMemoryEmpty(group, candidate); err != nil {
			return 0, 0, err
		}
		if err := writeMax(group, candidate); err != nil {
			return 0, 0, fmt.Errorf("set parent memory.max: %w", err)
		}
	}
	logrus.Infof("parent memory_limit bytes: total=%d system=%d control=%d other=%d distill=%d safety=%d candidate=%d effective=%d runtime_headroom=%d",
		total, values[0], values[1], values[2], distill, values[3], computed, candidate, values[4])
	return candidate, values[4], nil
}

// Validate before prepareRoot, which creates paths and enables controllers.
func validateMemoryLimitRoot(root string) (string, error) {
	normalized, err := normalizeCgroupRoot(root)
	if err != nil {
		return "", err
	}
	for _, sibling := range []string{"/system.slice", "/distillfs"} {
		if normalized == sibling || strings.HasPrefix(normalized, sibling+"/") || strings.HasPrefix(sibling, normalized+"/") {
			return "", fmt.Errorf("memory_limit root %s overlaps reserved cgroup %s", normalized, sibling)
		}
	}
	return normalized, nil
}

// parseMemoryBytes deliberately accepts only whole decimal bytes and IEC units.
func parseMemoryBytes(value string) (int64, error) {
	value = strings.TrimSpace(value)
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	units := map[string]int64{"": 1, "B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}
	multiplier, ok := units[value[end:]]
	if end == 0 || !ok {
		return 0, fmt.Errorf("invalid byte size %q", value)
	}
	n, err := strconv.ParseInt(value[:end], 10, 64)
	if err != nil || n > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("byte size %q overflows int64", value)
	}
	return n * multiplier, nil
}

// A zero return denotes the kernel's literal "max", never a numeric zero.
func readMemoryMax(filename string) (int64, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", filename, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return 0, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid positive finite memory.max %q at %s", value, filename)
	}
	return n, nil
}

func rootMemoryCapacity(mountpoint, group, meminfo string) (int64, error) {
	data, err := os.ReadFile(meminfo)
	if err != nil {
		return 0, fmt.Errorf("read MemTotal: %w", err)
	}
	total := int64(0)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "MemTotal:" {
			if len(fields) != 3 || fields[2] != "kB" {
				return 0, errors.New("invalid MemTotal in meminfo")
			}
			total, err = parseMemoryBytes(fields[1] + "KiB")
			if err != nil || total <= 0 {
				return 0, errors.New("invalid MemTotal in meminfo")
			}
			break
		}
	}
	if total == 0 {
		return 0, errors.New("MemTotal is missing from meminfo")
	}
	// The owned root's previous cap is excluded to prevent restart shrinkage.
	for path := filepath.Dir(group); ; path = filepath.Dir(path) {
		limit, err := readMemoryMax(filepath.Join(path, "memory.max"))
		// A true unified hierarchy root has no memory.max control.
		if err != nil && !(path == mountpoint && errors.Is(err, os.ErrNotExist)) {
			return 0, err
		}
		if limit > 0 && limit < total {
			total = limit
		}
		if path == mountpoint {
			return total, nil
		}
		if path == filepath.Dir(path) {
			return 0, errors.New("owned memory root is outside the cgroup mountpoint")
		}
	}
}

func checkRootMemoryEmpty(group string, candidate int64) error {
	data, err := os.ReadFile(filepath.Join(group, "cgroup.events"))
	if err != nil {
		return fmt.Errorf("read parent cgroup.events: %w", err)
	}
	populated := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			populated = fields[1]
		}
	}
	if populated != "0" {
		return errors.New("parent cgroup subtree must be empty before adding or lowering memory.max")
	}
	data, err = os.ReadFile(filepath.Join(group, "memory.current"))
	if err != nil {
		return fmt.Errorf("read parent memory.current: %w", err)
	}
	usage, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || usage < 0 || usage > candidate {
		return errors.New("parent residual memory.current exceeds the new memory.max or is invalid")
	}
	return nil
}

func writeRootMemoryMax(group string, candidate int64) error {
	filename := filepath.Join(group, "memory.max")
	file, err := os.OpenFile(filename, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	// Recheck the whole subtree immediately before the kernel write.
	if err := checkRootMemoryEmpty(group, candidate); err != nil {
		return errors.Join(err, file.Close())
	}
	_, writeErr := file.WriteString(strconv.FormatInt(candidate, 10))
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	actual, err := readMemoryMax(filename)
	if err != nil {
		return err
	}
	if actual != candidate {
		return fmt.Errorf("parent memory.max readback %d differs from requested %d", actual, candidate)
	}
	return nil
}
