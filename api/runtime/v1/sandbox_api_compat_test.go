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

package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
)

// TestV010WireContract pins the public protobuf descriptor while allowing
// comments and generated-code details to change.
//
// v011 (2026-08-18): added SandboxService.Pause/Resume and the
// PauseRequest/PauseResponse messages. All v010 field numbers, names,
// and json_names are unchanged.
// Scheduler CPU telemetry adds StatsResponse fields 7-9; the second check
// removes those additions plus SandboxStatus.ip (field 17), which was
// already in the source proto but missing from the prior generated descriptor.
// It verifies that every other part of the prior wire contract is unchanged.
// The generation-conditional CheckpointIfGeneration RPC reuses the existing
// CheckpointResponse; its one new request message and method are validated
// and projected out the same way before every frozen hash comparison.
// The M1 bidirectional resource contract (StatsResponse 24-33, including the
// read-only memory_cgroup_path locator, ResizeResourcesRequest 6-7,
// ShrinkResourcesRequest and its RPC) follows the same rule: validated in
// full, then projected out before any frozen hash.
func TestV010WireContract(t *testing.T) {
	descriptor := protodesc.ToFileDescriptorProto(File_api_runtime_v1_sandbox_api_proto)
	descriptor.SourceCodeInfo = nil
	// Validate then project only this additive bidirectional resource
	// contract (M1): StatsResponse fields 24-33, ResizeResourcesRequest fields
	// 6-7, the ShrinkResourcesRequest message, and the ShrinkResources RPC.
	for _, message := range descriptor.MessageType {
		if message.GetName() != "StatsResponse" {
			continue
		}
		if len(message.Field) != 33 {
			t.Fatalf("unexpected resource-contract field count %d", len(message.Field))
		}
		names := []string{"resource_revision", "resource_revision_known", "memory_high_bytes", "memory_high_known", "memory_high_unlimited", "frozen", "frozen_known", "resource_operation_id", "resource_operation_pending", "memory_cgroup_path"}
		jsonNames := []string{"resourceRevision", "resourceRevisionKnown", "memoryHighBytes", "memoryHighKnown", "memoryHighUnlimited", "frozen", "frozenKnown", "resourceOperationId", "resourceOperationPending", "memoryCgroupPath"}
		for i, name := range names {
			field := message.Field[23+i]
			wantType := descriptorpb.FieldDescriptorProto_TYPE_UINT64
			switch name {
			case "resource_revision_known", "memory_high_known", "memory_high_unlimited", "frozen", "frozen_known", "resource_operation_pending":
				wantType = descriptorpb.FieldDescriptorProto_TYPE_BOOL
			case "resource_operation_id", "memory_cgroup_path":
				wantType = descriptorpb.FieldDescriptorProto_TYPE_STRING
			}
			if field.GetName() != name || field.GetJsonName() != jsonNames[i] ||
				field.GetNumber() != int32(24+i) || field.GetType() != wantType ||
				field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL ||
				field.OneofIndex != nil || field.GetProto3Optional() {
				t.Fatalf("unexpected resource-contract field %s", name)
			}
		}
		message.Field = message.Field[:23]
	}
	// ShrinkResourcesRequest must mirror ResizeResourcesRequest's seven
	// fields exactly before both additions are projected away.
	shrinkNames := []string{"sandbox_id", "resource_generation", "expected", "target", "deadline_unix_ms", "operation_id", "expected_revision"}
	foundShrink := false
	for _, message := range descriptor.MessageType {
		if message.GetName() != "ShrinkResourcesRequest" {
			continue
		}
		if foundShrink || len(message.Field) != len(shrinkNames) || len(message.NestedType) != 0 || len(message.EnumType) != 0 {
			t.Fatal("unexpected shrink request message")
		}
		foundShrink = true
		for i, name := range shrinkNames {
			field := message.Field[i]
			wantType := descriptorpb.FieldDescriptorProto_TYPE_STRING
			switch name {
			case "expected", "target":
				wantType = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
			case "deadline_unix_ms":
				wantType = descriptorpb.FieldDescriptorProto_TYPE_INT64
			case "expected_revision":
				wantType = descriptorpb.FieldDescriptorProto_TYPE_UINT64
			}
			if field.GetName() != name || field.GetNumber() != int32(i+1) || field.GetType() != wantType {
				t.Fatalf("unexpected shrink request field %s", name)
			}
		}
	}
	if !foundShrink {
		t.Fatal("missing ShrinkResourcesRequest message")
	}
	foundShrinkRPC := false
	for _, service := range descriptor.Service {
		service.Method = slices.DeleteFunc(service.Method, func(m *descriptorpb.MethodDescriptorProto) bool {
			if m.GetName() != "ShrinkResources" {
				return false
			}
			if foundShrinkRPC || service.GetName() != "SandboxService" ||
				m.GetInputType() != "."+descriptor.GetPackage()+".ShrinkResourcesRequest" ||
				m.GetOutputType() != "."+descriptor.GetPackage()+".ResizeResourcesResponse" ||
				m.GetClientStreaming() || m.GetServerStreaming() {
				t.Fatal("unexpected ShrinkResources RPC")
			}
			foundShrinkRPC = true
			return true
		})
	}
	if !foundShrinkRPC {
		t.Fatal("missing ShrinkResources RPC")
	}
	descriptor.MessageType = slices.DeleteFunc(descriptor.MessageType, func(m *descriptorpb.DescriptorProto) bool {
		return m.GetName() == "ShrinkResourcesRequest"
	})
	for _, message := range descriptor.MessageType {
		if message.GetName() != "StartResponse" {
			continue
		}
		if len(message.Field) != 5 {
			t.Fatal("unexpected start identity extension")
		}
		field := message.Field[4]
		if field.GetName() != "resource_generation" || field.GetNumber() != 5 || field.GetType() != descriptorpb.FieldDescriptorProto_TYPE_STRING || field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL {
			t.Fatal("unexpected start generation field")
		}
		message.Field = message.Field[:4]
	}
	// Validate then project only this additive conditional-delete contract.
	newMessages := map[string][]string{
		"DeleteIfGenerationRequest":  {"id", "expected_generation"},
		"DeleteIfGenerationResponse": {"retired_generation"},
	}
	for _, message := range descriptor.MessageType {
		names, added := newMessages[message.GetName()]
		if !added {
			continue
		}
		if len(message.Field) != len(names) || len(message.NestedType) != 0 || len(message.EnumType) != 0 {
			t.Fatal("unexpected conditional delete message")
		}
		for i, name := range names {
			f := message.Field[i]
			if f.GetName() != name || f.GetNumber() != int32(i+1) || f.GetType() != descriptorpb.FieldDescriptorProto_TYPE_STRING || f.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL {
				t.Fatal("unexpected conditional delete field")
			}
		}
		delete(newMessages, message.GetName())
	}
	if len(newMessages) != 0 {
		t.Fatal("missing conditional delete messages")
	}
	foundDelete := false
	for _, service := range descriptor.Service {
		service.Method = slices.DeleteFunc(service.Method, func(m *descriptorpb.MethodDescriptorProto) bool {
			if m.GetName() != "DeleteIfGeneration" {
				return false
			}
			if foundDelete || service.GetName() != "SandboxService" || m.GetInputType() != "."+descriptor.GetPackage()+".DeleteIfGenerationRequest" || m.GetOutputType() != "."+descriptor.GetPackage()+".DeleteIfGenerationResponse" || m.GetClientStreaming() || m.GetServerStreaming() {
				t.Fatal("unexpected conditional delete RPC")
			}
			foundDelete = true
			return true
		})
	}
	if !foundDelete {
		t.Fatal("missing conditional delete RPC")
	}
	descriptor.MessageType = slices.DeleteFunc(descriptor.MessageType, func(m *descriptorpb.DescriptorProto) bool {
		return m.GetName() == "DeleteIfGenerationRequest" || m.GetName() == "DeleteIfGenerationResponse"
	})
	// Validate then project only this additive conditional-checkpoint contract.
	foundCheckpointRequest := false
	for _, message := range descriptor.MessageType {
		if message.GetName() != "CheckpointIfGenerationRequest" {
			continue
		}
		if foundCheckpointRequest || len(message.Field) != 2 || len(message.NestedType) != 0 || len(message.EnumType) != 0 {
			t.Fatal("unexpected conditional checkpoint request message")
		}
		foundCheckpointRequest = true
		nested := message.Field[0]
		if nested.GetName() != "checkpoint" || nested.GetNumber() != 1 ||
			nested.GetType() != descriptorpb.FieldDescriptorProto_TYPE_MESSAGE ||
			nested.GetTypeName() != "."+descriptor.GetPackage()+".CheckpointRequest" ||
			nested.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL {
			t.Fatal("unexpected conditional checkpoint request field")
		}
		generation := message.Field[1]
		if generation.GetName() != "expected_generation" || generation.GetNumber() != 2 ||
			generation.GetType() != descriptorpb.FieldDescriptorProto_TYPE_STRING ||
			generation.GetTypeName() != "" ||
			generation.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL {
			t.Fatal("unexpected conditional checkpoint generation field")
		}
	}
	if !foundCheckpointRequest {
		t.Fatal("missing conditional checkpoint request message")
	}
	foundCheckpointRPC := false
	for _, service := range descriptor.Service {
		service.Method = slices.DeleteFunc(service.Method, func(m *descriptorpb.MethodDescriptorProto) bool {
			if m.GetName() != "CheckpointIfGeneration" {
				return false
			}
			if foundCheckpointRPC || service.GetName() != "SandboxService" ||
				m.GetInputType() != "."+descriptor.GetPackage()+".CheckpointIfGenerationRequest" ||
				m.GetOutputType() != "."+descriptor.GetPackage()+".CheckpointResponse" ||
				m.GetClientStreaming() || m.GetServerStreaming() {
				t.Fatal("unexpected conditional checkpoint RPC")
			}
			foundCheckpointRPC = true
			return true
		})
	}
	if !foundCheckpointRPC {
		t.Fatal("missing conditional checkpoint RPC")
	}
	descriptor.MessageType = slices.DeleteFunc(descriptor.MessageType, func(m *descriptorpb.DescriptorProto) bool {
		return m.GetName() == "CheckpointIfGenerationRequest"
	})
	// Project only the validated new checkpoint identity field; keep all
	// frozen descriptor hashes unchanged so existing wire changes still fail.
	for _, message := range descriptor.MessageType {
		if message.GetName() != "CheckpointResponse" {
			continue
		}
		if len(message.Field) != 6 {
			t.Fatal("unexpected checkpoint response extension")
		}
		field := message.Field[5]
		if field.GetName() != "source_generation" || field.GetNumber() != 6 || field.GetType() != descriptorpb.FieldDescriptorProto_TYPE_STRING || field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL {
			t.Fatal("unexpected checkpoint source generation field")
		}
		message.Field = message.Field[:5]
	}
	for _, message := range descriptor.MessageType {
		if message.GetName() != "ResizeResourcesRequest" {
			continue
		}
		if len(message.Field) != 7 {
			t.Fatal("unexpected resize resource-contract field count")
		}
		if message.Field[4].GetName() != "deadline_unix_ms" ||
			message.Field[4].GetNumber() != 5 || message.Field[4].GetType() != descriptorpb.FieldDescriptorProto_TYPE_INT64 {
			t.Fatal("unexpected resize command expiry field")
		}
		if message.Field[5].GetName() != "operation_id" ||
			message.Field[5].GetNumber() != 6 || message.Field[5].GetType() != descriptorpb.FieldDescriptorProto_TYPE_STRING ||
			message.Field[6].GetName() != "expected_revision" ||
			message.Field[6].GetNumber() != 7 || message.Field[6].GetType() != descriptorpb.FieldDescriptorProto_TYPE_UINT64 {
			t.Fatal("unexpected resize operation identity fields")
		}
		message.Field = message.Field[:4]
	}
	// Validate only the four additive source-validity flags before projecting
	// them out. Keep all previously frozen descriptor hashes unchanged.
	for _, message := range descriptor.MessageType {
		if message.GetName() != "StatsResponse" {
			continue
		}
		if len(message.Field) != 23 {
			t.Fatalf("unexpected source-validity field count %d", len(message.Field))
		}
		names := []string{"cpu_usage_known", "memory_usage_known", "memory_limit_known", "memory_peak_known"}
		jsonNames := []string{"cpuUsageKnown", "memoryUsageKnown", "memoryLimitKnown", "memoryPeakKnown"}
		for i, name := range names {
			field := message.Field[19+i]
			if field.GetName() != name || field.GetJsonName() != jsonNames[i] ||
				field.GetNumber() != int32(20+i) || field.GetType() != descriptorpb.FieldDescriptorProto_TYPE_BOOL ||
				field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL ||
				field.OneofIndex != nil || field.GetProto3Optional() {
				t.Fatalf("unexpected source-validity field %s", name)
			}
		}
		message.Field = message.Field[:19]
	}
	// Pressure telemetry is strictly additive to the frozen resize contract.
	for _, message := range descriptor.MessageType {
		if message.GetName() != "StatsResponse" {
			continue
		}
		names := []string{"cpu_pressure_known", "cpu_periods", "cpu_throttled_periods", "cpu_throttled_ns", "memory_pressure_known", "memory_high_events", "memory_oom_events", "memory_oom_kill_events"}
		if len(message.Field) != 19 {
			t.Fatalf("unexpected pressure field count %d", len(message.Field))
		}
		for i, name := range names {
			field := message.Field[11+i]
			wantType := descriptorpb.FieldDescriptorProto_TYPE_UINT64
			if i == 0 || i == 4 {
				wantType = descriptorpb.FieldDescriptorProto_TYPE_BOOL
			}
			if field.GetNumber() != int32(12+i) || field.GetName() != name || field.GetType() != wantType {
				t.Fatalf("unexpected pressure field %d", i)
			}
		}
		message.Field = message.Field[:11]
	}
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	const want = "76eedf4ac128f108495be8ac8e743f7e507adbc08d8fad4d81fe28674676cf0e"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sandbox API descriptor hash = %s, want %s", got, want)
	}
	// Project away only the new resize contract; the entire prior descriptor
	// must remain byte-for-byte identical, including all existing RPCs.
	descriptor.MessageType = slices.DeleteFunc(descriptor.MessageType, func(m *descriptorpb.DescriptorProto) bool {
		return m.GetName() == "ResourceLimits" || m.GetName() == "ResizeResourcesRequest" || m.GetName() == "ResizeResourcesResponse"
	})
	for _, service := range descriptor.Service {
		service.Method = slices.DeleteFunc(service.Method, func(m *descriptorpb.MethodDescriptorProto) bool { return m.GetName() == "ResizeResources" })
	}
	for _, message := range descriptor.MessageType {
		if message.GetName() == "StatsResponse" {
			if len(message.Field) != 11 || message.Field[9].GetNumber() != 10 || message.Field[9].GetName() != "resource_generation" ||
				message.Field[10].GetNumber() != 11 || message.Field[10].GetName() != "elastic_policy" {
				t.Fatal("unexpected resize stats contract")
			}
			message.Field = message.Field[:9]
		}
	}
	previousWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	previousSum := sha256.Sum256(previousWire)
	if hex.EncodeToString(previousSum[:]) != "3e7cd829a4878b42660a7cb52c1f0ca6ba2206f74be12e44727a119019abd670" {
		t.Fatal("resize changed the prior wire contract")
	}
	for _, message := range descriptor.MessageType {
		if message.GetName() == "SandboxStatus" {
			last := len(message.Field) - 1
			if last < 0 || message.Field[last].GetNumber() != 17 || message.Field[last].GetName() != "ip" {
				t.Fatal("missing bridge IP field")
			}
			message.Field = message.Field[:last]
		}
		if message.GetName() == "StatsResponse" {
			if len(message.Field) != 9 {
				t.Fatalf("StatsResponse has %d fields", len(message.Field))
			}
			for index, name := range []string{"cpu_quota_usec", "cpu_period_usec", "cpu_limits_known"} {
				field := message.Field[6+index]
				if field.GetNumber() != int32(7+index) || field.GetName() != name {
					t.Fatalf("CPU telemetry field %d has unexpected identity", index)
				}
			}
			message.Field = message.Field[:6]
		}
	}
	legacyWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	legacySum := sha256.Sum256(legacyWire)
	const legacyWant = "a5923761dfddb093be26dfdccce5830b75e37800d8640f9e4e7113094c50f240"
	if got := hex.EncodeToString(legacySum[:]); got != legacyWant {
		t.Fatalf("existing API changed beyond the additive CPU and bridge IP fields: %s", got)
	}

}

// The scheduler branch once had an Ip Go field without matching descriptor
// metadata, so setting the struct alone did not put bridge IP on the wire.
func TestSandboxIPSurvivesWireRoundTrip(t *testing.T) {
	original := &SandboxStatus{ID: "sbox-wire", Ip: "10.88.0.23"}
	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SandboxStatus
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Ip != original.Ip {
		t.Fatalf("bridge IP lost on wire: %q", decoded.Ip)
	}
}

func TestPressureStatsSurviveWireRoundTrip(t *testing.T) {
	original := &StatsResponse{ResourceGeneration: "generation-1", CpuPressureKnown: true, CpuPeriods: 25, CpuThrottledPeriods: 4, CpuThrottledNs: 123000, MemoryPressureKnown: true, MemoryHighEvents: 9, MemoryOomEvents: 2, MemoryOomKillEvents: 1}
	wire, err := proto.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(StatsResponse)
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(original, decoded) {
		t.Fatal("pressure stats changed on wire")
	}
}

// The M1 resource revision contract must survive the wire unchanged,
// including the explicit unlimited marker that must never collapse into a
// finite zero, and the shrink request carries the same identity fields as
// resize.
func TestResourceRevisionContractSurvivesWireRoundTrip(t *testing.T) {
	original := &StatsResponse{
		ResourceGeneration:       "generation-1",
		ResourceRevision:         7,
		ResourceRevisionKnown:    true,
		MemoryHighBytes:          1,
		MemoryHighKnown:          true,
		MemoryHighUnlimited:      true,
		Frozen:                   false,
		FrozenKnown:              true,
		ResourceOperationID:      "operation-shrink-42",
		ResourceOperationPending: true,
	}
	wire, err := proto.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(StatsResponse)
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(original, decoded) {
		t.Fatal("resource revision contract changed on wire")
	}

	shrink := &ShrinkResourcesRequest{
		SandboxID:          "sbox-shrink",
		ResourceGeneration: "generation-1",
		Expected:           &ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 512 << 20},
		Target:             &ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 256 << 20},
		DeadlineUnixMs:     1760000000000,
		OperationID:        "operation-shrink-42",
		ExpectedRevision:   7,
	}
	wire, err = proto.Marshal(shrink)
	if err != nil {
		t.Fatal(err)
	}
	decodedShrink := new(ShrinkResourcesRequest)
	if err := proto.Unmarshal(wire, decodedShrink); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(shrink, decodedShrink) {
		t.Fatal("shrink request changed on wire")
	}
}
