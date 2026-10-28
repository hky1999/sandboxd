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
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Scheduler extension fields retain their generation, revision and operation
// identities across the intentional migration of the public agent-dx base.
func TestSchedulerResourceExtensionNumbers(t *testing.T) {
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
		if len(message.Field) != 6 {
			t.Fatal("unexpected start identity extension")
		}
		field := message.Field[4]
		if field.GetName() != "resource_generation" || field.GetNumber() != 5 || field.GetType() != descriptorpb.FieldDescriptorProto_TYPE_STRING || field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL {
			t.Fatal("unexpected start generation field")
		}
		if message.Field[5].GetName() != "ports" || message.Field[5].GetNumber() != 6 {
			t.Fatal("unexpected scheduler port mappings field")
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
	projectCheckpointResources(t, descriptor)
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

// Older clients must continue to decode the original fields when the server
// supplies the sandbox network endpoint required by agent-dx clients.
func TestStartResponseLegacyWireCompatibility(t *testing.T) {
	response := &StartResponse{Code: 0, Message: "Succeed", ID: "sandbox-compat", SandboxIp: "10.88.0.2"}
	message := protodesc.ToDescriptorProto(response.ProtoReflect().Descriptor())
	if got := message.Field[3].GetNumber(); got != 4 {
		t.Fatalf("sandbox_ip field number = %d, want 4", got)
	}
	message.Field = message.Field[:3]
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:        proto.String("legacy-start-response.proto"),
		Package:     proto.String("legacy"),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{message},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	legacy := dynamicpb.NewMessage(file.Messages().Get(0))
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(wire, legacy); err != nil {
		t.Fatal(err)
	}
	fields := legacy.Descriptor().Fields()
	if legacy.Get(fields.ByNumber(1)).Int() != 0 || legacy.Get(fields.ByNumber(2)).String() != "Succeed" || legacy.Get(fields.ByNumber(3)).String() != response.ID {
		t.Fatalf("legacy response fields changed: %s", legacy)
	}
	legacyWire, err := proto.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var decoded StartResponse
	if err := proto.Unmarshal(legacyWire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != response.ID || decoded.Message != response.Message || decoded.SandboxIp != "" {
		t.Fatalf("legacy server response did not retain its original fields: %s", &decoded)
	}
}

// Compare the public schema with a descriptor generated independently from the
// fixed upstream source. Scheduler-only fields must remain additive.
func TestAgentDXUpstreamWireCompatibility(t *testing.T) {
	wire, err := os.ReadFile("testdata/agent-dx-base.pb")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != "b2fef6676c7626036f23e610aff5821d89851cadbd8e2021746cfa044cb58e5d" {
		t.Fatal("upstream descriptor fixture changed")
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(wire, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.File) != 1 {
		t.Fatal("unexpected upstream descriptor count")
	}
	current := protodesc.ToFileDescriptorProto(File_api_runtime_v1_sandbox_api_proto)
	compareEnums := func(bases, actuals []*descriptorpb.EnumDescriptorProto) {
		for _, base := range bases {
			var actual *descriptorpb.EnumDescriptorProto
			for _, candidate := range actuals {
				if candidate.GetName() == base.GetName() {
					actual = candidate
					break
				}
			}
			if actual == nil || !proto.Equal(base.Options, actual.Options) {
				t.Fatalf("missing or changed upstream enum %s", base.GetName())
			}
			for _, value := range base.Value {
				var found *descriptorpb.EnumValueDescriptorProto
				for _, candidate := range actual.Value {
					if candidate.GetNumber() == value.GetNumber() {
						found = candidate
						break
					}
				}
				if !proto.Equal(value, found) {
					t.Fatalf("changed upstream enum value %s.%s", base.GetName(), value.GetName())
				}
			}
		}
	}
	var compareMessage func(*descriptorpb.DescriptorProto, *descriptorpb.DescriptorProto)
	compareMessage = func(base, got *descriptorpb.DescriptorProto) {
		if got == nil {
			t.Fatalf("missing upstream message %s", base.GetName())
		}
		if !proto.Equal(base.Options, got.Options) {
			t.Fatalf("changed message options %s", base.GetName())
		}
		compareEnums(base.EnumType, got.EnumType)
		for _, field := range base.Field {
			var found *descriptorpb.FieldDescriptorProto
			for _, candidate := range got.Field {
				if candidate.GetNumber() == field.GetNumber() {
					found = candidate
					break
				}
			}
			if !proto.Equal(field, found) {
				t.Fatalf("changed upstream field %s.%s at %d: got %v", base.GetName(), field.GetName(), field.GetNumber(), found)
			}
		}
		for _, nested := range base.NestedType {
			var found *descriptorpb.DescriptorProto
			for _, candidate := range got.NestedType {
				if candidate.GetName() == nested.GetName() {
					found = candidate
					break
				}
			}
			compareMessage(nested, found)
		}
	}
	for _, message := range set.File[0].MessageType {
		var found *descriptorpb.DescriptorProto
		for _, candidate := range current.MessageType {
			if candidate.GetName() == message.GetName() {
				found = candidate
				break
			}
		}
		compareMessage(message, found)
	}
	compareEnums(set.File[0].EnumType, current.EnumType)
	for _, service := range set.File[0].Service {
		var found *descriptorpb.ServiceDescriptorProto
		for _, candidate := range current.Service {
			if candidate.GetName() == service.GetName() {
				found = candidate
				break
			}
		}
		if found == nil {
			t.Fatalf("missing upstream service %s", service.GetName())
		}
		for _, method := range service.Method {
			var actual *descriptorpb.MethodDescriptorProto
			for _, candidate := range found.Method {
				if candidate.GetName() == method.GetName() {
					actual = candidate
					break
				}
			}
			if !proto.Equal(method, actual) {
				t.Fatalf("changed upstream method %s.%s", service.GetName(), method.GetName())
			}
		}
	}
}

// projectCheckpointResources validates and removes only the additive scheduler resource condition.
func projectCheckpointResources(t *testing.T, descriptor *descriptorpb.FileDescriptorProto) {
	t.Helper()
	found := false
	for _, message := range descriptor.MessageType {
		if message.GetName() != "CheckpointIfResourcesRequest" {
			continue
		}
		if found || len(message.Field) != 3 || len(message.NestedType) != 0 || len(message.EnumType) != 0 {
			t.Fatal("unexpected resource-conditioned checkpoint request")
		}
		found = true
		names := []string{"checkpoint", "expected_generation", "expected_revision"}
		kinds := []descriptorpb.FieldDescriptorProto_Type{descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_UINT64}
		for i, name := range names {
			field := message.Field[i]
			if field.GetName() != name || field.GetNumber() != int32(i+1) || field.GetType() != kinds[i] || field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL || field.OneofIndex != nil || field.GetProto3Optional() {
				t.Fatal("unexpected original resource condition wire field")
			}
			if i == 0 && field.GetTypeName() != "."+descriptor.GetPackage()+".CheckpointRequest" {
				t.Fatal("unexpected checkpoint command type")
			}
			if i != 0 && field.GetTypeName() != "" {
				t.Fatal("unexpected scalar condition type")
			}
		}
	}
	if !found {
		t.Fatal("missing separate resource checkpoint message")
	}
	descriptor.MessageType = slices.DeleteFunc(descriptor.MessageType, func(m *descriptorpb.DescriptorProto) bool { return m.GetName() == "CheckpointIfResourcesRequest" })
	rpcFound := false
	for _, service := range descriptor.Service {
		service.Method = slices.DeleteFunc(service.Method, func(m *descriptorpb.MethodDescriptorProto) bool {
			if m.GetName() != "CheckpointIfResources" {
				return false
			}
			if rpcFound || service.GetName() != "SandboxService" || m.GetInputType() != "."+descriptor.GetPackage()+".CheckpointIfResourcesRequest" || m.GetOutputType() != "."+descriptor.GetPackage()+".CheckpointResponse" || m.GetClientStreaming() || m.GetServerStreaming() {
				t.Fatal("unexpected resource-conditioned checkpoint RPC")
			}
			rpcFound = true
			return true
		})
	}
	if !rpcFound {
		t.Fatal("missing separate resource checkpoint RPC")
	}
	responseFound := false
	for _, message := range descriptor.MessageType {
		if message.GetName() != "CheckpointResponse" {
			continue
		}
		if responseFound || len(message.Field) != 7 {
			t.Fatal("unexpected resource-conditioned checkpoint reply")
		}
		responseFound = true
		field := message.Field[6]
		if field.GetName() != "source_resource_revision" || field.GetJsonName() != "sourceResourceRevision" || field.GetNumber() != 7 || field.GetType() != descriptorpb.FieldDescriptorProto_TYPE_UINT64 || field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL || field.OneofIndex != nil || field.GetProto3Optional() {
			t.Fatal("unexpected committed resource revision reply field")
		}
		message.Field = message.Field[:6]
	}
	if !responseFound {
		t.Fatal("missing checkpoint resource reply")
	}
}
