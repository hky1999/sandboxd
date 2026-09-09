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
// The generation-conditional DeleteIfGeneration and CheckpointIfGeneration
// RPCs, the StartResponse.resource_generation identity field, and the
// additive start-operation identity surface (StartWithOperation /
// GetStartOperation RPCs, their four request/status messages, and the
// StartOperationState enum) are validated in shape — field numbers, types,
// labels, enum values, RPC input/output types, and unary streaming — and
// then projected out before the frozen v0.1.0 hash comparison, so every
// other part of the prior wire contract must remain byte-identical.
func TestV010WireContract(t *testing.T) {
	descriptor := protodesc.ToFileDescriptorProto(File_api_runtime_v1_sandbox_api_proto)
	descriptor.SourceCodeInfo = nil
	projectCheckpointOperationWire(t, descriptor)
	for _, message := range descriptor.MessageType {
		if message.GetName() != "StartResponse" {
			continue
		}
		if len(message.Field) != 4 {
			t.Fatal("unexpected start identity extension")
		}
		field := message.Field[3]
		if field.GetName() != "resource_generation" || field.GetNumber() != 5 || field.GetType() != descriptorpb.FieldDescriptorProto_TYPE_STRING || field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL {
			t.Fatal("unexpected start generation field")
		}
		message.Field = message.Field[:3]
	}
	// Validate the additive conditional checkpoint API, then project it out.
	// Keep the frozen legacy descriptor hash unchanged.
	foundCheckpointRequest := false
	for _, message := range descriptor.MessageType {
		if message.GetName() != "CheckpointIfGenerationRequest" {
			continue
		}
		if foundCheckpointRequest || len(message.Field) != 2 || len(message.NestedType) != 0 || len(message.EnumType) != 0 || len(message.OneofDecl) != 0 || len(message.Extension) != 0 || len(message.ReservedRange) != 0 || len(message.ReservedName) != 0 {
			t.Fatal("unexpected conditional checkpoint message")
		}
		foundCheckpointRequest = true
		for i, f := range message.Field {
			name, kind, typeName := "expected_generation", descriptorpb.FieldDescriptorProto_TYPE_STRING, ""
			if i == 0 {
				name, kind, typeName = "checkpoint", descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, "."+descriptor.GetPackage()+".CheckpointRequest"
			}
			if f.GetName() != name || f.GetNumber() != int32(i+1) || f.GetType() != kind || f.GetTypeName() != typeName || f.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL || f.OneofIndex != nil || f.GetProto3Optional() {
				t.Fatal("unexpected conditional checkpoint field")
			}
		}
	}
	if !foundCheckpointRequest {
		t.Fatal("missing conditional checkpoint request")
	}
	foundCheckpointRPC := false
	for _, service := range descriptor.Service {
		service.Method = slices.DeleteFunc(service.Method, func(m *descriptorpb.MethodDescriptorProto) bool {
			if m.GetName() != "CheckpointIfGeneration" {
				return false
			}
			if foundCheckpointRPC || service.GetName() != "SandboxService" || m.GetInputType() != "."+descriptor.GetPackage()+".CheckpointIfGenerationRequest" || m.GetOutputType() != "."+descriptor.GetPackage()+".CheckpointResponse" || m.GetClientStreaming() || m.GetServerStreaming() {
				t.Fatal("unexpected conditional checkpoint RPC")
			}
			foundCheckpointRPC = true
			return true
		})
	}
	if !foundCheckpointRPC {
		t.Fatal("missing conditional checkpoint RPC")
	}
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
		return m.GetName() == "DeleteIfGenerationRequest" || m.GetName() == "DeleteIfGenerationResponse" || m.GetName() == "CheckpointIfGenerationRequest"
	})
	// Validate the additive start-operation identity API, then project it
	// out the same way, keeping the frozen legacy descriptor hash unchanged.
	pkg := "." + descriptor.GetPackage()
	type wireField struct {
		name     string
		kind     descriptorpb.FieldDescriptorProto_Type
		typeName string
	}
	stringField := func(name string) wireField {
		return wireField{name: name, kind: descriptorpb.FieldDescriptorProto_TYPE_STRING}
	}
	operationShape := map[string][]wireField{
		"RestoreArtifactIdentity": {
			stringField("checkpoint_dir"),
			stringField("expected_root_digest"),
		},
		"StartWithOperationRequest": {
			stringField("operation_id"),
			stringField("sandbox_id"),
			{"start", descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, pkg + ".StartRequest"},
			{"restore_artifacts", descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, pkg + ".RestoreArtifactIdentity"},
		},
		"StartOperationStatus": {
			stringField("operation_id"),
			stringField("sandbox_id"),
			{"state", descriptorpb.FieldDescriptorProto_TYPE_ENUM, pkg + ".StartOperationState"},
			stringField("resource_generation"),
			stringField("message"),
		},
		"GetStartOperationRequest": {
			stringField("operation_id"),
		},
	}
	for _, message := range descriptor.MessageType {
		shape, added := operationShape[message.GetName()]
		if !added {
			continue
		}
		if len(message.Field) != len(shape) || len(message.NestedType) != 0 || len(message.EnumType) != 0 || len(message.OneofDecl) != 0 || len(message.Extension) != 0 || len(message.ReservedRange) != 0 || len(message.ReservedName) != 0 {
			t.Fatalf("unexpected start-operation message %s", message.GetName())
		}
		for i, want := range shape {
			f := message.Field[i]
			if f.GetName() != want.name || f.GetNumber() != int32(i+1) || f.GetType() != want.kind || f.GetTypeName() != want.typeName || f.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL || f.OneofIndex != nil || f.GetProto3Optional() {
				t.Fatalf("unexpected start-operation field %d of %s", i, message.GetName())
			}
		}
		delete(operationShape, message.GetName())
	}
	if len(operationShape) != 0 {
		t.Fatal("missing start-operation messages")
	}
	foundOperationEnum := false
	for _, enum := range descriptor.EnumType {
		if enum.GetName() != "StartOperationState" {
			continue
		}
		wantValues := []string{
			"START_OPERATION_STATE_UNSPECIFIED",
			"START_OPERATION_STATE_RUNNING",
			"START_OPERATION_STATE_SUCCEEDED",
			"START_OPERATION_STATE_FAILED",
			"START_OPERATION_STATE_UNKNOWN",
		}
		if foundOperationEnum || len(enum.Value) != len(wantValues) || len(enum.ReservedRange) != 0 || len(enum.ReservedName) != 0 {
			t.Fatal("unexpected start-operation state enum")
		}
		foundOperationEnum = true
		for i, want := range wantValues {
			v := enum.Value[i]
			if v.GetName() != want || v.GetNumber() != int32(i) {
				t.Fatal("unexpected start-operation state value")
			}
		}
	}
	if !foundOperationEnum {
		t.Fatal("missing start-operation state enum")
	}
	operationRPCs := map[string][2]string{
		"StartWithOperation": {pkg + ".StartWithOperationRequest", pkg + ".StartOperationStatus"},
		"GetStartOperation":  {pkg + ".GetStartOperationRequest", pkg + ".StartOperationStatus"},
	}
	for _, service := range descriptor.Service {
		service.Method = slices.DeleteFunc(service.Method, func(m *descriptorpb.MethodDescriptorProto) bool {
			io, added := operationRPCs[m.GetName()]
			if !added {
				return false
			}
			if service.GetName() != "SandboxService" || m.GetInputType() != io[0] || m.GetOutputType() != io[1] || m.GetClientStreaming() || m.GetServerStreaming() {
				t.Fatalf("unexpected start-operation RPC %s", m.GetName())
			}
			delete(operationRPCs, m.GetName())
			return true
		})
	}
	if len(operationRPCs) != 0 {
		t.Fatal("missing start-operation RPCs")
	}
	descriptor.MessageType = slices.DeleteFunc(descriptor.MessageType, func(m *descriptorpb.DescriptorProto) bool {
		return m.GetName() == "StartWithOperationRequest" || m.GetName() == "RestoreArtifactIdentity" ||
			m.GetName() == "StartOperationStatus" || m.GetName() == "GetStartOperationRequest"
	})
	descriptor.EnumType = slices.DeleteFunc(descriptor.EnumType, func(e *descriptorpb.EnumDescriptorProto) bool {
		return e.GetName() == "StartOperationState"
	})
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	// Rolled for StartRequest.inject_entrypoint (field 22), which supplies the
	// in-sandbox destination for injected OCI image startup configuration.
	// Recompute after any proto change: run this test, copy the got hash.
	const want = "5cbcd4bbad5035b8c2d5224e0f08944f38ee0188d5116e09ac8f16ef5419fc6b"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sandbox API descriptor hash = %s, want %s", got, want)
	}
}

// Validate the additive source-operation surface before projecting it out.
// The legacy descriptor hash must remain unchanged.
func projectCheckpointOperationWire(t *testing.T, d *descriptorpb.FileDescriptorProto) {
	t.Helper()
	type field struct {
		name     string
		kind     descriptorpb.FieldDescriptorProto_Type
		typeName string
	}
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	pkg := "." + d.GetPackage() + "."
	messages := map[string][]field{
		"CheckpointWithOperationRequest": {{"operation_id", str, ""}, {"checkpoint", descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, pkg + "CheckpointRequest"}, {"expected_generation", str, ""}},
		"GetCheckpointOperationRequest":  {{"operation_id", str, ""}},
		"RecoverCheckpointOperationRequest": {
			{"operation", descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, pkg + "CheckpointWithOperationRequest"},
			{"recovery_timeout_seconds", descriptorpb.FieldDescriptorProto_TYPE_UINT32, ""},
		},
		"CheckpointOperationStatus": {
			{"operation_id", str, ""},
			{"sandbox_id", str, ""},
			{"state", descriptorpb.FieldDescriptorProto_TYPE_ENUM, pkg + "CheckpointOperationState"},
			{"source_generation", str, ""},
			{"checkpoint_dir", str, ""},
			{"request_digest", str, ""},
			{"artifact_root_digest", str, ""},
			{"artifact_root_scheme", str, ""},
			{"message", str, ""},
			{"recovery_protocol", descriptorpb.FieldDescriptorProto_TYPE_ENUM, pkg + "CheckpointOperationRecoveryProtocol"},
			{"evidence_released", descriptorpb.FieldDescriptorProto_TYPE_BOOL, ""},
		},
	}
	d.MessageType = slices.DeleteFunc(d.MessageType, func(m *descriptorpb.DescriptorProto) bool {
		want, ok := messages[m.GetName()]
		if !ok {
			return false
		}
		if len(m.Field) != len(want) || len(m.OneofDecl) != 0 || len(m.NestedType) != 0 || len(m.EnumType) != 0 || len(m.ReservedRange) != 0 || len(m.ReservedName) != 0 {
			t.Fatalf("unexpected source operation message %s", m.GetName())
		}
		for i, w := range want {
			f := m.Field[i]
			if f.GetName() != w.name || f.GetNumber() != int32(i+1) || f.GetType() != w.kind || f.GetTypeName() != w.typeName || f.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL || f.OneofIndex != nil || f.GetProto3Optional() {
				t.Fatalf("unexpected source operation field %s.%s", m.GetName(), f.GetName())
			}
		}
		delete(messages, m.GetName())
		return true
	})
	if len(messages) != 0 {
		t.Fatal("missing source operation messages")
	}
	foundEnum := false
	d.EnumType = slices.DeleteFunc(d.EnumType, func(e *descriptorpb.EnumDescriptorProto) bool {
		if e.GetName() != "CheckpointOperationState" {
			return false
		}
		names := []string{"UNSPECIFIED", "RUNNING", "SUCCEEDED", "FAILED", "UNKNOWN"}
		if foundEnum || len(e.Value) != len(names) || len(e.ReservedRange) != 0 || len(e.ReservedName) != 0 {
			t.Fatal("unexpected source operation enum")
		}
		for i, n := range names {
			if e.Value[i].GetName() != "CHECKPOINT_OPERATION_STATE_"+n || e.Value[i].GetNumber() != int32(i) {
				t.Fatal("unexpected source operation enum value")
			}
		}
		foundEnum = true
		return true
	})
	if !foundEnum {
		t.Fatal("missing source operation enum")
	}
	// The additive recovery-protocol enum of the source-operation surface,
	// validated and projected out the same way before the frozen hash.
	foundProtocolEnum := false
	d.EnumType = slices.DeleteFunc(d.EnumType, func(e *descriptorpb.EnumDescriptorProto) bool {
		if e.GetName() != "CheckpointOperationRecoveryProtocol" {
			return false
		}
		names := []string{"UNSPECIFIED", "WITNESS"}
		if foundProtocolEnum || len(e.Value) != len(names) || len(e.ReservedRange) != 0 || len(e.ReservedName) != 0 {
			t.Fatal("unexpected source recovery protocol enum")
		}
		for i, n := range names {
			if e.Value[i].GetName() != "CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_"+n || e.Value[i].GetNumber() != int32(i) {
				t.Fatal("unexpected source recovery protocol enum value")
			}
		}
		foundProtocolEnum = true
		return true
	})
	if !foundProtocolEnum {
		t.Fatal("missing source recovery protocol enum")
	}
	rpcs := map[string]string{
		"CheckpointWithOperation":    "CheckpointWithOperationRequest",
		"GetCheckpointOperation":     "GetCheckpointOperationRequest",
		"RecoverCheckpointOperation": "RecoverCheckpointOperationRequest",
	}
	for _, service := range d.Service {
		service.Method = slices.DeleteFunc(service.Method, func(m *descriptorpb.MethodDescriptorProto) bool {
			input, ok := rpcs[m.GetName()]
			if !ok {
				return false
			}
			if service.GetName() != "SandboxService" || m.GetInputType() != pkg+input || m.GetOutputType() != pkg+"CheckpointOperationStatus" || m.GetClientStreaming() || m.GetServerStreaming() {
				t.Fatal("unexpected source operation RPC")
			}
			delete(rpcs, m.GetName())
			return true
		})
	}
	if len(rpcs) != 0 {
		t.Fatal("missing source operation RPCs")
	}
}
