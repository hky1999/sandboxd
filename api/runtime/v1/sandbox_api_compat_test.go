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
// The generation-conditional DeleteIfGeneration RPC and the
// StartResponse.resource_generation identity field are validated and then
// projected out before the frozen v0.1.0 hash comparison, so every other part
// of the prior wire contract must remain byte-identical.
func TestV010WireContract(t *testing.T) {
	descriptor := protodesc.ToFileDescriptorProto(File_api_runtime_v1_sandbox_api_proto)
	descriptor.SourceCodeInfo = nil
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
