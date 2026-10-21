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
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// TestV010WireContract pins the public protobuf descriptor while allowing
// comments and generated-code details to change.
func TestV010WireContract(t *testing.T) {
	descriptor := protodesc.ToFileDescriptorProto(File_api_runtime_v1_sandbox_api_proto)
	descriptor.SourceCodeInfo = nil
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	// Rolled for additive ADX identified-start/retirement RPCs and generation
	// fields. StartResponse.sandbox_ip stays field 4; resource_generation is
	// field 5. The three- and four-field client tests below pin compatibility.
	// Also includes the additive node-local DescribeCheckpointArtifacts RPC.
	// Recompute after any proto change: run this test, copy the got hash.
	const want = "e09bc417920d032b0e067b50a0116dfd667aa6d59dcf6954b8a5b1ec8f95314e"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sandbox API descriptor hash = %s, want %s", got, want)
	}
}

// Older clients must continue to decode the original fields when the server
// supplies the sandbox network endpoint required by newer YuanRong releases.
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

// The actually deployed ADX A0 client already reads field 4 (sandbox_ip).
// Adding resource_generation must preserve that routing field in both directions.
func TestStartResponseA0FourFieldWireCompatibility(t *testing.T) {
	response := &StartResponse{
		Code: 0, Message: "Succeed", ID: "sbox-a0-wire",
		SandboxIp: "10.88.0.3", ResourceGeneration: "new-generation",
	}
	message := protodesc.ToDescriptorProto(response.ProtoReflect().Descriptor())
	if len(message.Field) != 5 || message.Field[3].GetName() != "sandbox_ip" ||
		message.Field[3].GetNumber() != 4 || message.Field[4].GetName() != "resource_generation" ||
		message.Field[4].GetNumber() != 5 {
		t.Fatalf("additive StartResponse layout changed: %s", message)
	}
	message.Field = message.Field[:4]
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("a0-four-field-start-response.proto"),
		Package: proto.String("legacy_a0"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{message},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	older := dynamicpb.NewMessage(file.Messages().Get(0))
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(wire, older); err != nil {
		t.Fatal(err)
	}
	fields := older.Descriptor().Fields()
	if older.Get(fields.ByNumber(1)).Int() != 0 ||
		older.Get(fields.ByNumber(2)).String() != response.Message ||
		older.Get(fields.ByNumber(3)).String() != response.ID ||
		older.Get(fields.ByNumber(4)).String() != response.SandboxIp {
		t.Fatalf("A0 routing fields changed: %s", older)
	}
	olderWire, err := proto.Marshal(older)
	if err != nil {
		t.Fatal(err)
	}
	var decoded StartResponse
	if err := proto.Unmarshal(olderWire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != response.ID || decoded.Message != response.Message ||
		decoded.SandboxIp != response.SandboxIp || decoded.ResourceGeneration != "" {
		t.Fatalf("A0 response round trip lost routing fields: %s", &decoded)
	}
}
