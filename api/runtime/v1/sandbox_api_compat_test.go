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
func TestV010WireContract(t *testing.T) {
	descriptor := protodesc.ToFileDescriptorProto(File_api_runtime_v1_sandbox_api_proto)
	descriptor.SourceCodeInfo = nil
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	const want = "3e7cd829a4878b42660a7cb52c1f0ca6ba2206f74be12e44727a119019abd670"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sandbox API descriptor hash = %s, want %s", got, want)
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
