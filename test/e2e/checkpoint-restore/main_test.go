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

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeClient records the four RPCs the CLI selects between, answering each
// from a configurable stub. The embedded interface is nil, so any other RPC
// (Start, say) panics — misuse tests thereby prove no RPC was reached.
type fakeClient struct {
	runtime.SandboxServiceClient

	checkpointCalls   []*runtime.CheckpointRequest
	checkpointIfCalls []*runtime.CheckpointIfGenerationRequest
	deleteCalls       []*runtime.DeleteRequest
	deleteIfCalls     []*runtime.DeleteIfGenerationRequest

	checkpointErr   error
	checkpointIfErr error
	deleteErr       error
	deleteIfErr     error

	retiredGeneration string
}

func (f *fakeClient) Checkpoint(
	_ context.Context,
	request *runtime.CheckpointRequest,
	_ ...grpc.CallOption,
) (*runtime.CheckpointResponse, error) {
	f.checkpointCalls = append(f.checkpointCalls, request)
	return new(runtime.CheckpointResponse), f.checkpointErr
}

func (f *fakeClient) CheckpointIfGeneration(
	_ context.Context,
	request *runtime.CheckpointIfGenerationRequest,
	_ ...grpc.CallOption,
) (*runtime.CheckpointResponse, error) {
	f.checkpointIfCalls = append(f.checkpointIfCalls, request)
	return new(runtime.CheckpointResponse), f.checkpointIfErr
}

func (f *fakeClient) Delete(
	_ context.Context,
	request *runtime.DeleteRequest,
	_ ...grpc.CallOption,
) (*runtime.DeleteResponse, error) {
	f.deleteCalls = append(f.deleteCalls, request)
	return new(runtime.DeleteResponse), f.deleteErr
}

func (f *fakeClient) DeleteIfGeneration(
	_ context.Context,
	request *runtime.DeleteIfGenerationRequest,
	_ ...grpc.CallOption,
) (*runtime.DeleteIfGenerationResponse, error) {
	f.deleteIfCalls = append(f.deleteIfCalls, request)
	return &runtime.DeleteIfGenerationResponse{RetiredGeneration: f.retiredGeneration}, f.deleteIfErr
}

func (f *fakeClient) totalCalls() int {
	return len(f.checkpointCalls) + len(f.checkpointIfCalls) +
		len(f.deleteCalls) + len(f.deleteIfCalls)
}

func checkpointOptions() options {
	return options{
		sandboxID:                "sbx-1",
		checkpointDir:            "/tmp/cp",
		checkpointTimeoutSeconds: 30,
		compress:                 true,
		leaveRunning:             true,
		snapshotType:             "Full",
	}
}

func TestCheckpointSelectsRPCByExpectedGeneration(t *testing.T) {
	client := new(fakeClient)
	if err := checkpoint(context.Background(), client, checkpointOptions()); err != nil {
		t.Fatalf("legacy checkpoint: %v", err)
	}
	if len(client.checkpointCalls) != 1 {
		t.Fatalf("legacy Checkpoint calls = %d, want 1", len(client.checkpointCalls))
	}
	if len(client.checkpointIfCalls) != 0 {
		t.Fatalf("legacy CheckpointIfGeneration calls = %d, want 0", len(client.checkpointIfCalls))
	}

	value := checkpointOptions()
	value.expectedGeneration = "gen-42"
	client = new(fakeClient)
	if err := checkpoint(context.Background(), client, value); err != nil {
		t.Fatalf("conditional checkpoint: %v", err)
	}
	if len(client.checkpointCalls) != 0 {
		t.Fatalf("conditional checkpoint called plain Checkpoint %d times", len(client.checkpointCalls))
	}
	if len(client.checkpointIfCalls) != 1 {
		t.Fatalf("CheckpointIfGeneration calls = %d, want 1", len(client.checkpointIfCalls))
	}
	got := client.checkpointIfCalls[0]
	if got.GetExpectedGeneration() != "gen-42" {
		t.Errorf("expected_generation = %q, want %q", got.GetExpectedGeneration(), "gen-42")
	}
	inner := got.GetCheckpoint()
	if inner.GetID() != "sbx-1" || inner.GetCheckpointDir() != "/tmp/cp" ||
		inner.GetTimeoutSeconds() != 30 || !inner.GetCompress() ||
		!inner.GetLeaveRunning() || inner.GetSnapshotType() != "Full" {
		t.Errorf("embedded checkpoint request = %+v", inner)
	}
}

func TestDeleteSelectsRPCByExpectedGeneration(t *testing.T) {
	client := new(fakeClient)
	if err := deleteSandbox(context.Background(), client, options{sandboxID: "sbx-1"}); err != nil {
		t.Fatalf("legacy delete: %v", err)
	}
	if len(client.deleteCalls) != 1 || client.deleteCalls[0].GetID() != "sbx-1" {
		t.Fatalf("legacy Delete calls = %+v", client.deleteCalls)
	}
	if len(client.deleteIfCalls) != 0 {
		t.Fatalf("legacy DeleteIfGeneration calls = %d, want 0", len(client.deleteIfCalls))
	}

	client = &fakeClient{retiredGeneration: "gen-42"}
	if err := deleteSandbox(
		context.Background(),
		client,
		options{sandboxID: "sbx-1", expectedGeneration: "gen-42"},
	); err != nil {
		t.Fatalf("conditional delete: %v", err)
	}
	if len(client.deleteCalls) != 0 {
		t.Fatalf("conditional delete called plain Delete %d times", len(client.deleteCalls))
	}
	if len(client.deleteIfCalls) != 1 {
		t.Fatalf("DeleteIfGeneration calls = %d, want 1", len(client.deleteIfCalls))
	}
	if request := client.deleteIfCalls[0]; request.GetID() != "sbx-1" ||
		request.GetExpectedGeneration() != "gen-42" {
		t.Errorf("DeleteIfGeneration request = %+v", request)
	}
}

func TestDeleteReceiptMustMatchExpectedGeneration(t *testing.T) {
	client := &fakeClient{retiredGeneration: "gen-43"}
	err := deleteSandbox(
		context.Background(),
		client,
		options{sandboxID: "sbx-1", expectedGeneration: "gen-42"},
	)
	if err == nil {
		t.Fatal("mismatched retired_generation must fail the delete")
	}
	if !strings.Contains(err.Error(), "gen-43") || !strings.Contains(err.Error(), "gen-42") {
		t.Errorf("error should name the retired and expected generations, got %v", err)
	}
	if len(client.deleteCalls) != 0 {
		t.Fatalf("receipt mismatch must not fall back to Delete")
	}
}

func TestConditionalFailuresNeverFallback(t *testing.T) {
	failures := []error{
		status.Error(codes.Unimplemented, "sandboxd predates the conditional RPCs"),
		errors.New("generation conflict"),
	}
	for _, failure := range failures {
		client := &fakeClient{checkpointIfErr: failure}
		err := checkpoint(context.Background(), client, func() options {
			value := checkpointOptions()
			value.expectedGeneration = "gen-42"
			return value
		}())
		if err == nil || !errors.Is(err, failure) {
			t.Fatalf("conditional checkpoint error = %v, want %v", err, failure)
		}
		if len(client.checkpointCalls) != 0 {
			t.Fatalf("failed conditional checkpoint fell back to plain Checkpoint")
		}

		client = &fakeClient{deleteIfErr: failure, retiredGeneration: "gen-42"}
		err = deleteSandbox(
			context.Background(),
			client,
			options{sandboxID: "sbx-1", expectedGeneration: "gen-42"},
		)
		if err == nil || !errors.Is(err, failure) {
			t.Fatalf("conditional delete error = %v, want %v", err, failure)
		}
		if len(client.deleteCalls) != 0 {
			t.Fatalf("failed conditional delete fell back to plain Delete")
		}
	}
}

func TestInvalidExpectedGenerationRejectedBeforeRPC(t *testing.T) {
	invalid := []string{
		" ",
		"\t\n",
		strings.Repeat("x", 257),
	}
	for _, generation := range invalid {
		client := new(fakeClient)
		value := checkpointOptions()
		value.expectedGeneration = generation
		if err := checkpoint(context.Background(), client, value); err == nil {
			t.Errorf("checkpoint accepted invalid generation %q", generation)
		} else if client.totalCalls() != 0 {
			t.Errorf("checkpoint with generation %q still reached an RPC", generation)
		}

		client = new(fakeClient)
		if err := deleteSandbox(context.Background(), client, options{
			sandboxID:          "sbx-1",
			expectedGeneration: generation,
		}); err == nil {
			t.Errorf("delete accepted invalid generation %q", generation)
		} else if client.totalCalls() != 0 {
			t.Errorf("delete with generation %q still reached an RPC", generation)
		}
	}

	// The 256-byte boundary itself stays valid.
	client := new(fakeClient)
	value := checkpointOptions()
	value.expectedGeneration = strings.Repeat("x", maxExpectedGenerationLength)
	if err := checkpoint(context.Background(), client, value); err != nil {
		t.Fatalf("checkpoint at the length boundary: %v", err)
	}
	if len(client.checkpointIfCalls) != 1 {
		t.Fatalf("CheckpointIfGeneration calls = %d, want 1", len(client.checkpointIfCalls))
	}
}

func TestExpectedGenerationRejectedForStartAndRestore(t *testing.T) {
	client := new(fakeClient)
	if err := start(context.Background(), client, options{
		rootfs:             "/tmp/rootfs",
		sandboxID:          "sbx-1",
		requestFile:        "/tmp/start.json",
		expectedGeneration: "gen-42",
	}); err == nil {
		t.Error("start must reject --expected-generation")
	}
	if err := restore(context.Background(), client, options{
		targetID:           "sbx-2",
		checkpointDir:      "/tmp/cp",
		requestFile:        "/tmp/start.json",
		expectedGeneration: "gen-42",
	}); err == nil {
		t.Error("restore must reject --expected-generation")
	}
	if client.totalCalls() != 0 {
		t.Fatalf("misused --expected-generation still reached %d RPCs", client.totalCalls())
	}
}
