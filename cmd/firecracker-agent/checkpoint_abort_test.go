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
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"golang.org/x/sys/unix"
)

func abortRequest(
	operationID, sourceGeneration string,
) firecrackerproto.CheckpointAbortRequest {
	return firecrackerproto.CheckpointAbortRequest{
		OperationID:      operationID,
		RequestDigest:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SourceGeneration: sourceGeneration,
	}
}

type handoffRead struct {
	value string
	err   error
}

// readCheckpointHandoff registers a guest FIFO reader and returns the channel
// that will receive its read result.
func readCheckpointHandoff(
	t *testing.T,
	handoff *checkpointHandoff,
) <-chan handoffRead {
	t.Helper()
	result := make(chan handoffRead, 1)
	go func() {
		data, err := os.ReadFile(handoff.fifoPath)
		result <- handoffRead{value: string(data), err: err}
	}()
	waitForCheckpointReader(t, handoff)
	return result
}

func expectHandoff(t *testing.T, result <-chan handoffRead, want string) {
	t.Helper()
	select {
	case read := <-result:
		if read.err != nil || read.value != want {
			t.Fatalf("handoff = %q, %v, want %q", read.value, read.err, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("checkpoint handoff did not deliver %q", want)
	}
}

// expectNoHandoff fails if the reader observes a delivery. Every signal path
// is synchronous under the handoff mutex, so silence after the call returns
// cannot become a delivery later.
func expectNoHandoff(t *testing.T, result <-chan handoffRead) {
	t.Helper()
	select {
	case read := <-result:
		t.Fatalf("checkpoint handoff unexpectedly delivered %q, %v", read.value, read.err)
	case <-time.After(100 * time.Millisecond):
	}
}

func checkpointReaderRegistered(handoff *checkpointHandoff) bool {
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	return handoff.reader != nil
}

func prepareAbortHandoff(t *testing.T) *checkpointHandoff {
	t.Helper()
	handoff, err := prepareCheckpointHandoff(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handoff.close)
	return handoff
}

func TestCheckpointAbortRetryDoesNotReleaseLaterReader(t *testing.T) {
	handoff := prepareAbortHandoff(t)
	request := abortRequest("op-retry", "gen-1")
	first := readCheckpointHandoff(t, handoff)
	if err := handoff.abort(request); err != nil {
		t.Fatal(err)
	}
	expectHandoff(t, first, "error\n")

	// serve/openWriter may register a new guest FIFO reader before a host
	// retry following a lost reply RPC; the wire request is identical.
	second := readCheckpointHandoff(t, handoff)
	if err := handoff.abort(request); err != nil {
		t.Fatalf("duplicate abort rejected: %v", err)
	}
	expectNoHandoff(t, second)
}

func TestCheckpointAbortConflictingBindingRejected(t *testing.T) {
	handoff := prepareAbortHandoff(t)
	request := abortRequest("op-conflict", "gen-1")
	first := readCheckpointHandoff(t, handoff)
	if err := handoff.abort(request); err != nil {
		t.Fatal(err)
	}
	expectHandoff(t, first, "error\n")

	digestConflict := abortRequest("op-conflict", "gen-1")
	digestConflict.RequestDigest = strings.Repeat("f", 64)
	for _, conflicting := range []firecrackerproto.CheckpointAbortRequest{
		abortRequest("op-conflict", "gen-2"),
		digestConflict,
	} {
		err := handoff.abort(conflicting)
		if err == nil || !strings.Contains(err.Error(), "conflicts") {
			t.Fatalf("conflicting abort accepted: %v", err)
		}
	}

	// The recorded receipt keeps its original binding: the first request is
	// still a duplicate, and the conflicting retries released nobody.
	second := readCheckpointHandoff(t, handoff)
	if err := handoff.abort(request); err != nil {
		t.Fatalf("duplicate of original receipt rejected: %v", err)
	}
	expectNoHandoff(t, second)
}

func TestCheckpointAbortWithoutReaderDropsAndRecords(t *testing.T) {
	handoff := prepareAbortHandoff(t)
	request := abortRequest("op-noreader", "gen-1")
	// With no reader the outcome is dropped, never queued, and the receipt is
	// still recorded.
	if err := handoff.abort(request); err != nil {
		t.Fatal(err)
	}
	first := readCheckpointHandoff(t, handoff)
	if err := handoff.abort(request); err != nil {
		t.Fatal(err)
	}
	expectNoHandoff(t, first)

	// An unrelated operation still delivers to that reader.
	if err := handoff.abort(abortRequest("op-noreader-second", "gen-1")); err != nil {
		t.Fatal(err)
	}
	expectHandoff(t, first, "error\n")
}

func TestCheckpointAbortAfterClose(t *testing.T) {
	handoff := prepareAbortHandoff(t)
	request := abortRequest("op-closed", "gen-1")
	if err := handoff.abort(request); err != nil {
		t.Fatal(err)
	}
	handoff.close()

	// A recorded receipt still answers after close: the retry is acked and a
	// conflicting replay is a hard error.
	if err := handoff.abort(request); err != nil {
		t.Fatalf("replay of accepted abort after close: %v", err)
	}
	if err := handoff.abort(abortRequest("op-closed", "gen-2")); err == nil ||
		!strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflicting replay after close = %v", err)
	}

	// An operation the agent never accepted is refused, not acknowledged,
	// and leaves no receipt behind.
	if err := handoff.abort(abortRequest("op-closed-new", "gen-1")); err == nil ||
		!strings.Contains(err.Error(), "closed") {
		t.Fatalf("new abort after close = %v", err)
	}
	handoff.mu.Lock()
	_, recorded := handoff.aborts["op-closed-new"]
	stored := len(handoff.aborts)
	handoff.mu.Unlock()
	if recorded || stored != 1 {
		t.Fatalf("refused abort left receipts: recorded=%v stored=%d", recorded, stored)
	}

	// The legacy signal keeps its drop-and-succeed behavior on a closed
	// handoff.
	if err := handoff.signal("error"); err != nil {
		t.Fatalf("legacy signal after close: %v", err)
	}
}

func TestCheckpointAbortReceiptCapacity(t *testing.T) {
	handoff := prepareAbortHandoff(t)
	for index := 0; index < maxAbortReceipts; index++ {
		request := abortRequest(fmt.Sprintf("op-full-%d", index), "gen-1")
		if err := handoff.abort(request); err != nil {
			t.Fatalf("fill receipt %d: %v", index, err)
		}
	}

	// No eviction: a duplicate of the oldest receipt is still acknowledged.
	if err := handoff.abort(abortRequest("op-full-0", "gen-1")); err != nil {
		t.Fatalf("duplicate of oldest receipt rejected: %v", err)
	}

	// Refusal happens before any effect and records no receipt.
	overflow := abortRequest("op-overflow", "gen-1")
	reader := readCheckpointHandoff(t, handoff)
	for attempt := 0; attempt < 2; attempt++ {
		err := handoff.abort(overflow)
		if err == nil || !strings.Contains(err.Error(), "full") {
			t.Fatalf("overflow attempt %d = %v", attempt, err)
		}
	}
	if !checkpointReaderRegistered(handoff) {
		t.Fatal("refused abort released the registered reader")
	}

	// The reader stays usable and the table did not grow.
	if err := handoff.signal("error"); err != nil {
		t.Fatal(err)
	}
	expectHandoff(t, reader, "error\n")
	handoff.mu.Lock()
	stored := len(handoff.aborts)
	handoff.mu.Unlock()
	if stored != maxAbortReceipts {
		t.Fatalf("stored receipts = %d, want %d", stored, maxAbortReceipts)
	}
}

func TestCheckpointAbortInvalidRequestRejected(t *testing.T) {
	handoff := prepareAbortHandoff(t)
	invalid := []firecrackerproto.CheckpointAbortRequest{
		{},
		func() firecrackerproto.CheckpointAbortRequest {
			request := abortRequest("op", "gen")
			request.OperationID = ""
			return request
		}(),
		func() firecrackerproto.CheckpointAbortRequest {
			request := abortRequest("op", "gen")
			request.OperationID = strings.Repeat(
				"o",
				firecrackerproto.CheckpointAbortMaxIdentityBytes+1,
			)
			return request
		}(),
		func() firecrackerproto.CheckpointAbortRequest {
			request := abortRequest("op", "gen")
			request.SourceGeneration = ""
			return request
		}(),
		func() firecrackerproto.CheckpointAbortRequest {
			request := abortRequest("op", "gen")
			request.SourceGeneration = strings.Repeat(
				"g",
				firecrackerproto.CheckpointAbortMaxIdentityBytes+1,
			)
			return request
		}(),
		func() firecrackerproto.CheckpointAbortRequest {
			request := abortRequest("op", "gen")
			request.RequestDigest = strings.Repeat(
				"0",
				firecrackerproto.CheckpointAbortDigestLength-1,
			)
			return request
		}(),
		func() firecrackerproto.CheckpointAbortRequest {
			request := abortRequest("op", "gen")
			request.RequestDigest = strings.Replace(request.RequestDigest, "a", "z", 1)
			return request
		}(),
	}
	for index, request := range invalid {
		if err := handoff.abort(request); err == nil {
			t.Fatalf("case %d: invalid abort accepted", index)
		}
	}
	handoff.mu.Lock()
	allocated := handoff.aborts != nil
	handoff.mu.Unlock()
	if allocated {
		t.Fatal("invalid aborts allocated the receipt map")
	}

	// An invalid abort never reaches the reader.
	reader := readCheckpointHandoff(t, handoff)
	if err := handoff.abort(invalid[0]); err == nil {
		t.Fatal("accepted invalid abort with a registered reader")
	}
	if !checkpointReaderRegistered(handoff) {
		t.Fatal("invalid abort released the registered reader")
	}
	expectNoHandoff(t, reader)
}

func TestCheckpointAbortConcurrentDuplicates(t *testing.T) {
	handoff := prepareAbortHandoff(t)
	request := abortRequest("op-concurrent", "gen-1")
	first := readCheckpointHandoff(t, handoff)

	const attempts = 32
	results := make(chan error, attempts)
	begin := make(chan struct{})
	var group sync.WaitGroup
	for index := 0; index < attempts; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-begin
			results <- handoff.abort(request)
		}()
	}
	close(begin)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent duplicate abort: %v", err)
		}
	}
	expectHandoff(t, first, "error\n")

	second := readCheckpointHandoff(t, handoff)
	if err := handoff.abort(request); err != nil {
		t.Fatal(err)
	}
	expectNoHandoff(t, second)
}

// exchangeAgentMessage sends one message over a real stream connection and
// returns the agent's response, mirroring the per-request vsock connections
// the host uses.
func exchangeAgentMessage(
	t *testing.T,
	messageType firecrackerproto.MessageType,
	value any,
) firecrackerproto.Response {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	client := os.NewFile(uintptr(pair[0]), "agent-client")
	connection := os.NewFile(uintptr(pair[1]), "agent-connection")
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConnection(connection)
	}()
	defer func() {
		client.Close()
		<-done
	}()
	if err := firecrackerproto.WriteMessage(client, messageType, value); err != nil {
		t.Fatal(err)
	}
	responseType, payload, err := firecrackerproto.ReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	if responseType != firecrackerproto.MessageResponse {
		t.Fatalf("response type = %d, want %d", responseType, firecrackerproto.MessageResponse)
	}
	var response firecrackerproto.Response
	if err := firecrackerproto.Decode(payload, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestCheckpointAbortDispatch(t *testing.T) {
	handoff := prepareAbortHandoff(t)
	state.mu.Lock()
	previous := state.handoff
	state.handoff = handoff
	state.mu.Unlock()
	t.Cleanup(func() {
		state.mu.Lock()
		state.handoff = previous
		state.mu.Unlock()
	})

	// An agent that predates the message rejects it as unknown, and that
	// rejection never signals the handoff on its own.
	first := readCheckpointHandoff(t, handoff)
	if response := exchangeAgentMessage(t, firecrackerproto.MessageType(99), nil); response.OK {
		t.Fatalf("unknown message accepted: %+v", response)
	}
	if !checkpointReaderRegistered(handoff) {
		t.Fatal("unknown-message rejection released the registered reader")
	}

	request := abortRequest("op-dispatch", "gen-1")
	if response := exchangeAgentMessage(
		t,
		firecrackerproto.MessageCheckpointAbort,
		request,
	); !response.OK {
		t.Fatalf("abort response = %+v", response)
	}
	expectHandoff(t, first, "error\n")

	// A retry after a lost reply is acknowledged and leaves a later reader
	// alone; the reply travels on that request's own connection.
	second := readCheckpointHandoff(t, handoff)
	if response := exchangeAgentMessage(
		t,
		firecrackerproto.MessageCheckpointAbort,
		request,
	); !response.OK {
		t.Fatalf("duplicate abort response = %+v", response)
	}
	expectNoHandoff(t, second)

	conflicting := request
	conflicting.SourceGeneration = "gen-2"
	if response := exchangeAgentMessage(
		t,
		firecrackerproto.MessageCheckpointAbort,
		conflicting,
	); response.OK || !strings.Contains(response.Error, "conflicts") {
		t.Fatalf("conflicting abort response = %+v", response)
	}

	invalid := request
	invalid.RequestDigest = "not-hex"
	if response := exchangeAgentMessage(
		t,
		firecrackerproto.MessageCheckpointAbort,
		invalid,
	); response.OK || !strings.Contains(response.Error, "digest") {
		t.Fatalf("invalid abort response = %+v", response)
	}

	unknownField := map[string]any{
		"operation_id":      "op-unknown-field",
		"request_digest":    request.RequestDigest,
		"source_generation": "gen-1",
		"unexpected":        true,
	}
	if response := exchangeAgentMessage(
		t,
		firecrackerproto.MessageCheckpointAbort,
		unknownField,
	); response.OK || !strings.Contains(response.Error, "unknown field") {
		t.Fatalf("unknown-field abort response = %+v", response)
	}
	expectNoHandoff(t, second)

	// Legacy MessageCheckpoint keeps its dispatch semantics: a repeated
	// error outcome does release later readers, which is exactly why a
	// retryable abort must use the identified message.
	legacy := firecrackerproto.CheckpointRequest{Outcome: "error"}
	if response := exchangeAgentMessage(
		t,
		firecrackerproto.MessageCheckpoint,
		legacy,
	); !response.OK {
		t.Fatalf("legacy checkpoint response = %+v", response)
	}
	expectHandoff(t, second, "error\n")
	third := readCheckpointHandoff(t, handoff)
	if response := exchangeAgentMessage(
		t,
		firecrackerproto.MessageCheckpoint,
		legacy,
	); !response.OK {
		t.Fatalf("repeated legacy checkpoint response = %+v", response)
	}
	expectHandoff(t, third, "error\n")
}
