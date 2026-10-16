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

package runsc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateLinksAndRoutesArgsImplementsFilePayloader(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	args := &createLinksAndRoutesArgs{
		payload: filePayload{Files: []*os.File{f}},
	}
	fp, ok := any(args).(filePayloader)
	if !ok {
		t.Fatalf("createLinksAndRoutesArgs does not implement filePayloader")
	}
	if got := len(fp.filePayload()); got != 1 {
		t.Fatalf("file payload length = %d, want 1", got)
	}
}

func TestMarkStateRunningPreservesStateFields(t *testing.T) {
	root := t.TempDir()
	id := "sandbox-1"
	client := NewClient("/usr/local/bin/runsc", root)
	statePath := filepath.Join(root, id+"_sandbox:"+id+".state")
	if err := os.WriteFile(statePath, []byte(`{"id":"sandbox-1","status":"created","sandbox":{"controlSocketPath":"/tmp/runsc.sock"},"extra":{"answer":42}}`), 0640); err != nil {
		t.Fatal(err)
	}

	if err := client.markStateRunning(id); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if got := state["status"]; got != "running" {
		t.Fatalf("status = %v, want running", got)
	}
	extra, ok := state["extra"].(map[string]any)
	if !ok {
		t.Fatalf("extra field was not preserved: %#v", state["extra"])
	}
	if got := extra["answer"]; got != float64(42) {
		t.Fatalf("extra.answer = %v, want 42", got)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0640 {
		t.Fatalf("mode = %o, want 0640", got)
	}
}

type blockedTimeoutRPC struct{ done chan struct{} }

func (b *blockedTimeoutRPC) Call(string, any, any) error { <-b.done; return nil }
func (b *blockedTimeoutRPC) Close() error                { close(b.done); return nil }

func TestInternalStartRPCTimeoutPreservesDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rpc := &blockedTimeoutRPC{done: make(chan struct{})}
	err := callContextWithTimeout(ctx, rpc, contMgrRootContainerStart, nil, nil, time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("internal timeout = %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("parent deadline expired: %v", ctx.Err())
	}
}
