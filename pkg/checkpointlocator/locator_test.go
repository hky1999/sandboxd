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

package checkpointlocator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func face(overrides ...func(*RuntimeFace)) RuntimeFace {
	f := RuntimeFace{
		Name: "firecracker",
		CheckpointCompat: CheckpointCompat{
			Arch:        "amd64",
			Firecracker: "fc-digest",
			Kernel:      "kernel-digest",
			Initrd:      "initrd-digest",
			KernelArgs:  "console=ttyS0",
		},
	}
	for _, o := range overrides {
		o(&f)
	}
	return f
}

func TestEvaluateMirrorsRestoreSemantics(t *testing.T) {
	tuple := &CheckpointCompat{
		Arch:        "amd64",
		Firecracker: "fc-digest",
		Kernel:      "kernel-digest",
		Initrd:      "initrd-digest",
		KernelArgs:  "console=ttyS0",
	}
	if got := Evaluate(tuple, face()); !got.Compatible {
		t.Fatalf("identical stack incompatible: %+v", got)
	}

	// Every recorded field gates.
	for _, field := range []func(f *RuntimeFace){
		func(f *RuntimeFace) { f.Arch = "arm64" },
		func(f *RuntimeFace) { f.Firecracker = "other-vmm" },
		func(f *RuntimeFace) { f.Kernel = "other-kernel" },
		func(f *RuntimeFace) { f.Initrd = "other-initrd" },
		func(f *RuntimeFace) { f.KernelArgs = "console=ttyS1" },
	} {
		eval := Evaluate(tuple, face(field))
		if eval.Compatible {
			t.Fatalf("mismatched field not rejected: %+v", eval)
		}
		if len(eval.Reasons) == 0 {
			t.Fatal("rejection without reasons")
		}
	}

	// Unrecorded fields never gate: a tuple that only pins the kernel
	// ignores every other difference.
	onlyKernel := &CheckpointCompat{Kernel: "kernel-digest"}
	if got := Evaluate(onlyKernel, face(func(f *RuntimeFace) {
		f.Firecracker, f.Initrd, f.KernelArgs = "other", "other", "other"
	})); !got.Compatible {
		t.Fatalf("unrecorded fields gated: %+v", got)
	}

	// No tuple at all: pre-tuple artifacts verify anywhere.
	if got := Evaluate(nil, face(func(f *RuntimeFace) { f.Kernel = "whatever" })); !got.Compatible {
		t.Fatalf("nil tuple gated: %+v", got)
	}
}

func TestDecidePrefersOrigin(t *testing.T) {
	nodes := []NodeRecord{
		{ID: "node-b", Address: "http://b:18090", Runtimes: []RuntimeFace{face()}},
		{ID: "node-a", Address: "http://a:18090", Runtimes: []RuntimeFace{face()}},
	}
	tuple := &CheckpointCompat{Firecracker: "fc-digest"}

	got, err := Decide(Input{
		CheckpointID: "C1",
		Compat:       tuple,
		OriginNodeID: "node-a",
		Nodes:        nodes,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if got.NodeID != "node-a" || got.CrossNode {
		t.Fatalf("origin not preferred: %+v", got)
	}
}

func TestDecideSkipsIncompatibleOrigin(t *testing.T) {
	// The origin registered but its stack drifted after the checkpoint was
	// made: origin preference must not return a node whose own restore
	// verification would refuse the artifact.
	nodes := []NodeRecord{
		{ID: "origin", Runtimes: []RuntimeFace{face(func(f *RuntimeFace) { f.Kernel = "upgraded" })}},
		{ID: "peer", Runtimes: []RuntimeFace{face()}},
	}
	got, err := Decide(Input{
		CheckpointID: "C1",
		Compat:       &CheckpointCompat{Kernel: "kernel-digest"},
		OriginNodeID: "origin",
		Nodes:        nodes,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if got.NodeID != "peer" || !got.CrossNode {
		t.Fatalf("incompatible origin still preferred: %+v", got)
	}

	// With no compatible peer the request must fail closed rather than
	// return the incompatible origin.
	if _, err := Decide(Input{
		CheckpointID: "C1",
		Compat:       &CheckpointCompat{Kernel: "kernel-digest"},
		OriginNodeID: "origin",
		Nodes:        nodes[:1],
	}); err == nil {
		t.Fatal("incompatible-only origin accepted")
	}
}

func TestDecideCrossNodeFallsBackInStableOrder(t *testing.T) {
	nodes := []NodeRecord{
		{ID: "node-b", Address: "http://b:18090", Runtimes: []RuntimeFace{face()}},
		{ID: "node-c", Address: "http://c:18090", Runtimes: []RuntimeFace{face(func(f *RuntimeFace) { f.Kernel = "other" })}},
	}
	got, err := Decide(Input{
		CheckpointID: "C1",
		Compat:       &CheckpointCompat{Kernel: "kernel-digest"},
		OriginNodeID: "node-a", // not registered
		Nodes:        nodes,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if got.NodeID != "node-b" || !got.CrossNode {
		t.Fatalf("compatible fallback not chosen: %+v", got)
	}
}

func TestDecideFailsClosed(t *testing.T) {
	nodes := []NodeRecord{
		{ID: "node-c", Runtimes: []RuntimeFace{face(func(f *RuntimeFace) { f.Kernel = "other" })}},
	}
	_, err := Decide(Input{
		CheckpointID: "C1",
		Compat:       &CheckpointCompat{Kernel: "kernel-digest"},
		OriginNodeID: "node-a",
		Nodes:        nodes,
	})
	if err == nil {
		t.Fatal("incompatible placement succeeded")
	}
	if !strings.Contains(err.Error(), "cannot restore cross-node") {
		t.Fatalf("error not fail-closed shaped: %v", err)
	}

	// Pin with an unavailable origin must fail even when a compatible
	// candidate exists.
	compatible := []NodeRecord{{ID: "node-b", Runtimes: []RuntimeFace{face()}}}
	if _, err := Decide(Input{
		CheckpointID: "C1",
		Compat:       &CheckpointCompat{},
		OriginNodeID: "node-a",
		PinToOrigin:  true,
		Nodes:        compatible,
	}); err == nil {
		t.Fatal("pinned placement degraded to a peer")
	}
}

func TestFetchAndReadCompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/node" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(NodeRecord{
			ID:       "node-x",
			Runtimes: []RuntimeFace{face()},
		})
	}))
	defer srv.Close()

	record, err := FetchNode(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if record.ID != "node-x" || record.Address != srv.URL {
		t.Fatalf("record = %+v", record)
	}

	live, failed := FetchAll(context.Background(), []string{srv.URL, srv.URL + "/dead"})
	if len(live) != 1 || len(failed) != 1 {
		t.Fatalf("fetchall live=%d failed=%d", len(live), len(failed))
	}

	dir := t.TempDir()
	manifest := map[string]any{
		"version": 2,
		"compat":  map[string]any{"firecracker": "fc-digest"},
	}
	raw, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	compat, err := ReadCheckpointCompat(dir)
	if err != nil {
		t.Fatalf("read compat: %v", err)
	}
	if compat == nil || compat.Firecracker != "fc-digest" {
		t.Fatalf("compat = %+v", compat)
	}

	// A sealed checkpoint without a tuple reads as nil (verify anywhere).
	noTuple := map[string]any{"version": 2}
	raw, _ = json.Marshal(noTuple)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	compat, err = ReadCheckpointCompat(dir)
	if err != nil || compat != nil {
		t.Fatalf("no-tuple read = %+v, %v", compat, err)
	}
}

func TestDecidePublishedGate(t *testing.T) {
	nodes := []NodeRecord{{ID: "peer", Runtimes: []RuntimeFace{face()}}}
	base := Input{
		CheckpointID: "C1",
		Compat:       &CheckpointCompat{},
		OriginNodeID: "gone",
		Nodes:        nodes,
	}

	// Without the gate, cross-node placement proceeds.
	if got, err := Decide(base); err != nil || got.NodeID != "peer" {
		t.Fatalf("ungated = %+v, %v", got, err)
	}

	// Requiring publication locks cross-node until the state machine says
	// published; every non-published state fails closed with the state named.
	for _, state := range []string{"", "publishing", "publish_failed"} {
		in := base
		in.RequirePublished = true
		in.PublishState = state
		if _, err := Decide(in); err == nil ||
			!strings.Contains(err.Error(), "cross-node restore is locked") {
			t.Fatalf("state %q not locked: %v", state, err)
		}
	}

	// Published unlocks it.
	in := base
	in.RequirePublished = true
	in.PublishState = "published"
	if got, err := Decide(in); err != nil || !got.CrossNode {
		t.Fatalf("published not unlocked: %+v, %v", got, err)
	}

	// The origin is exempt: it holds the local artifact, published or not.
	origin := []NodeRecord{{ID: "origin", Runtimes: []RuntimeFace{face()}}}
	in2 := Input{
		CheckpointID:     "C1",
		Compat:           &CheckpointCompat{},
		OriginNodeID:     "origin",
		RequirePublished: true,
		Nodes:            origin,
	}
	if got, err := Decide(in2); err != nil || got.NodeID != "origin" || got.CrossNode {
		t.Fatalf("origin not exempt = %+v, %v", got, err)
	}
}

func TestDecideTemplateHolderAndMatrix(t *testing.T) {
	goodFace := face()
	badFace := face(func(f *RuntimeFace) { f.Kernel = "other" })
	holders := []NodeHolder{
		{Record: NodeRecord{ID: "node-a", Runtimes: []RuntimeFace{badFace}}, Holds: []string{"tpl-1"}},
		{Record: NodeRecord{ID: "node-b", Runtimes: []RuntimeFace{goodFace}}, Holds: []string{"tpl-2"}},
		{Record: NodeRecord{ID: "node-c", Runtimes: []RuntimeFace{goodFace}}, Holds: []string{"tpl-1"}},
	}

	got, err := DecideTemplate(TemplateInput{
		TemplateID: "tpl-1",
		Compat:     &CheckpointCompat{Kernel: "kernel-digest"},
		Nodes:      holders,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	// node-a holds it but is incompatible; node-b is compatible but does not
	// hold it; node-c wins.
	if got.NodeID != "node-c" {
		t.Fatalf("placement = %+v", got)
	}

	_, err = DecideTemplate(TemplateInput{
		TemplateID: "tpl-missing",
		Compat:     &CheckpointCompat{},
		Nodes:      holders,
	})
	if err == nil || !strings.Contains(err.Error(), "no compatible holder") {
		t.Fatalf("missing template not fail-closed: %v", err)
	}
}
