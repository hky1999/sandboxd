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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func TestA1RunscCapabilitiesDoNotInventFailedStartProof(t *testing.T) {
	client := NewClient("/not-executed", t.TempDir())
	handler := &Handler{runsc: client}
	if !handler.SupportsCheckpointRootVerification() {
		t.Fatal("actual client root verifier unavailable")
	}
	legacy := &Handler{runsc: successfulRunscClient{}}
	if legacy.SupportsCheckpointRootVerification() {
		t.Fatal("legacy injected client can ignore expected root")
	}
	if _, ok := any(handler).(runtimecore.StartFailureCleanupProver); ok {
		t.Fatal("failed-start cleanup proof was advertised")
	}
}

func TestA1RunscHandlerRejectsRootBeforeCreate(t *testing.T) {
	dir, _ := a1RunscCheckpoint(t, false)
	handler := &Handler{runsc: NewClient("/not-executed", t.TempDir())}
	err := handler.Restore(context.Background(), runtimecore.StartConfig{ID: "target", CheckpointDir: dir, ExpectedCheckpointRoot: strings.Repeat("0", 64)})
	if err == nil || !strings.Contains(err.Error(), "expected root") {
		t.Fatalf("restore failed at wrong boundary: %v", err)
	}
}

func TestA1RunscHandlerRefusesClientRootBypass(t *testing.T) {
	dir, root := a1RunscCheckpoint(t, false)
	handler := &Handler{runsc: successfulRunscClient{}}
	err := handler.Restore(context.Background(), runtimecore.StartConfig{ID: "target", CheckpointDir: dir, ExpectedCheckpointRoot: root})
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("unverifying client accepted: %v", err)
	}
}

type a1RunscCapturingClient struct {
	successfulRunscClient
	restored          StartArgs
	deletedID         string
	deletedGeneration string
	deleteErr         error
}

func (*a1RunscCapturingClient) SupportsCheckpointRootVerification() bool { return true }
func (c *a1RunscCapturingClient) Restore(_ context.Context, args StartArgs, _ string) error {
	c.restored = args
	return nil
}
func (c *a1RunscCapturingClient) DeleteIfGeneration(_ context.Context, id, generation string) error {
	c.deletedID = id
	c.deletedGeneration = generation
	return c.deleteErr
}

func TestA1RunscHandlerPropagatesPinnedRoot(t *testing.T) {
	dir, root := a1RunscCheckpoint(t, true)
	bundleRoot := t.TempDir()
	bundle := filepath.Join(bundleRoot, "target")
	if err := os.Mkdir(bundle, 0755); err != nil {
		t.Fatal(err)
	}
	client := &a1RunscCapturingClient{}
	handler := &Handler{
		runsc:        client,
		ociLoader:    staticOciLoader{bundlePath: bundle, spec: &runtimecore.Spec{Root: &runtimecore.Root{Path: t.TempDir()}}},
		filestoreDir: t.TempDir(),
		sandboxRoot:  bundleRoot,
	}
	err := handler.Restore(context.Background(), runtimecore.StartConfig{
		ID: "target", CheckpointDir: dir, ExpectedCheckpointRoot: root, Network: &networkmanager.NetResource{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.restored.ExpectedCheckpointRoot != root {
		t.Fatal("expected root not forwarded to consumption boundary")
	}
}

func TestA1RunscStrictHandlerNoLegacyFallback(t *testing.T) {
	handler := &Handler{runsc: successfulRunscClient{}, sandboxRoot: t.TempDir()}
	if err := handler.DeleteStrict(context.Background(), "target", "generation"); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("legacy client accepted as strict proof: %v", err)
	}
}

func TestA1RunscStrictHandlerPropagatesIdentityAndError(t *testing.T) {
	failure := errors.New("reader exit unproven")
	client := &a1RunscCapturingClient{deleteErr: failure}
	handler := &Handler{runsc: client, sandboxRoot: t.TempDir()}
	if err := handler.DeleteStrict(context.Background(), "target", "generation"); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if client.deletedID != "target" || client.deletedGeneration != "generation" {
		t.Fatal("strict identity lost")
	}
	if err := handler.DeleteStrict(context.Background(), "target", ""); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatal(err)
	}
}

func a1RunscCommand(t *testing.T, script string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "runsc")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"+script), 0755); err != nil {
		t.Fatal(err)
	}
	return binary, dir
}

func TestA1RunscStrictClientArguments(t *testing.T) {
	binary, dir := a1RunscCommand(t, "printf '%s\\n' \"$@\" > \"$RUNSC_A1_ARGS\"\n")
	argsFile := filepath.Join(dir, "args")
	t.Setenv("RUNSC_A1_ARGS", argsFile)
	if err := NewClient(binary, dir).DeleteIfGeneration(context.Background(), "target", "generation"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "delete\n--force\n--expected-generation=generation\n--\ntarget\n") {
		t.Fatalf("arguments=%q", raw)
	}
}

func TestA1RunscStrictClientMissingAndOldCLIStayFailures(t *testing.T) {
	for _, output := range []string{"container not found", "flag provided but not defined: expected-generation"} {
		t.Run(output, func(t *testing.T) {
			binary, dir := a1RunscCommand(t, "echo called >> \"$RUNSC_A1_CALLS\"\nprintf '%s\\n' \"$RUNSC_A1_ERROR\" >&2\nexit 2\n")
			calls := filepath.Join(dir, "calls")
			t.Setenv("RUNSC_A1_CALLS", calls)
			t.Setenv("RUNSC_A1_ERROR", output)
			if err := NewClient(binary, dir).DeleteIfGeneration(context.Background(), "target", "generation"); err == nil {
				t.Fatal("strict failure swallowed")
			}
			raw, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(raw), "called") != 1 {
				t.Fatalf("legacy fallback or retry occurred: %q", raw)
			}
		})
	}
}

func TestA1RunscStrictClientCancellation(t *testing.T) {
	binary, dir := a1RunscCommand(t, "exec sleep 30\n")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := NewClient(binary, dir).DeleteIfGeneration(ctx, "target", "generation"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
