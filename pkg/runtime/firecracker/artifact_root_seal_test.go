// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
package firecracker

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func TestFinalizedFirecrackerCheckpointBindsMemoryAndWritableLayer(t *testing.T) {
	for _, virtioFS := range []bool{false, true} {
		t.Run(fmt.Sprintf("virtiofs-%v", virtioFS), func(t *testing.T) {
			directory := t.TempDir()
			files, err := prepareFirecrackerCheckpointV2(directory, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if virtioFS {
				files.VirtioFSState = filepath.Join(directory, firecrackerCheckpointVirtioFSName)
			}
			contents := make(map[string][]byte)
			for _, component := range firecrackerCheckpointComponents(files) {
				contents[component.name] = []byte("immutable fixture " + component.name)
				if err := os.WriteFile(component.path, contents[component.name], 0600); err != nil {
					t.Fatal(err)
				}
			}
			manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull, VirtioFS: virtioFS}
			if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
				t.Fatal(err)
			}
			for _, component := range firecrackerCheckpointComponents(files) {
				expected := fmt.Sprintf("%x", sha256.Sum256(contents[component.name]))
				if manifest.Digests[component.name] != expected {
					t.Fatalf("%s has no exact sealed content digest", component.name)
				}
			}
			binding, err := checkpointroot.Bind(directory)
			if err != nil {
				t.Fatalf("producer output must be admissible without inventing a root: %v", err)
			}
			artifact, err := openFirecrackerCheckpoint(directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyFirecrackerExpectedRoot(runtimecore.StartConfig{
				CheckpointDir: directory, ExpectedCheckpointRoot: binding.RootDigest,
			}, artifact); err != nil {
				t.Fatal(err)
			}
			if err := new(checkpointDigestCache).verifyFirecrackerCheckpointDigests(context.Background(), artifact); err != nil {
				t.Fatal(err)
			}
			for _, component := range firecrackerCheckpointComponents(files) {
				if component.name != firecrackerCheckpointMemoryName && component.name != firecrackerCheckpointOverlayName {
					continue
				}
				corrupt := append([]byte(nil), contents[component.name]...)
				corrupt[0] ^= 1
				if err := os.WriteFile(component.path, corrupt, 0600); err != nil {
					t.Fatal(err)
				}
				if err := new(checkpointDigestCache).verifyFirecrackerCheckpointDigests(context.Background(), artifact); err == nil {
					t.Fatalf("consumer accepted changed %s bytes of the sealed checkpoint", component.name)
				}
				if err := os.WriteFile(component.path, contents[component.name], 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFirecrackerCheckpointSealNeverPublishesMissingLargeComponent(t *testing.T) {
	for _, missing := range []string{firecrackerCheckpointMemoryName, firecrackerCheckpointOverlayName} {
		t.Run(missing, func(t *testing.T) {
			directory := t.TempDir()
			files, err := prepareFirecrackerCheckpointV2(directory, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, component := range firecrackerCheckpointComponents(files) {
				if component.name == missing {
					continue
				}
				if err := os.WriteFile(component.path, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// A known memory size must not hide a missing memory payload.
			manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull, MemorySize: 7}
			if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err == nil {
				t.Fatal("incomplete large-component proof must fail sealing")
			}
			if _, err := os.Lstat(filepath.Join(directory, firecrackerCheckpointManifestName)); !os.IsNotExist(err) {
				t.Fatalf("failed proof published a manifest: %v", err)
			}
		})
	}
}
