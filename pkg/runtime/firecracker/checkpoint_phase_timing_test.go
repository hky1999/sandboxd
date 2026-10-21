// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0.
package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func capturePhase64Logs(t *testing.T) *bytes.Buffer {
	t.Helper()
	logger := logrus.StandardLogger()
	oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})
	return &output
}

func phase64Files(t *testing.T) firecrackerCheckpointFiles {
	t.Helper()
	dir := t.TempDir()
	files := firecrackerCheckpointFiles{
		State:   filepath.Join(dir, firecrackerCheckpointStateName),
		Memory:  filepath.Join(dir, firecrackerCheckpointMemoryName),
		Overlay: filepath.Join(dir, firecrackerCheckpointOverlayName),
	}
	for _, component := range firecrackerCheckpointComponents(files) {
		if err := os.WriteFile(component.path, []byte("unit-only-component"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func phase64Rows(t *testing.T, output *bytes.Buffer, phase string) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row["timing_phase"] != phase {
			continue
		}
		for _, field := range []string{"checkpoint_dir", "component", "component_path", "success"} {
			if _, ok := row[field]; !ok {
				t.Fatalf("missing %s: %#v", field, row)
			}
		}
		elapsed, ok := row["elapsed_ns"].(float64)
		if !ok || elapsed < 0 {
			t.Fatalf("invalid elapsed_ns: %#v", row)
		}
		rows = append(rows, row)
	}
	return rows
}

func TestPhase64SealTimingFields(t *testing.T) {
	output := capturePhase64Logs(t)
	files := phase64Files(t)
	manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
		t.Fatal(err)
	}
	digests := phase64Rows(t, output, "seal_component_digest")
	if len(digests) != len(firecrackerCheckpointComponents(files)) {
		t.Fatalf("component logs: %#v", digests)
	}
	for _, row := range digests {
		if row["success"] != true || row["checkpoint_dir"] != filepath.Dir(files.State) {
			t.Fatalf("bad attribution: %#v", row)
		}
	}
	writes := phase64Rows(t, output, "seal_manifest_write")
	if len(writes) != 1 || writes[0]["success"] != true {
		t.Fatalf("manifest log: %#v", writes)
	}
}

func TestPhase64ManifestExclusiveErrorUnchanged(t *testing.T) {
	output := capturePhase64Logs(t)
	files := phase64Files(t)
	path := filepath.Join(filepath.Dir(files.State), firecrackerCheckpointManifestName)
	if err := os.WriteFile(path, []byte("existing-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	err := finalizeFirecrackerCheckpointV2(context.Background(), files, &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull})
	if !errors.Is(err, os.ErrExist) || !strings.HasPrefix(err.Error(), "create Firecracker checkpoint manifest:") {
		t.Fatalf("exclusive error changed: %v", err)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil || string(body) != "existing-marker" {
		t.Fatalf("marker changed: %q %v", body, readErr)
	}
	rows := phase64Rows(t, output, "seal_manifest_write")
	if len(rows) != 1 || rows[0]["success"] != false {
		t.Fatalf("failed write log: %#v", rows)
	}
}

func TestPhase64VerifyCacheAndMismatchUnchanged(t *testing.T) {
	output := capturePhase64Logs(t)
	files := phase64Files(t)
	manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
		t.Fatal(err)
	}
	artifact := &firecrackerCheckpointArtifact{Layout: firecrackerCheckpointLayoutV2Directory, Files: files, Manifest: manifest}
	cache := &checkpointDigestCache{}
	if err := cache.verifyFirecrackerCheckpointDigests(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	firstHashes := cache.hashes
	if err := cache.verifyFirecrackerCheckpointDigests(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if cache.hashes != firstHashes {
		t.Fatal("cache hit changed hash behavior")
	}
	rows := phase64Rows(t, output, "verify_component_digest")
	count := len(firecrackerCheckpointComponents(files))
	if len(rows) != 2*count {
		t.Fatalf("verify logs: %#v", rows)
	}
	for i, row := range rows {
		if row["cache_hit"] != (i >= count) || row["success"] != true {
			t.Fatalf("cache attribution: %#v", row)
		}
		ns, ok := row["hash_elapsed_ns"].(float64)
		if !ok || ns < 0 || (i >= count && ns != 0) {
			t.Fatalf("hash duration: %#v", row)
		}
	}
	manifest.Digests[firecrackerCheckpointMemoryName] = "wrong"
	err := cache.verifyFirecrackerCheckpointDigests(context.Background(), artifact)
	if err == nil || !strings.HasPrefix(err.Error(), "Firecracker checkpoint component "+firecrackerCheckpointMemoryName+" digest mismatch:") {
		t.Fatalf("mismatch error changed: %v", err)
	}
	rows = phase64Rows(t, output, "verify_component_digest")
	if rows[len(rows)-1]["success"] != false {
		t.Fatalf("mismatch log: %#v", rows)
	}
}

func TestPhase64InstantiateVerifyFailureStopsBeforeClone(t *testing.T) {
	output := capturePhase64Logs(t)
	files := phase64Files(t)
	manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Digests[firecrackerCheckpointMemoryName] = "wrong"
	artifact := &firecrackerCheckpointArtifact{Layout: firecrackerCheckpointLayoutV2Directory, Files: files, Manifest: manifest}
	stateDir := t.TempDir()
	overlayPath := filepath.Join(stateDir, "uncreated-live-overlay.ext4")
	checkpointDir := filepath.Dir(files.State)
	_, _, err := instantiateFirecrackerCheckpoint(context.Background(), artifact, &checkpointDigestCache{}, checkpointDir, stateDir, overlayPath)
	want := "verify Firecracker checkpoint " + checkpointDir + ": Firecracker checkpoint component " + firecrackerCheckpointMemoryName + " digest mismatch:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("verify error changed: %v", err)
	}
	if _, err := os.Lstat(overlayPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("overlay was created or unexpected stat error: %v", err)
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row["timing_phase"] == "instantiate_overlay_clone_call" {
			t.Fatal("clone stage ran after failed verification")
		}
		if row["timing_phase"] == "instantiate_verify" {
			found = true
			if row["success"] != false || row["checkpoint_dir"] != checkpointDir || row["state_dir"] != stateDir {
				t.Fatalf("failed verify attribution: %#v", row)
			}
			if elapsed, ok := row["elapsed_ns"].(float64); !ok || elapsed < 0 {
				t.Fatalf("failed verify duration: %#v", row)
			}
		}
	}
	if !found {
		t.Fatal("missing failed instantiate_verify record")
	}
}
