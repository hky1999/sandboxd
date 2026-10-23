// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package checkpoint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func deletionFixture(t *testing.T) (string, string, DeleteIdentity) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "published")
	fact, err := PublishAt(dir, SourceIdentity{CheckpointID: "checkpoint", SourceID: "source", SourceGeneration: "original-generation", Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64)}, func(image string) error {
		return os.WriteFile(image, []byte("original live pages"), 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := DeleteIdentity{SourceGeneration: fact.Manifest.SourceGeneration, CheckpointID: fact.Manifest.CheckpointID, SourceID: fact.Manifest.SourceID, ImageSize: fact.Manifest.ImageSize, ImageSHA256: fact.Manifest.ImageSHA256}
	trash := filepath.Join(filepath.Dir(dir), "."+filepath.Base(dir)+".deleting-"+expected.ImageSHA256)
	if err := os.Rename(dir, trash); err != nil {
		t.Fatal(err)
	}
	return dir, trash, expected
}

func saveDeletionReceipt(t *testing.T, trash string, expected DeleteIdentity) string {
	t.Helper()
	device, inode, err := directoryIdentity(trash)
	if err != nil {
		t.Fatal(err)
	}
	path := deleteIntentPath(trash, expected)
	if err := persistDeleteIntent(path, deleteIntent{Version: 1, Expected: expected, Device: device, Inode: inode}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDeleteAtResumesAfterManifestUnlinked(t *testing.T) {
	dir, trash, expected := deletionFixture(t)
	receipt := saveDeletionReceipt(t, trash, expected)
	if err := os.Remove(filepath.Join(trash, ManifestName)); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAt(dir, expected); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAt(dir, expected); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, trash, receipt} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("owned cleanup path remains %s: %v", path, err)
		}
	}
}

func TestDeleteAtFinishesReceiptAfterTreeAlreadyGone(t *testing.T) {
	dir, trash, expected := deletionFixture(t)
	receipt := saveDeletionReceipt(t, trash, expected)
	if err := os.RemoveAll(trash); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAt(dir, expected); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(receipt); !os.IsNotExist(err) {
		t.Fatalf("receipt remains: %v", err)
	}
}

func TestDeleteAtRetainsUnprovenPartialArtifact(t *testing.T) {
	dir, trash, expected := deletionFixture(t)
	if err := os.Remove(filepath.Join(trash, ManifestName)); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAt(dir, expected); err == nil {
		t.Fatal("partial tree without durable receipt was deleted")
	}
	if _, err := os.Stat(filepath.Join(trash, ImageName)); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAtReceiptCannotOwnReplacementOrDifferentGeneration(t *testing.T) {
	for _, mode := range []string{"replacement", "generation", "corrupt-receipt"} {
		t.Run(mode, func(t *testing.T) {
			dir, trash, expected := deletionFixture(t)
			receipt := saveDeletionReceipt(t, trash, expected)
			if mode == "replacement" {
				// Keep the original inode alive so a new directory cannot reuse it.
				if err := os.Rename(trash, trash+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(trash, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(trash, "foreign"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if mode == "generation" {
				if err := os.Remove(filepath.Join(trash, ManifestName)); err != nil {
					t.Fatal(err)
				}
				expected.SourceGeneration = "different-generation"
			} else {
				if err := os.WriteFile(receipt, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := DeleteAt(dir, expected); err == nil {
				t.Fatal("unproven receipt authorized deletion")
			}
			if _, err := os.Stat(trash); err != nil {
				t.Fatal(err)
			}
		})
	}
}
