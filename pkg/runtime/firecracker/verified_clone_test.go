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

package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

func verifiedCloneFixture(t *testing.T) (string, []byte, *checkpointchunks.BackingProof) {
	t.Helper()
	dir := t.TempDir()
	data := make([]byte, 4*4096)
	data[4099] = 0xA7
	f, err := os.Create(filepath.Join(dir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte{0xA7}, 4099); err != nil {
		t.Fatal(err)
	}
	f.Close()
	m, err := checkpointchunks.Compute(context.Background(), dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	p, err := checkpointchunks.VerifyMemoryBacking(context.Background(), dir, m.FileDigest, m.FileDigestMode)
	if err != nil {
		t.Fatal(err)
	}
	return dir, data, p
}
func TestVerifiedCloneFallback(t *testing.T) {
	original := cloneFileIoctl
	t.Cleanup(func() { cloneFileIoctl = original })
	cloneFileIoctl = func(_, src *os.File) error {
		_, err := src.Seek(7, 0)
		if err != nil {
			return err
		}
		return syscall.EOPNOTSUPP
	}
	_, data, p := verifiedCloneFixture(t)
	dst := filepath.Join(t.TempDir(), "copy")
	reflinked, err := cloneVerifiedBackingNoSync(context.Background(), p, dst)
	if err != nil || reflinked {
		t.Fatalf("clone: %v %v", reflinked, err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("fallback did not copy whole file: %v", err)
	}
}
func TestVerifiedCloneRejectsMutationAndPreservesExisting(t *testing.T) {
	for _, kind := range []string{"replace", "modify", "io-error", "existing"} {
		t.Run(kind, func(t *testing.T) {
			dir, data, p := verifiedCloneFixture(t)
			dst := filepath.Join(t.TempDir(), "copy")
			original := cloneFileIoctl
			t.Cleanup(func() { cloneFileIoctl = original })
			cloneFileIoctl = func(_, src *os.File) error {
				switch kind {
				case "replace":
					q := filepath.Join(dir, "new")
					if err := os.WriteFile(q, data, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(q, filepath.Join(dir, "memory")); err != nil {
						t.Fatal(err)
					}
				case "modify":
					f, err := os.OpenFile(filepath.Join(dir, "memory"), os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, err = f.WriteAt([]byte{9}, 0)
					f.Close()
					if err != nil {
						t.Fatal(err)
					}
				case "io-error":
					return syscall.EIO
				case "existing":
					t.Fatal("should not clone into existing destination")
				}
				return syscall.EOPNOTSUPP
			}
			if kind == "existing" {
				if err := os.WriteFile(dst, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := cloneVerifiedBackingNoSync(context.Background(), p, dst); err == nil {
				t.Fatal("expected clone rejection")
			}
			if kind == "existing" {
				b, err := os.ReadFile(dst)
				if err != nil || string(b) != "keep" {
					t.Fatal("existing target changed")
				}
			} else if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Fatalf("partial target remains: %v", err)
			}
		})
	}
}

// Run explicitly with CN_PROOF_ARTIFACT_DIR and TMPDIR on the same private
// reflink filesystem. Normal unit-test runs do not execute this benchmark.
func BenchmarkVerifiedCloneRealArtifact(b *testing.B) {
	dir := os.Getenv("CN_PROOF_ARTIFACT_DIR")
	if dir == "" {
		b.Skip("requires a prepared real artifact")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		b.Fatal(err)
	}
	var manifest firecrackerCheckpointManifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		b.Fatal(err)
	}
	chunks, err := os.ReadFile(filepath.Join(dir, checkpointchunks.ManifestName))
	if err != nil {
		b.Fatal(err)
	}
	var proofTime, cloneTime, verifyTime time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstDir := b.TempDir()
		ctx := context.Background()
		start := time.Now()
		proof, err := checkpointchunks.VerifyMemoryBacking(ctx, dir, manifest.Digests["memory"], manifest.MemoryDigestMode)
		if err != nil {
			b.Fatal(err)
		}
		proved := time.Now()
		reflinked, err := cloneVerifiedBackingNoSync(ctx, proof, filepath.Join(dstDir, "memory"))
		if err != nil {
			b.Fatal(err)
		}
		cloned := time.Now()
		if !reflinked {
			b.Fatal("real artifact benchmark requires FICLONE")
		}
		b.StopTimer()
		if err = os.WriteFile(filepath.Join(dstDir, checkpointchunks.ManifestName), chunks, 0600); err != nil {
			b.Fatal(err)
		}
		_, err = checkpointchunks.VerifyMemoryBacking(ctx, dstDir, manifest.Digests["memory"], manifest.MemoryDigestMode)
		if err != nil {
			b.Fatal(err)
		}
		proofTime += proved.Sub(start)
		cloneTime += cloned.Sub(proved)
		verifyTime += time.Since(cloned)
		b.StartTimer()
	}
	b.ReportMetric(float64(proofTime.Microseconds())/float64(b.N)/1000, "proof-ms/op")
	b.ReportMetric(float64(cloneTime.Microseconds())/float64(b.N)/1000, "clone-with-checks-ms/op")
	b.ReportMetric(float64(verifyTime.Microseconds())/float64(b.N)/1000, "destination-verify-ms/op")
}
