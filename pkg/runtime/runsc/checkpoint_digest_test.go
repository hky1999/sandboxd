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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRunscArtifact(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSealAndVerifyRunscCheckpoint(t *testing.T) {
	dir := t.TempDir()
	writeRunscArtifact(t, dir, "checkpoint.img", "state")
	writeRunscArtifact(t, dir, "pages_meta.img", "meta")
	writeRunscArtifact(t, dir, "pages.img", "pages")
	// Non-artifact files are not digested.
	writeRunscArtifact(t, dir, "notes.txt", "ignore me")

	if err := sealRunscCheckpoint(context.Background(), dir); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := verifyRunscCheckpoint(context.Background(), dir); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tampering any recorded artifact fails verification.
	if err := os.WriteFile(filepath.Join(dir, "pages.img"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifyRunscCheckpoint(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "pages.img") {
		t.Fatalf("tampered verify = %v", err)
	}

	// A directory without a manifest restores unverified.
	plain := t.TempDir()
	writeRunscArtifact(t, plain, "checkpoint.img", "x")
	if err := verifyRunscCheckpoint(context.Background(), plain); err != nil {
		t.Fatalf("unsealed verify = %v", err)
	}

	// Sealing a directory with no artifacts is an error, not an empty seal.
	empty := t.TempDir()
	if err := sealRunscCheckpoint(context.Background(), empty); err == nil {
		t.Fatal("empty seal succeeded")
	}
}
