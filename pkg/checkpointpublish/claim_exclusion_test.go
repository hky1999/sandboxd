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

package checkpointpublish

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// TestPublishAndMaterializeExcludeSourceDirectoryClaim pins the transport
// boundary of the Firecracker directory claim: a claim tombstone sitting
// beside the sealed artifact changes nothing about publication — the same
// chunks and the same artifact INDEX are published — and a materialized
// target never carries one. The claim is source-directory ownership
// metadata, not content, so the store and the INDEX stay claim-free.
func TestPublishAndMaterializeExcludeSourceDirectoryClaim(t *testing.T) {
	source := fixtureCheckpoint(t)
	writeFullArtifact(t, source)
	claimContent := []byte(`{"version":1,"sandbox_id":"sandbox-publish","operation_id":"op-publish",` +
		`"request_digest":"` + strings.Repeat("ab", 32) + `","source_generation":"gen-publish",` +
		`"directory":` + quoteJSONString(source) + `,"directory_dev":1,"directory_inode":2}`)
	claimPath := filepath.Join(source, checkpointroot.ClaimFileName)
	if err := os.WriteFile(claimPath, claimContent, 0600); err != nil {
		t.Fatal(err)
	}

	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := filepath.Base(source)
	result, err := Run(context.Background(), source, id, store, "test-local")
	if err != nil {
		t.Fatalf("publish with a claim tombstone present: %v", err)
	}
	if result.State.State != StatePublished {
		t.Fatalf("result = %+v", result)
	}
	// Publication never touched the source tombstone.
	after, err := os.ReadFile(claimPath)
	if err != nil || string(after) != string(claimContent) {
		t.Fatalf("publication modified the source claim: %v", err)
	}

	// A materialized target is built purely from the INDEX: it carries the
	// artifact set and never the claim.
	target := filepath.Join(t.TempDir(), "restored")
	if err := Materialize(context.Background(), target, id, store); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = true
	}
	if names[checkpointroot.ClaimFileName] {
		t.Fatalf("materialized target carries the source claim: %v", names)
	}
	for _, name := range []string{"manifest.json", "chunks.json", "vmstate", "overlay.ext4", "memory", MaterializedMarker} {
		if !names[name] {
			t.Fatalf("materialized target is missing %s: %v", name, names)
		}
	}
}

func quoteJSONString(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
}
