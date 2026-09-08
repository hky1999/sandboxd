package checkpointpublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
	"os"
	"path/filepath"
	"testing"
)

func TestPackedMaterializePreservesOperationRoot(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		t.Run("identity="+identity, func(t *testing.T) {
			ctx := context.Background()
			source := packSource(t, packData(4, 4096), 4096)
			m, err := checkpointchunks.Load(source)
			if err != nil {
				t.Fatal(err)
			}
			state, err := os.ReadFile(filepath.Join(source, "vmstate"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(state)
			raw, _ := json.Marshal(map[string]any{"version": 2, "snapshot_type": "Full", "memory_size": m.FileSize, "memory_digest_mode": "chunks", "digests": map[string]string{"memory": m.FileDigest, "vmstate": hex.EncodeToString(sum[:])}})
			if err := os.WriteFile(filepath.Join(source, "manifest.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := writeOverlaySidecar(t, source); err != nil {
				t.Fatal(err)
			}
			before, err := checkpointroot.Bind(source)
			if err != nil {
				t.Fatalf("source root: %v", err)
			}
			store, err := chunkstore.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			result, err := RunWithOptions(ctx, source, "root-pack", store, "local", Options{Workers: 2, PackBytes: 8192, PackIdentity: identity})
			if err != nil {
				t.Fatal(err)
			}
			if result.PacksPut == 0 {
				t.Fatal("test did not publish packs")
			}
			target := filepath.Join(t.TempDir(), "blind")
			if err := Materialize(ctx, target, "root-pack", store); err != nil {
				t.Fatal(err)
			}
			transport, err := checkpointchunks.LoadTransport(target)
			if err != nil {
				t.Fatal(err)
			}
			if transport.Version == 1 || len(transport.Packs) == 0 {
				t.Fatal("target did not retain packed transport")
			}
			after, err := checkpointroot.Bind(target)
			if err != nil {
				t.Fatalf("packed target root v%d: %v", transport.Version, err)
			}
			if before.RootDigest != after.RootDigest {
				t.Fatalf("logical content root changed: %s -> %s", before.RootDigest, after.RootDigest)
			}
		})
	}
}
