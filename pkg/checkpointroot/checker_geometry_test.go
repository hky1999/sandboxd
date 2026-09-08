package checkpointroot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckerGeometryChangesIdentity(t *testing.T) {
	d := t.TempDir()
	data := []byte("0123456789")
	os.WriteFile(filepath.Join(d, "memory"), data, 0600)
	hash := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	manifest, _ := json.Marshal(map[string]any{"version": 2, "snapshot_type": "Full", "digests": map[string]string{"memory": hash(data)}})
	os.WriteFile(filepath.Join(d, "manifest.json"), manifest, 0600)
	entries := []checkpointchunks.Chunk{{Offset: 0, Digest: hash(data[:6])}, {Offset: 6, Digest: hash(data[6:])}}
	side := checkpointchunks.Manifest{Version: 1, File: "memory", FileSize: 10, FileDigest: checkpointchunks.RootDigest(entries), FileDigestMode: "chunks", ChunkBytes: 6, ChunkCount: 2, Entries: entries}
	write := func() {
		raw, _ := json.Marshal(side)
		if err := os.WriteFile(filepath.Join(d, "chunks.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	a, err := Bind(d)
	if err != nil {
		t.Fatal(err)
	}
	side.ChunkBytes = 7
	side.Entries[1].Offset = 7
	write()
	b, err := Bind(d)
	if err != nil {
		t.Logf("mutated geometry refused: %v", err)
		return
	}
	if a.RootDigest == b.RootDigest {
		t.Fatalf("different read geometry accepted with identical expected root %s", a.RootDigest)
	}
}
