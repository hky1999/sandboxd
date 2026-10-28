package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func revisionBoundSource(t *testing.T, revision uint64) SourceIdentity {
	t.Helper()
	source := SourceIdentity{CheckpointID: "revision-bound", SourceID: "source", SourceGeneration: "generation", Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64)}
	data, err := json.Marshal(map[string]uint64{"SourceResourceRevision": revision})
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	return source
}

func TestCheckpointArtifactRetainsOriginalResourceRevision(t *testing.T) {
	source := revisionBoundSource(t, 7)
	directory := filepath.Join(t.TempDir(), "artifact")
	fact, err := PublishAt(directory, source, func(image string) error { return os.WriteFile(image, []byte("saved original memory"), 0600) })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fact.Paths.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["sourceResourceRevision"] != float64(7) {
		t.Fatalf("original resource revision missing from committed manifest: %v", manifest["sourceResourceRevision"])
	}
	if _, err = InspectAt(directory, source.CheckpointID); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointReplayCannotAdoptAnotherResourceRevision(t *testing.T) {
	source := revisionBoundSource(t, 7)
	directory := filepath.Join(t.TempDir(), "artifact")
	fact, err := PublishAt(directory, source, func(image string) error { return os.WriteFile(image, []byte("saved original memory"), 0600) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = MatchSource(fact, revisionBoundSource(t, 8)); err == nil {
		t.Fatal("same checkpoint was adopted under a different resource revision")
	}
}
