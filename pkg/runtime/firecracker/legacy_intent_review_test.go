package firecracker

import (
	"errors"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewIntentRejectsLegacyArchiveWithoutPanic(t *testing.T) {
	dir := t.TempDir()
	dev, ino, err := reserveFirecrackerCheckpointDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	record := schemaTestV2Witness(firecrackerCheckpointOperationPhaseIntent)
	record.Directory = dir
	record.DirectoryDev = dev
	record.DirectoryInode = ino
	if err = os.WriteFile(filepath.Join(dir, checkpointImageName), []byte("legacy archive placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("foreign archive causes panic instead of refusal: %v", p)
		}
	}()
	if _, err = verifyCheckpointOperationIntentSeal("review", record); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("foreign archive refusal = %v", err)
	}
}
