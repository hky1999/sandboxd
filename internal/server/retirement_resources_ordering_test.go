package server

import (
	"context"
	"encoding/json"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type originalRetirementArchiveHandler struct {
	*svc.FakeRuntimeHandler
	root     string
	observed bool
}

func (h *originalRetirementArchiveHandler) Delete(context.Context, string) error {
	entries, _ := os.ReadDir(filepath.Join(h.root, "scheduler-resource-retirements"))
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.root, "scheduler-resource-retirements", entry.Name()))
		if err != nil {
			continue
		}
		var record map[string]any
		if json.Unmarshal(data, &record) != nil {
			continue
		}
		confirmed, ok := record["physical_deletion_confirmed"].(bool)
		if record["sandbox_id"] == "predelete-evidence" && record["resource_generation"] == "generation-one" && record["phase"] == "before_runtime_delete" && ok && !confirmed {
			h.observed = true
		}
	}
	return nil
}
func TestOriginalResourceArchiveMustPrecedeRuntimeDelete(t *testing.T) {
	h := &originalRetirementArchiveHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": h})
	h.root = s.config.RootDir
	storeSandboxForDelete(t, s, "predelete-evidence")
	require.NoError(t, s.sandboxManager.UpdateLabels("predelete-evidence", map[string]string{resourceGenerationLabel: "generation-one"}))
	stageFilesystemOwner(t, s, "predelete-evidence", "generation-one")
	stageEmptyDeviceOwner(t, s, "predelete-evidence", "generation-one")
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: "predelete-evidence", ExpectedGeneration: "generation-one"})
	require.NoError(t, err)
	require.True(t, h.observed, "runtime handler ran without a durable matching pre-delete resource record")
}

func TestRetirementRejectsSameGenerationMetadataMutation(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "retire-same-generation-change"
	var mutationErr error
	cgroups := &retirementCgroups{}
	cgroups.onStats = func() {
		current, err := s.sandboxManager.Get(id)
		if err != nil {
			mutationErr = err
			return
		}
		current.Metadata.RuntimeHandler = "kata"
	}
	s.cgroupMgr = cgroups
	storeRetirementSandbox(t, s, id, "unchanged-generation", nil)
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "unchanged-generation",
	})
	require.NoError(t, mutationErr)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.calls)
	require.Empty(t, readRetirementEvidence(t, s, id, "unchanged-generation"))
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, "unchanged-generation", current.Metadata.Labels[resourceGenerationLabel])
	require.Equal(t, "kata", current.Metadata.RuntimeHandler)
}
