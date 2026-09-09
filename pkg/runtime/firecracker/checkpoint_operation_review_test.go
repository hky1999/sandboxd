package firecracker

import "testing"

func TestReviewMalformedAcknowledgedRetainsEvidence(t *testing.T) {
	for _, phase := range []string{firecrackerCheckpointOperationPhaseAcked, firecrackerCheckpointOperationPhaseAbortAcked} {
		for _, mutation := range []struct {
			name   string
			change func(*firecrackerCheckpointOperationRecord)
		}{
			{"unknown-version", func(r *firecrackerCheckpointOperationRecord) { r.Version = 999 }},
			{"missing-operation", func(r *firecrackerCheckpointOperationRecord) { r.OperationID = "" }},
			{"missing-directory-inode", func(r *firecrackerCheckpointOperationRecord) { r.DirectoryInode = 0 }},
		} {
			t.Run(phase+"/"+mutation.name, func(t *testing.T) {
				r := schemaTestV2Witness(phase)
				mutation.change(&r)
				if validateFirecrackerCheckpointOperationRecord(r) == nil {
					t.Fatal("fixture must be invalid")
				}
				if !r.retainsEvidence() {
					t.Error("invalid acknowledgment releases evidence")
				}
				if refuseCheckpointOperationEvidence("review", firecrackerPersistedState{CheckpointOperation: r}) == nil {
					t.Error("invalid acknowledgment allows new checkpoint")
				}
			})
		}
	}
}
