package firecracker

import "testing"

func TestIncrementalMemoryAuditSelection(t *testing.T) {
	for _, typ := range []string{"Full", "Diff", "Incremental", "SoftDirty", ""} {
		for _, enabled := range []bool{false, true} {
			for _, stopOnly := range []bool{false, true} {
				for _, leaveRunning := range []bool{false, true} {
					// Allowed tuples specify the contract: continuing deltas
					// require unrestricted audit; stopped deltas permit either mode.
					want := false
					if enabled {
						switch typ {
						case "Incremental", "SoftDirty":
							want = !leaveRunning || !stopOnly
						}
					}
					if got := incrementalMemoryAuditEnabled(enabled, stopOnly, leaveRunning, typ); got != want {
						t.Fatalf("type=%q enabled=%v stopOnly=%v leaveRunning=%v: got %v want %v", typ, enabled, stopOnly, leaveRunning, got, want)
					}
				}
			}
		}
	}
}
