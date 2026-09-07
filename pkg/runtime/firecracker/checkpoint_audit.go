package firecracker

// incrementalMemoryAuditEnabled selects diagnostic reads without changing the
// snapshot tier. Stop-only mode avoids perturbing continuing incremental windows.
func incrementalMemoryAuditEnabled(enabled, stopOnly, leaveRunning bool, snapshotType string) bool {
	if !enabled || (stopOnly && leaveRunning) {
		return false
	}
	return snapshotType == firecrackerSnapshotTypeIncremental || snapshotType == firecrackerSnapshotTypeSoftDirty
}
