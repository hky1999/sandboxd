// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkpointpublish

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// BackpressureSnapshot is the node-local publication health signal: how
// many unpublished artifacts hold unique bytes, how many bytes they hold,
// how long the oldest has waited, and how much space remains on the
// artifact filesystem. It is read-only — the safety contract (never delete
// the unique copy) is enforced by NOTHING here deleting anything.
type BackpressureSnapshot struct {
	Pending          int           `json:"pending"`
	UnpublishedBytes int64         `json:"unpublished_bytes"`
	OldestPendingAge time.Duration `json:"oldest_pending_age,omitempty"`
	FreeBytes        int64         `json:"free_bytes"`
	Backpressured    bool          `json:"backpressured"`
	Reason           string        `json:"reason,omitempty"`
}

// BackpressureLimits are the watermark thresholds. MinFreeBytes reserves
// space for live writable layers and the running instances: below it the
// snapshot flags backpressure so a caller may DELAY or REJECT new
// checkpoints instead of letting the artifact spool squeeze active RWFS
// toward ENOSPC. Reclaimable cache is NOT counted here — cache eviction is
// a separate (M2) mechanism; this signal deliberately reports the worst
// case in which nothing has been reclaimed.
type BackpressureLimits struct {
	MinFreeBytes int64
}

// SnapshotBackpressure scans the roots' unpublished artifacts and the
// artifact filesystem's free space. It never mutates anything.
func SnapshotBackpressure(roots []string, limits BackpressureLimits, now func() time.Time) BackpressureSnapshot {
	if now == nil {
		now = time.Now
	}
	snap := BackpressureSnapshot{}
	for _, root := range roots {
		entries, err := readDirNames(root)
		if err != nil {
			// Fail-closed: an unreadable root means the spool state is
			// unknowable, which must refuse admission rather than guess.
			snap.Backpressured = true
			snap.Reason = fmt.Sprintf("root %s unreadable: %v", root, err)
			continue
		}
		for _, name := range entries {
			dir := root + "/" + name
			sealedAt, sealed := sealedTimestampByName(dir)
			if !sealed {
				continue // not a sealed artifact (no manifest)
			}
			state, err := Status(dir)
			if err != nil || state == nil {
				// A sealed artifact with no state file (or an undecodable
				// one) is an implicit local_ready — its bytes are unique
				// unpublished data. Count it conservatively.
				snap.Pending++
				snap.UnpublishedBytes += artifactBytes(dir)
				if age := now().Sub(sealedAt); age > snap.OldestPendingAge {
					snap.OldestPendingAge = age
				}
				continue
			}
			switch state.State {
			case StatePublished:
				continue
			case StatePublishing:
				// A young publishing record belongs to a live publisher;
				// its bytes still count (they are not remote yet).
				snap.Pending++
				snap.UnpublishedBytes += artifactBytes(dir)
				if age := now().Sub(state.StartedAt); age > snap.OldestPendingAge {
					snap.OldestPendingAge = age
				}
			default: // queued, publish_failed, local_ready-implicit
				snap.Pending++
				snap.UnpublishedBytes += artifactBytes(dir)
				// Age from whichever is older: the seal transition (manifest
				// mtime) or the recorded state start (a publish_failed record
				// may be older than its artifact's mtime suggests).
				if age := now().Sub(state.StartedAt); age > snap.OldestPendingAge {
					snap.OldestPendingAge = age
				}
				if sealedAt, ok := sealedTimestampByName(dir); ok {
					if age := now().Sub(sealedAt); age > snap.OldestPendingAge {
						snap.OldestPendingAge = age
					}
				}
			}
		}
	}
	// All roots are checked; the minimum usable free bytes is the
	// signal (one full filesystem makes the whole spool constrained).
	freeSet := false
	for _, root := range roots {
		var stat unix.Statfs_t
		if err := unix.Statfs(root, &stat); err != nil {
			snap.Backpressured = true
			snap.Reason = fmt.Sprintf("root %s statfs: %v", root, err)
			continue
		}
		free := int64(stat.Bavail) * int64(stat.Bsize)
		if !freeSet || free < snap.FreeBytes {
			snap.FreeBytes = free
			freeSet = true
		}
	}
	if limits.MinFreeBytes > 0 && freeSet && snap.FreeBytes < limits.MinFreeBytes {
		snap.Backpressured = true
		snap.Reason = fmt.Sprintf("free %d bytes below reserve %d", snap.FreeBytes, limits.MinFreeBytes)
	}
	return snap
}

// AdmissionError is the typed error a checkpoint admission gate returns
// when the publication spool is over its watermark: the caller DELAYS or
// REJECTS the new checkpoint explicitly (fail-visible), never silently
// deletes an unpublished unique copy.
type AdmissionError struct {
	Snapshot BackpressureSnapshot
}

func (e *AdmissionError) Error() string {
	return fmt.Sprintf("checkpoint admission refused: publication spool backpressured (%s); pending=%d unpublished=%d bytes oldest=%s free=%d",
		e.Snapshot.Reason, e.Snapshot.Pending, e.Snapshot.UnpublishedBytes, e.Snapshot.OldestPendingAge.Round(time.Second), e.Snapshot.FreeBytes)
}

// CheckAdmission is the gate the checkpoint service MAY call before
// accepting a new checkpoint into a catalogued root (M1 wiring is
// config-gated and defaults OFF — zero behavior change for existing
// deployments). It returns *AdmissionError when the reserve is exhausted.
func CheckAdmission(roots []string, limits BackpressureLimits) error {
	snap := SnapshotBackpressure(roots, limits, nil)
	if snap.Backpressured {
		return &AdmissionError{Snapshot: snap}
	}
	return nil
}

func readDirNames(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue // system namespaces are never publish targets
		}
		names = append(names, e.Name())
	}
	return names, nil
}

func sealedTimestampByName(dir string) (time.Time, bool) {
	info, err := os.Stat(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}
