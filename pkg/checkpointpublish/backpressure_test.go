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
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestBackpressureSnapshotCountsUnpublishedOnly: published artifacts do not
// count; queued/publish_failed do; the bytes match the artifact sizes.
func TestBackpressureSnapshotCountsUnpublishedOnly(t *testing.T) {
	root := t.TempDir()
	store := mustLocal(t)
	pub := newM1Fixture(t, root, "bp-published")
	if _, err := Run(t.Context(), pub.dir, pub.id, store, "test"); err != nil {
		t.Fatal(err)
	}
	queued := newM1Fixture(t, root, "bp-queued")
	writeQueuedState(queued.dir, queued.id, "test", time.Now().Add(-time.Minute))
	failed := newM1Fixture(t, root, "bp-failed")
	if err := writeState(State{CheckpointID: failed.id, Dir: failed.dir, State: StatePublishFailed, Store: "test", StartedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	snap := SnapshotBackpressure([]string{root}, BackpressureLimits{}, nil)
	if snap.Pending != 2 {
		t.Fatalf("pending = %d, want 2 (queued+failed; published excluded)", snap.Pending)
	}
	if snap.UnpublishedBytes <= 0 {
		t.Fatalf("unpublished bytes = %d", snap.UnpublishedBytes)
	}
	if snap.OldestPendingAge < 55*time.Minute {
		t.Fatalf("oldest age = %v, want >= 55m (failed record)", snap.OldestPendingAge)
	}
	// A huge reserve flags backpressure; the typed admission error carries
	// the snapshot.
	err := CheckAdmission([]string{root}, BackpressureLimits{MinFreeBytes: 1 << 62})
	var adm *AdmissionError
	if !errors.As(err, &adm) || !adm.Snapshot.Backpressured {
		t.Fatalf("admission err = %v, want backpressured AdmissionError", err)
	}
	// Zero reserve (the default) never refuses.
	if err := CheckAdmission([]string{root}, BackpressureLimits{}); err != nil {
		t.Fatalf("zero-reserve admission refused: %v", err)
	}
}

// TestBackpressureNeverMutatesArtifacts: the snapshot and the admission
// check never touch the artifact bytes (unique-copy safety).
func TestBackpressureNeverMutatesArtifacts(t *testing.T) {
	root := t.TempDir()
	fx := newM1Fixture(t, root, "bp-safe")
	writeQueuedState(fx.dir, fx.id, "test", time.Now())
	before := dirDigest(fx.dir)
	_ = SnapshotBackpressure([]string{root}, BackpressureLimits{MinFreeBytes: 1 << 62}, nil)
	_ = CheckAdmission([]string{root}, BackpressureLimits{MinFreeBytes: 1 << 62})
	if after := dirDigest(fx.dir); after != before {
		t.Fatal("backpressure path mutated the artifact")
	}
	_ = filepath.Join // keep import if unused above
}
