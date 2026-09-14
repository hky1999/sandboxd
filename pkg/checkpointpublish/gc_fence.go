// Copyright 2026 Ant Group Corporation.
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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// GCMarkNamespace is the key prefix under which cn-gcsweep records deletion
// candidates: gc-marks/<object-key>. A mark is a small object whose store
// modification time is the marking instant. Marks never gate reads — they
// exist so a publisher that is about to lean on an EXISTING object (a Has
// hit) can notice the object is on its way out and refresh it instead.
const GCMarkNamespace = "gc-marks"

// GCMarkKey is the mark object's key for a swept store object.
func GCMarkKey(key string) string {
	return GCMarkNamespace + "/" + key
}

// GCClaimNamespace is the key prefix of the per-object EXCLUSIVE CLAIM the
// sweep and the publishers contend for with atomic creates
// (chunkstore.ExclusivePutter): gc-claims/<object-key>. Whoever wins the
// claim owns the object for one operation — the sweep for one verified
// delete (claim → recheck verdicts → DELETE → drop claim), a publisher for
// one fenced re-upload (claim → re-PUT → INDEX commit; the claim is dropped
// by a later sweep once stale). This closes the window the delete-time
// relisting cannot: a publisher that refreshes an object and commits its
// INDEX entirely between another sweep's relisting and its DELETE is no
// longer reachable, because the sweep must win the claim AFTER its
// relisting, and the fenced publisher already holds it by then.
const GCClaimNamespace = "gc-claims"

// GCClaimKey is the claim object's key for a store object.
func GCClaimKey(key string) string {
	return GCClaimNamespace + "/" + key
}

// claimAcquireWait bounds how long a fenced publisher waits for a sweep's
// claim to clear. A sweep holds a claim for one recheck plus one DELETE —
// milliseconds — so half a minute covers a slow shared bucket with margin;
// past the bound the publish fails closed rather than racing the delete.
const claimAcquireWait = 30 * time.Second

// gcAcquireClaim atomically creates the claim for key. A lost race (a sweep
// is mid-delete) is retried until the bound; the error path is the
// fail-closed outcome, never "proceed anyway".
func gcAcquireClaim(ctx context.Context, store chunkstore.Keyed, key string) error {
	ep, ok := store.(chunkstore.ExclusivePutter)
	if !ok {
		return fmt.Errorf("cannot fence sweep-marked reuse of %s: store has no conditional (create-only) puts", key)
	}
	deadline := time.Now().Add(claimAcquireWait)
	for {
		created, err := ep.PutKeyIfAbsent(ctx, GCClaimKey(key), strings.NewReader("claim"))
		if err != nil {
			return err
		}
		if created {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("a bucket sweep has held the claim on %s for over %s; aborting the publish rather than racing its delete", key, claimAcquireWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// gcFenceClaim probes the sweep mark and, when fenced, acquires the claim
// before the caller re-uploads: from here on no sweep can win this object's
// claim until it drops ours, so the re-upload and the INDEX commit that
// follows are protected against a relisting-verdict racing in from the past.
// The claim is NOT released afterwards: a later sweep clears it as stale
// once it outlives the publish it was protecting.
func gcFenceClaim(ctx context.Context, store chunkstore.Keyed, key string) (fenced bool, err error) {
	fenced, err = gcReuseFenced(ctx, store, key)
	if err != nil || !fenced {
		return fenced, err
	}
	if err := gcAcquireClaim(ctx, store, key); err != nil {
		return false, err
	}
	return true, nil
}

// gcReuseFenced reports whether reusing the store object at key is fenced by
// a sweep mark. A fenced Has hit must NOT skip the upload: the mark says a
// sweep judged this object dead and may collect it once the mark ages past
// its grace, and min-age offers no protection because the object is old by
// construction. Re-uploading the bytes from the local artifact refreshes the
// object's store timestamp, which the sweep's delete-time recheck observes
// and spares — the fence and the recheck are one protocol, not two guards.
//
// An error is returned, not swallowed: a fence that cannot be proven is not
// a pass, and failing the publish is the fail-closed outcome. This probe
// costs one extra GET per Has hit (marks are absent in steady state).
func gcReuseFenced(ctx context.Context, store chunkstore.Keyed, key string) (bool, error) {
	ok, err := store.HasKey(ctx, GCMarkKey(key))
	if err != nil {
		return false, fmt.Errorf("probe sweep mark for %s: %w", key, err)
	}
	return ok, nil
}
