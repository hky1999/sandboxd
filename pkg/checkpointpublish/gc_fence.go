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
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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
// delete (claim → fresh basis → DELETE → release), a publisher for one
// fenced (re-)upload (claim → PUT → release). The claim body carries the
// owner's unique nonce, and every release or stale cleanup is a conditional
// delete bound to the observed generation (If-Match), so a replacement
// claim can never be destroyed by a participant acting on an older
// observation.
const GCClaimNamespace = "gc-claims"

// GCClaimKey is the claim object's key for a store object.
func GCClaimKey(key string) string {
	return GCClaimNamespace + "/" + key
}

// claimAcquireWait bounds how long a fenced publisher waits for a sweep's
// claim to clear. A sweep holds a claim for one fresh check plus one DELETE
// — milliseconds — so half a minute covers a slow shared bucket with
// margin; past the bound the publish fails closed rather than racing the
// delete.
const claimAcquireWait = 30 * time.Second

// claimNonceValue mints a per-process unique owner token for claim bodies:
// the generation token a later conditional delete must match. A fixed
// string is NOT a credential — two different participants must never share
// one.
var claimNonceValue atomic.Pointer[string]

func init() {
	nonce := "pub-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" +
		strconv.FormatUint(uint64(os.Getpid()), 36)
	claimNonceValue.Store(&nonce)
}

func claimBody() string { return *claimNonceValue.Load() }

// claimETag is the S3 ETag of a claim body (hex MD5 of single-part PUTs);
// callers that know their own nonce never need a prior GET to release.
func claimETag(body string) string {
	sum := md5.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

// gcAcquireClaim atomically creates the claim for key. A lost race (a sweep
// is mid-delete, or another publisher fences first) is retried until the
// bound; the error path is the fail-closed outcome, never "proceed anyway".
func gcAcquireClaim(ctx context.Context, store chunkstore.Keyed, key string) error {
	ep, ok := store.(chunkstore.ExclusivePutter)
	if !ok {
		return fmt.Errorf("cannot fence sweep-marked reuse of %s: store has no conditional (create-only) puts", key)
	}
	deadline := time.Now().Add(claimAcquireWait)
	for {
		created, err := ep.PutKeyIfAbsent(ctx, GCClaimKey(key), strings.NewReader(claimBody()))
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

// gcReleaseClaim drops a claim this process created, and ONLY that
// generation: the conditional delete answers 412 when someone else already
// replaced the claim, which is the desired outcome — their protection must
// survive our cleanup.
func gcReleaseClaim(ctx context.Context, store chunkstore.Keyed, key string) {
	ep, ok := store.(chunkstore.ExclusivePutter)
	if !ok {
		return // stores without the primitive never created claims either
	}
	_, _ = ep.DeleteKeyIfMatch(ctx, GCClaimKey(key), claimETag(claimBody()))
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

// gcFenceClaim probes the sweep mark and, when fenced, acquires the claim
// BEFORE the caller re-uploads: from here on no sweep can win this object's
// claim until this process releases it (gcReleaseClaim, after the upload),
// so the re-upload and the INDEX commit that follows are protected against a
// collector acting on a pre-claim observation.
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

// gcGuardFreshUpload closes the OTHER write path around the claim: a Has
// MISS means some collector may have just deleted the object while still
// holding its claim, and this fresh PUT recreates the key without any
// protection. After the upload the object's mark is probed — a sweep only
// ever deletes keys it has marked, so an unmarked key needs no guard — and
// a marked key gets the full claim → re-upload → release cycle: the re-make
// under mutual exclusion guarantees the object exists once the claim is
// released, whatever a concurrent collector did to the first copy.
func gcGuardFreshUpload(ctx context.Context, store chunkstore.Keyed, key string, reupload func() error) error {
	marked, err := gcReuseFenced(ctx, store, key)
	if err != nil {
		return err
	}
	if !marked {
		return nil
	}
	if err := gcAcquireClaim(ctx, store, key); err != nil {
		return err
	}
	defer gcReleaseClaim(ctx, store, key)
	return reupload()
}
