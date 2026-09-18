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

// GCPubIntentNamespace is the key prefix of the PUBLICATION INTENT:
// gc-pubintents/<checkpoint-id>/<attempt-nonce>. A publisher writes its
// intent BEFORE its first store object of the run and removes it only
// after the artifact INDEX has committed (or the attempt has definitively
// failed). The sweep refuses to delete ANYTHING while an intent younger
// than its grace exists, which closes the gap between the per-object
// claims (each ends at its PUT) and the INDEX commit that makes the
// publication's references visible to the sweep's re-derivation — without
// holding one claim per object across the whole publication.
//
// The attempt-nonce component is what makes overlapping attempts under the
// same checkpoint ID safe: two attempts never share one intent object, so
// the attempt that finishes first removes ONLY its own intent and cannot
// strip a still-running attempt's mid-publish protection (a single shared
// key would have exactly that hole — the successor's legal conditional
// delete of its own generation would leave the live predecessor
// intent-less and its uploads collectable). The sweep's skip is the union
// of every live attempt's window.
const GCPubIntentNamespace = "gc-pubintents"

// claimAcquireWait bounds how long a fenced publisher waits for a sweep's
// claim to clear. A sweep holds a claim for one fresh check plus one DELETE
// — milliseconds — so half a minute covers a slow shared bucket with
// margin; past the bound the publish fails closed rather than racing the
// delete.
const claimAcquireWait = 30 * time.Second

// claimNonceValue is the per-process prefix of every owner token; the
// per-acquisition counter below makes each ACQUISITION's body unique. A
// fixed body is NOT a credential: two acquisitions by the same process must
// never share one either, or a conditional delete bound to the earlier
// acquisition's generation (its ETag) would also match the later claim —
// the same replacement-destruction window the protocol exists to close.
var claimNonceValue atomic.Pointer[string]
var claimNonceSeq atomic.Uint64

func init() {
	nonce := "pub-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" +
		strconv.FormatUint(uint64(os.Getpid()), 36)
	claimNonceValue.Store(&nonce)
}

// claimBody mints a unique owner token for ONE claim acquisition; the
// returned body is the generation a later conditional delete must match.
func claimBody() string {
	return *claimNonceValue.Load() + "-" + strconv.FormatUint(claimNonceSeq.Add(1), 36)
}

// claimETag is the S3 ETag of a claim body (hex MD5 of single-part PUTs);
// callers that know their own body never need a prior GET to release. On a
// backend whose ETags are not content MD5 (SSE-KMS and friends) the
// conditional delete simply never matches and fails safe: the claim
// lingers, the next acquisition of the key fails closed after
// claimAcquireWait, and the sweep's preflight refuses deletion — the
// documented boundary, not a silent assumption.
func claimETag(body string) string {
	sum := md5.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

// gcAcquireClaim atomically creates the claim for key and returns the
// acquired generation's body — the handle every later release of THIS
// acquisition must carry. A lost race (a sweep is mid-delete, or another
// publisher fences first) is retried until the bound; the error path is the
// fail-closed outcome, never "proceed anyway".
func gcAcquireClaim(ctx context.Context, store chunkstore.Keyed, key string) (string, error) {
	ep, ok := store.(chunkstore.ExclusivePutter)
	if !ok {
		return "", fmt.Errorf("cannot fence sweep-marked reuse of %s: store has no conditional (create-only) puts", key)
	}
	deadline := time.Now().Add(claimAcquireWait)
	for {
		body := claimBody()
		created, err := ep.PutKeyIfAbsent(ctx, GCClaimKey(key), strings.NewReader(body))
		if err != nil {
			return "", err
		}
		if created {
			return body, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("a bucket sweep has held the claim on %s for over %s; aborting the publish rather than racing its delete", key, claimAcquireWait)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// gcReleaseClaim drops a claim this process created, and ONLY the
// acquisition whose handle is passed: the conditional delete answers 412
// when someone else already replaced the claim (or the body never matched),
// which is the desired outcome — their protection must survive our cleanup.
func gcReleaseClaim(ctx context.Context, store chunkstore.Keyed, key, body string) {
	ep, ok := store.(chunkstore.ExclusivePutter)
	if !ok {
		return // stores without the primitive never created claims either
	}
	_, _ = ep.DeleteKeyIfMatch(ctx, GCClaimKey(key), claimETag(body))
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
// BEFORE the caller re-uploads. The returned body is the acquired claim's
// handle: no sweep can win this object's claim until this process releases
// it (gcReleaseClaim with that handle, after the upload), so the re-upload
// and the INDEX commit that follows are protected against a collector
// acting on a pre-claim observation. A fenced publisher that finds no mark
// returns ("", false, nil) and must not re-upload.
func gcFenceClaim(ctx context.Context, store chunkstore.Keyed, key string) (body string, fenced bool, err error) {
	fenced, err = gcReuseFenced(ctx, store, key)
	if err != nil || !fenced {
		return "", fenced, err
	}
	body, err = gcAcquireClaim(ctx, store, key)
	if err != nil {
		return "", false, err
	}
	return body, true, nil
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
	body, err := gcAcquireClaim(ctx, store, key)
	if err != nil {
		return err
	}
	defer gcReleaseClaim(ctx, store, key, body)
	return reupload()
}

// gcBeginPubIntent publishes a fresh, ATTEMPT-UNIQUE intent object before
// any store object of the run is written, returning the exact key and body
// the matching end must use. Every call mints its own key under
// gc-pubintents/<id>/<nonce>, so a retry never waits on (and never
// interferes with) a crashed predecessor's leftover, and a concurrently
// running sibling attempt keeps its own protection until IT ends. The PUT
// failing is a fail-closed condition the caller must propagate: a
// publication that continued would run its entire uploads-to-INDEX window
// with zero protection.
func gcBeginPubIntent(ctx context.Context, store chunkstore.Keyed, id string) (key, body string, err error) {
	nonce := claimBody()
	key = GCPubIntentNamespace + "/" + id + "/" + nonce
	body = nonce
	if err := store.PutKey(ctx, key, strings.NewReader(body)); err != nil {
		return "", "", fmt.Errorf("write publication intent for %s: %w", id, err)
	}
	return key, body, nil
}

// gcEndPubIntent removes THIS attempt's intent after the publication
// reached a terminal state (INDEX committed, attempt failed, or caller
// unwind). Other attempts' intents are different keys and are never
// touched. A caller cancelled before ending (or a crash) leaves the intent
// in place: the sweep skips deletions until it ages past the grace bound,
// which is the documented crash-leftover terminal state — publication
// protection errs toward skipping, never toward collecting.
func gcEndPubIntent(ctx context.Context, store chunkstore.Keyed, key, body string) {
	ep, ok := store.(chunkstore.ExclusivePutter)
	if !ok {
		return // stores without the primitive never wrote a removable intent
	}
	_, _ = ep.DeleteKeyIfMatch(ctx, key, claimETag(body))
}
