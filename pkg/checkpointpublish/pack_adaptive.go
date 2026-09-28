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

// Adaptive layout selection (design: Docs/checks/20260927T-m2-adaptive-
// pack-base-reuse-design-check.md §3.1a). One probe-only classification
// pass over the unique chunk digests decides plain vs pack by ACTUAL
// missing standalone bytes — never by a manifest-derived estimate, which
// overestimates on warm stores — and the same classification feeds the
// chosen stage, so the decision never costs a second round of Has probes.
// The probes run inside the attempt's publish claim and GC publication
// intent (both are already open at the decision point), so the F3 claim
// lifecycle and the sweep fences are unchanged.

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

const (
	layoutPlain = "plain"
	layoutPack  = "pack"
	// Stable LayoutDecision.Reason enums (telemetry contract: do not
	// rename — consumers key on these strings).
	layoutReasonBelow     = "below_threshold"
	layoutReasonAtOrAbove = "at_or_above_threshold"
	layoutReasonSticky    = "sticky_retry"
	// maxAdaptiveThresholdBytes is a sanity bound, not a tuning hint.
	maxAdaptiveThresholdBytes = int64(1) << 40
)

type chunkClass uint8

const (
	classPresent chunkClass = iota // reusable standalone object
	classMissing                   // the store lacks the object
	classRefresh                   // present but sweep-marked: re-upload (fail if inherited)
)

// chunkClassification is the single pass shared by the adaptive decision
// and the stage that runs afterwards. missingBytes/missingChunks count BOTH
// missing and refresh chunks: either layout must upload those bytes.
type chunkClassification struct {
	missing       []checkpointchunks.Chunk
	refresh       []checkpointchunks.Chunk
	missingBytes  int64
	missingChunks int
	classByDigest map[string]chunkClass
}

// AdaptiveMiBToBytes converts the CLI's MiB flag to the Options threshold
// with the bounds check BEFORE the shift: an unchecked int64 shift can wrap
// to zero or negative (silently disabling the feature or slipping past the
// package ceiling). Both CLIs must go through this one helper.
func AdaptiveMiBToBytes(mib int64) (int64, error) {
	const maxMiB = maxAdaptiveThresholdBytes >> 20
	if mib < 0 || mib > maxMiB {
		return 0, fmt.Errorf("adaptive pack threshold must be between 0 (off) and %d MiB, got %d", maxMiB, mib)
	}
	return mib << 20, nil
}

// uniqueSortedChunks returns the manifest's chunks deduplicated by digest
// in stable digest order (the packed stage's canonical iteration order).
func uniqueSortedChunks(m *checkpointchunks.Manifest) []checkpointchunks.Chunk {
	unique := []checkpointchunks.Chunk{}
	seen := map[string]bool{}
	for _, c := range m.Entries {
		if !seen[c.Digest] {
			seen[c.Digest] = true
			unique = append(unique, c)
		}
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i].Digest < unique[j].Digest })
	return unique
}

// classifyUniqueChunks probes every unique chunk once (Has + sweep-mark
// check, never acquiring a claim). INHERITED entries are classified as
// FACTS, never as failures: a standalone miss or a sweep mark on an
// inherited digest is recorded as classMissing/classRefresh exactly like
// any other chunk, because the bytes may still be served by the parent
// generation's PACK objects once auto-base resolves (classification runs
// before the hint is read). Fail-closed enforcement stays where the bytes
// are actually consumed: the plain stage fails an inherited upload before
// reading the local hole, and the packed stage fails any inherited chunk
// with no verified, unfenced parent pack to reuse — repacking a hole is
// impossible and must never read local hole bytes.
// The all-zero chunk is never classified as uploadable: readers synthesize
// zero blocks as sparse holes without a GET, so neither layout needs its
// object (a cold-store plain publish used to PUT it once; the reader
// contract makes that object unnecessary).
func classifyUniqueChunks(ctx context.Context, store chunkstore.Store, unique []checkpointchunks.Chunk, m *checkpointchunks.Manifest, workers int) (*chunkClassification, error) {
	keyed, _ := store.(chunkstore.Keyed)
	out := &chunkClassification{classByDigest: make(map[string]chunkClass, len(unique))}
	var mu sync.Mutex
	err := parallelPackWork(ctx, len(unique), workers, func(ctx context.Context, i int) error {
		c := unique[i]
		length := min(int64(m.ChunkBytes), m.FileSize-c.Offset)
		if c.Digest == checkpointchunks.ZeroChunkDigest(int(length)) {
			mu.Lock()
			out.classByDigest[c.Digest] = classPresent
			mu.Unlock()
			return nil
		}
		ok, err := store.Has(ctx, c.Digest)
		if err != nil {
			return err
		}
		if !ok {
			mu.Lock()
			out.classByDigest[c.Digest] = classMissing
			out.missing = append(out.missing, c)
			out.missingBytes += length
			out.missingChunks++
			mu.Unlock()
			return nil
		}
		if keyed != nil {
			fenced, err := gcReuseFenced(ctx, keyed, chunkstore.PlainKey(c.Digest))
			if err != nil {
				return err
			}
			if fenced {
				mu.Lock()
				out.classByDigest[c.Digest] = classRefresh
				out.refresh = append(out.refresh, c)
				out.missingBytes += length
				out.missingChunks++
				mu.Unlock()
				return nil
			}
		}
		mu.Lock()
		out.classByDigest[c.Digest] = classPresent
		mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
