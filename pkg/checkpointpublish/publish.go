// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package checkpointpublish distributes a checkpoint's memory chunks to a
// chunk store and records the outcome in a persisted state machine:
//
//	local_ready -> publishing -> published
//	                    `-> publish_failed (retryable; Run resumes)
//
// Semantics the batch-3 plan pins: publishing is an external step (the
// checkpoint RPC returns before any of it — fail-open to local restore);
// only `published` unlocks cross-node placement; published objects are
// immutable and self-contained, so the source node can reclaim its local
// artifact once every consumer has fetched. State lives beside the
// catalogued artifact roots, not inside the sealed checkpoint directory.
package checkpointpublish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// States of the publish state machine. StateQueued is the persisted
// enqueue record the scanner writes on discovery (M1): it makes the
// "queued" lifecycle state observable and crash-durable without a second
// authority — the record lives in the same .publish namespace and only the
// scanner itself creates it.
const (
	StateLocalReady    = "local_ready"
	StateQueued        = "queued"
	StatePublishing    = "publishing"
	StatePublished     = "published"
	StatePublishFailed = "publish_failed"
)

// StateDirName is the sibling directory holding publish states, relative to
// a catalogued checkpoint root. The catalog scanner skips it naturally: it
// carries no manifest.json.
const StateDirName = ".publish"

// State is the persisted publish record for one checkpoint.
type State struct {
	CheckpointID string `json:"checkpoint_id"`
	Dir          string `json:"dir"`
	State        string `json:"state"`
	Store        string `json:"store,omitempty"`
	ChunksTotal  int    `json:"chunks_total"`
	ChunksPut    int    `json:"chunks_put"`
	// ArtifactSet records whether the non-memory files (manifest, chunks
	// sidecar, vmstate, overlay) are uploaded under the artifact namespace —
	// what a node with no visibility into the source directory needs to
	// materialize a restorable copy (memory itself is served by digest from
	// the chunk objects).
	ArtifactSet bool      `json:"artifact_set"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	// Retries counts failed publish attempts (publish_failed backoff input).
	// Absent on records written before M1: such records retry immediately,
	// preserving the historical behavior for old artifacts.
	Retries int `json:"retries,omitempty"`
	// FailedAt timestamps the last failed attempt; the scanner defers a
	// retry until FailedAt + StateNextAttempt(Retries, base, cap).
	FailedAt *time.Time `json:"failed_at,omitempty"`
	// Layout records the layout an adaptive decision chose for this
	// artifact ("plain" or "pack"). Retries of the same artifact reuse it,
	// so one artifact never mixes layouts across attempts. Absent on
	// records written before adaptive selection existed, and absent
	// whenever the feature is off — either way the next attempt decides
	// from scratch if the feature is enabled.
	Layout string `json:"layout,omitempty"`
}

// StateNextAttempt is the bounded exponential backoff delay before retry
// number retries+1: base << retries, capped. Zero base disables deferral.
func StateNextAttempt(retries int, base, cap time.Duration) time.Duration {
	if base <= 0 || retries <= 0 {
		return 0
	}
	d := base
	for i := 1; i < retries; i++ {
		// Saturation guard: multiplying past cap/2 means the next doubling
		// either overflows int64 or exceeds cap — both resolve to cap. A
		// very large retries must never wrap d to a negative value and
		// bypass the ceiling.
		if cap > 0 && d >= cap/2 {
			return cap
		}
		// >= (not >): d == 1<<62 exactly would overflow on the next
		// doubling (2^63 wraps to MinInt64), so the boundary value itself
		// must saturate. An uncapped (cap == 0) backoff saturates to
		// MaxInt64 — returning cap here would return zero and disable the
		// deferral precisely when retries are huge, the one case that
		// needs it most.
		if d >= (1 << 62) {
			if cap > 0 {
				return cap
			}
			return time.Duration(math.MaxInt64)
		}
		d *= 2
	}
	if cap > 0 && d > cap {
		return cap
	}
	return d
}

// StatePath returns the state file location for a checkpoint directory.
func StatePath(checkpointDir string) string {
	return filepath.Join(filepath.Dir(checkpointDir), StateDirName, filepath.Base(checkpointDir)+".json")
}

// Status reads the persisted state for a checkpoint directory. A missing
// state file is not an error: the checkpoint was never published, which the
// caller represents as a nil state (local-only).
func Status(checkpointDir string) (*State, error) {
	raw, err := os.ReadFile(StatePath(checkpointDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("decode publish state: %w", err)
	}
	return &state, nil
}

// StateWriteTiming separates the file Sync from the complete local state write.
// Durations are wall-clock nanoseconds, not CPU time or remote store latency.
type StateWriteTiming struct {
	Total time.Duration `json:"total_ns"`
	Sync  time.Duration `json:"sync_ns"`
}

type StateTimings struct {
	Publishing StateWriteTiming `json:"publishing"`
	Published  StateWriteTiming `json:"published"`
	Failed     StateWriteTiming `json:"failed,omitempty"`
}

func writeState(state State) error {
	return writeStateMeasured(state, nil)
}

func writeStateMeasured(state State, timing *StateWriteTiming) error {
	if timing != nil {
		start := time.Now()
		defer func() { timing.Total = time.Since(start) }()
	}
	path := StatePath(state.Dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// Write-through-temp + atomic rename: a daemon or CLI reading the
	// state concurrently (publishd scanners, catalog) must never observe a
	// half-written JSON, and a crash mid-write must leave the previous
	// state intact.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(append(encoded, '\n')); err != nil {
		return err
	}
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	syncStart := time.Now()
	err = tmp.Sync()
	if timing != nil {
		timing.Sync = time.Since(syncStart)
	}
	if err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Result summarizes one Run.
type Result struct {
	StateTimings      *StateTimings  `json:"state_timings,omitempty"`
	Phases            *PublishPhases `json:"phases,omitempty"` // attempt attribution (walls + request counters)
	PackPayloadBudget int            `json:"pack_payload_budget,omitempty"`
	PackPayloadPeak   int64          `json:"pack_payload_peak,omitempty"`
	PackTimings       *PackTimings   `json:"pack_timings,omitempty"`
	PacksPut          int            `json:"packs_put,omitempty"`
	PacksSkip         int            `json:"packs_skip,omitempty"`
	Workers           int            `json:"workers"` // actual memory upload concurrency
	State             State          `json:"state"`
	ChunksPut         int            `json:"chunks_put"`  // unique chunks written this run
	ChunksSkip        int            `json:"chunks_skip"` // unique chunks reused or synthesized
	// LayoutDecision records the adaptive layout choice when
	// Options.AdaptivePackThresholdBytes is enabled. It is deliberately a
	// separate struct — never inside Phases, which is a duration map — and
	// omitempty so old consumers and old state files are unaffected.
	LayoutDecision *LayoutDecision `json:"layout_decision,omitempty"`
	// AutoBase records the automatic pack-baseline resolution when
	// Options.PackAutoBase is enabled. Separate from Phases for the same
	// reason; omitempty so non-auto runs are unaffected.
	AutoBase *AutoBaseDecision `json:"auto_base,omitempty"`
}

// LayoutDecision is the observable record of one adaptive choice. It is
// emitted ONLY when adaptive selection is enabled — explicit -pack-mib and
// default runs keep their old semantics and record nothing. Reason is a
// stable enum: "below_threshold" (fresh decision chose plain),
// "at_or_above_threshold" (fresh decision chose pack), "sticky_retry"
// (the recorded layout was reused without re-probing). The actual-missing
// fields are POINTERS with omitempty precisely so a sticky retry — which
// does not re-classify — omits them instead of emitting a misleading zero
// that could be read as a real measurement.
type LayoutDecision struct {
	ActualMissingBytes  *int64 `json:"actual_missing_bytes,omitempty"`
	ActualMissingChunks *int   `json:"actual_missing_chunks,omitempty"`
	ThresholdBytes      int64  `json:"threshold_bytes"`
	Chosen              string `json:"chosen"` // "plain" or "pack"
	Reason              string `json:"reason"`
}

// Run publishes the checkpoint's memory chunks: it computes (or reuses) the
// chunk manifest, streams every chunk the store does not already hold, and
// drives the persisted state machine. It is idempotent — a failed or
// interrupted run resumes and re-puts only what is missing. The memory file
// is opened once and seeked per chunk.
func Run(ctx context.Context, checkpointDir, id string, store chunkstore.Store, storeName string) (Result, error) {
	return RunWithOptions(ctx, checkpointDir, id, store, storeName, Options{})
}

// newPackStreamReader builds the streaming pack reader for one PUT or
// verification drain, honoring the per-run instrumentation hook.
func (o *Options) newPackStreamReader(ctx context.Context, src io.ReaderAt, m *checkpointchunks.Manifest, chunks []checkpointchunks.Chunk) packStreamReader {
	if o.packStreamFactory != nil {
		return o.packStreamFactory(ctx, src, m, chunks)
	}
	return newVerifiedPackReadSeeker(ctx, src, m, chunks)
}

// Options bounds memory upload concurrency independently of host CPU count.
// Zero Workers preserves Run's default (at most eight GOMAXPROCS workers).
type Options struct {
	PackBatchHash      bool   // synchronous batches of up to 16 SHA256 digests; requires packing
	PackSkipChunkProbe bool   // skip standalone chunk reuse; still probe baseline and newly built packs
	PackPayloadBytes   int    // zero keeps the 16MiB active pack payload budget
	PackIdentity       string // empty = legacy whole-pack SHA256; chunks-v1 = versioned chunk root
	Workers            int
	// OverlayWorkers bounds the overlay chunk upload pool; zero keeps the
	// package default (8). Overlay chunks are never packed or compressed,
	// so this is the only overlay throughput knob.
	OverlayWorkers int
	PackBytes      int    // zero keeps version-1 single-chunk publication
	BaseID         string // optional verified published baseline in the same store
	// CompressChunks uploads standalone memory chunk objects as zstd
	// bodies under the ".z" content key and marks the transport sidecar
	// accordingly. Digests keep naming uncompressed bytes, and readers
	// fall back to the plain object when a chunk predates compression,
	// so verification and cross-format reuse are unchanged. Packs carry
	// range-readable payloads and are never compressed by this option.
	CompressChunks bool
	// PackStreamingPut opts into verified streaming PUT for pack objects:
	// instead of assembling the full pack buffer in memory and calling
	// PutKey with a bytes.Reader, a verified io.ReadSeeker streams chunks
	// directly from the memory file (ReadAt + sha256 per chunk, bytes
	// verified before exposure). Only active when PackIdentity ==
	// chunks-v1 (the pack key is derivable from the parts list without
	// reading the pack bytes). Default false keeps the exact buffer path.
	PackStreamingPut bool
	// PackAutoBase opts into automatic pack-baseline resolution: the
	// sealed manifest's base_memory field (the parent generation's
	// checkpoint directory name, recorded at seal time) is read as a HINT
	// and, when the layout enters the packed stage, adopted as this
	// attempt's BaseID — passing through the same validPackedID gate and
	// the same loadPackBaseline verification chain as an explicit -base-id.
	// An explicit BaseID is always authoritative (the hint is not even
	// read). The resolution is observable on the Result as AutoBase.
	// Default false keeps the exact historical behavior.
	PackAutoBase bool
	// autoBaseOrigin marks that BaseID was set by the auto-base resolver,
	// not by the caller. It controls the loadPackBaseline failure
	// semantics inside runPacked: an auto-resolved base that fails to
	// load (parent absent/corrupt) falls back to a no-base publish; an
	// explicit BaseID keeps its historical hard error. Unexported — the
	// resolver sets it, callers never do.
	autoBaseOrigin bool
	// packStreamFactory substitutes the streaming pack reader constructor.
	// Unexported and PER-RUN (an Options field, never a package global):
	// test instrumentation only, so an integration test can observe exact
	// reader creation and per-reader chunk loads across a full publish.
	// Nil keeps newVerifiedPackReadSeeker.
	packStreamFactory func(ctx context.Context, src io.ReaderAt, m *checkpointchunks.Manifest, chunks []checkpointchunks.Chunk) packStreamReader
	// AdaptivePackThresholdBytes opts into adaptive layout selection:
	// one probe-only classification measures the ACTUAL missing standalone
	// bytes (missing + sweep-marked refresh, never a manifest estimate)
	// and the artifact is published plain while that stays BELOW this
	// threshold, packed at or above it. Zero (the default) disables the
	// feature and keeps the explicit-flag semantics: PackBytes > 0 forces
	// packing, zero forces plain. Requires PackBytes to be configured;
	// mutually exclusive with CompressChunks, BaseID, and
	// PackSkipChunkProbe (the classification must probe standalone reuse).
	// The chosen layout is recorded in the artifact's publish state and
	// reused by retries of the same artifact, so one artifact never mixes
	// layouts across attempts.
	AdaptivePackThresholdBytes int64
}

// RunWithOptions is Run with an explicit memory-upload concurrency bound.
// Overlay publication retains its own bounded worker pool.
func RunWithOptions(ctx context.Context, checkpointDir, id string, store chunkstore.Store, storeName string, opts Options) (Result, error) {
	if opts.OverlayWorkers < 0 || opts.OverlayWorkers > 64 {
		return Result{}, fmt.Errorf("overlay workers %d out of range [0,64] — reject instead of clamping so a misconfigured knob is visible", opts.OverlayWorkers)
	}
	if opts.PackPayloadBytes < 0 || opts.PackPayloadBytes > 64<<20 {
		return Result{}, fmt.Errorf("pack payload budget %d out of range [0,%d]", opts.PackPayloadBytes, 64<<20)
	}
	if opts.CompressChunks && opts.PackBytes != 0 {
		return Result{}, fmt.Errorf("compressed chunks require unpacked publication")
	}
	if opts.PackBatchHash && opts.PackBytes == 0 {
		return Result{}, fmt.Errorf("batch hashing requires packing")
	}
	if opts.PackSkipChunkProbe && opts.PackBytes == 0 {
		return Result{}, fmt.Errorf("skipping standalone chunk probes requires packing")
	}
	if opts.PackIdentity != "" && (opts.PackIdentity != checkpointchunks.PackIdentityChunks || opts.PackBytes == 0) {
		return Result{}, fmt.Errorf("pack identity requires packing and must be chunks-v1 or empty")
	}
	if opts.CompressChunks && opts.PackBytes != 0 {
		return Result{}, fmt.Errorf("compressed standalone chunks require unpacked publication; packs are range-readable and stay uncompressed")
	}
	if opts.Workers < 0 || opts.Workers > 64 {
		return Result{}, fmt.Errorf("publish workers must be between 0 and 64, got %d", opts.Workers)
	}
	if opts.PackBytes < 0 || opts.PackBytes > checkpointchunks.MaxPackBytes || (opts.PackBytes > 0 && opts.PackBytes < 4096) {
		return Result{}, fmt.Errorf("pack bytes must be zero or between 4096 and %d", checkpointchunks.MaxPackBytes)
	}
	if opts.PackPayloadBytes != 0 && (opts.PackBytes == 0 || opts.PackPayloadBytes < opts.PackBytes || opts.PackPayloadBytes > maxPackPayloadBudget) {
		return Result{}, fmt.Errorf("pack payload budget requires packing and must be between pack size and %d", maxPackPayloadBudget)
	}
	if opts.BaseID != "" && (opts.PackBytes == 0 || !validPackedID(opts.BaseID) || opts.BaseID == id) {
		return Result{}, fmt.Errorf("pack base ID must be a distinct checkpoint ID with packing enabled")
	}
	if opts.AdaptivePackThresholdBytes < 0 || opts.AdaptivePackThresholdBytes > maxAdaptiveThresholdBytes {
		return Result{}, fmt.Errorf("adaptive pack threshold must be zero (off) or between 1 and %d bytes", maxAdaptiveThresholdBytes)
	}
	if opts.AdaptivePackThresholdBytes != 0 {
		// The opt-in feature defines its own probing semantics, so it is
		// rejected (not silently ignored) against every flag combination
		// that would change or bypass them.
		if opts.PackBytes == 0 {
			return Result{}, errors.New("adaptive pack layout requires packing to be configured (pack-mib defines the pack size)")
		}
		if opts.CompressChunks {
			return Result{}, errors.New("adaptive pack layout cannot be combined with compressed standalone chunks")
		}
		if opts.BaseID != "" {
			return Result{}, errors.New("adaptive pack layout cannot be combined with an explicit pack base")
		}
		if opts.PackSkipChunkProbe {
			return Result{}, errors.New("adaptive pack layout requires standalone probes and cannot skip them")
		}
	}
	if err := validateAutoBaseOptions(opts); err != nil {
		return Result{}, err
	}
	claim, err := acquirePublishClaim(ctx, checkpointDir)
	if err != nil {
		return Result{}, err
	}
	defer claim.Close()
	workers := opts.Workers
	if workers == 0 {
		workers = min(runtime.GOMAXPROCS(0), 8)
	}
	result := Result{Workers: workers, StateTimings: &StateTimings{}}
	state := State{
		CheckpointID: id,
		Dir:          checkpointDir,
		State:        StatePublishing,
		Store:        storeName,
		StartedAt:    time.Now().UTC(),
	}
	if previous, err := Status(checkpointDir); err != nil {
		// An UNREADABLE state file used to be silently treated as "no
		// state", which let a malformed record bypass every protection
		// built on it (layout authority, resume accounting). Fail closed
		// before any store IO: only a genuinely absent file means fresh.
		return Result{}, fmt.Errorf("read publish state for %s: %w (refusing to treat an unreadable state as fresh; repair or remove the state file deliberately)", id, err)
	} else if previous != nil {
		// NOTE on identity: previous.CheckpointID may legitimately differ
		// from id — republishing one directory under a new label is a
		// supported flow (existing tests: claim_test's owner/retry,
		// pack_publish_test's base/warm). The state is directory-scoped
		// by construction (StatePath), and the recorded ID is the LAST
		// publication's label, not an ownership proof; refusing here
		// would change that contract. The layout-authority rules below
		// are unaffected: they bind the DIRECTORY's layout, whichever
		// label the republish uses.
		state.ChunksTotal, state.ChunksPut = previous.ChunksTotal, previous.ChunksPut
		// An adaptive decision is sticky per artifact: a retry reuses the
		// recorded layout so one artifact never mixes plain and pack
		// objects across attempts. Records predating the feature (or
		// published with it off) carry no layout and decide afresh.
		state.Layout = previous.Layout
		if state.Layout != "" {
			// A persisted layout is authoritative in EVERY later invocation,
			// not only adaptive ones. Unknown strings are state corruption:
			// fail closed before any store IO instead of silently treating
			// them as plain. A layout recorded under adaptive selection with
			// the feature now off is configuration drift — the forced run
			// would silently change this artifact's layout, so refuse and
			// name the remedy (restore the adaptive configuration; to
			// deliberately change layout, retire the artifact's state).
			if state.Layout != layoutPlain && state.Layout != layoutPack {
				return Result{}, fmt.Errorf("publish state for %s carries unknown layout %q (corrupt state); refusing to publish", id, state.Layout)
			}
			if opts.AdaptivePackThresholdBytes == 0 {
				return Result{}, fmt.Errorf(
					"artifact %s already decided layout %q under adaptive selection; this run has adaptive off — restore the adaptive configuration (or retire the artifact's publish state to change layout deliberately); refusing a layout-changing forced run",
					id, state.Layout)
			}
			if state.Layout == layoutPack && opts.PackBytes == 0 {
				return Result{}, fmt.Errorf("artifact %s already decided pack layout but no pack size is configured", id)
			}
		}
		// Stamp THIS attempt's own start: cn-publishd's stale-lease requeue
		// judges liveness by StartedAt, and an inherited first-generation
		// timestamp would let a retry in flight be re-claimed as a crash
		// leftover (F8). A full owner lease is still future work; this
		// closes the practical gap.
		state.StartedAt = time.Now().UTC()
	}

	// Attribution (T_remote decomposition): every store request of the
	// attempt is counted, split into data (Has/GET/PUT with bytes) and
	// control (GC intents/claims, no data columns). The tiered wrapper
	// preserves the store's exact capability set — optional-interface
	// assertions (Keyed, ExclusivePutter) answer identically before and
	// after wrapping, so fallback and fail-closed paths are unchanged.
	counters := &phaseCounters{}
	store = instrumentStore(store, counters)
	phases := &PublishPhases{}
	result.Phases = phases
	// Unified freeze: EVERY return path from here on finalizes the shared
	// attribution. The defer mutates the POINTED-TO Phases/StateTimings, so
	// the caller observes it even though Result travels by value — this is
	// what keeps early returns (a failed publishing state write, a failed
	// failed-state write in failAttempt, mid-upload errors) from leaking an
	// unfrozen attempt. finalizeAttemptPhases is idempotent (it re-reads
	// the monotonic counters), so success paths that already finalized are
	// unaffected.
	defer finalizeAttemptPhases(result.Phases, counters, result.StateTimings)

	// Publication intent: from before the first store write of this run
	// until its terminal state, gc-pubintents/<id>/<attempt-nonce> tells
	// every sweep that this publication's objects are on their way to an
	// INDEX commit and must not be collected. The per-object claims each
	// end at their PUT and cannot cover the release→INDEX gap; the intent
	// covers every object family of the run — Has-reused plain chunks, .z
	// bodies, inherited digests with no local bytes, packs, overlay chunks,
	// and the artifact set — because it opens before any of them are
	// touched. Establishing it is a safety record, not telemetry: a failed
	// intent PUT fails the whole publish closed BEFORE any data upload or
	// INDEX write. The deferred end runs on success, failure, and panic
	// unwinds alike; a cancelled context (or a crash) leaves the intent to
	// expire by the sweep's grace bound, which is the safe direction —
	// protection errs toward skipping collection, never toward collecting.
	intentKeyed, intentOK := store.(chunkstore.Keyed)
	if intentOK {
		intentKey, intentBody, err := gcBeginPubIntent(ctx, intentKeyed, id)
		if err != nil {
			return failAttempt(&result, counters, state, err)
		}
		defer gcEndPubIntent(context.WithoutCancel(ctx), intentKeyed, intentKey, intentBody)
	}

	loadStart := time.Now()
	manifest, err := checkpointchunks.Load(checkpointDir)
	phases.ManifestLoadWall = time.Since(loadStart)
	if err != nil {
		if !os.IsNotExist(err) {
			return failAttempt(&result, counters, state, err)
		}
		// No sealed sidecar: this is the only path that actually scans and
		// hashes the memory file.
		scanStart := time.Now()
		manifest, err = checkpointchunks.Compute(ctx, checkpointDir, checkpointchunks.DefaultChunkBytes)
		phases.ScanHashWall = time.Since(scanStart)
		if err != nil {
			return failAttempt(&result, counters, state, err)
		}
	}
	state.ChunksTotal = manifest.ChunkCount
	// Adaptive layout (opt-in): one probe-only classification measures the
	// ACTUAL missing standalone bytes, decides the layout, and feeds the
	// chosen stage — the probes are never repeated downstream. The pass
	// runs inside the claim and GC publication intent this attempt already
	// opened, so the F3 claim lifecycle and sweep fences are unchanged.
	var adaptiveClass *chunkClassification
	if opts.AdaptivePackThresholdBytes != 0 && state.Layout == "" {
		var err error
		adaptiveClass, err = classifyUniqueChunks(ctx, store, uniqueSortedChunks(manifest), manifest, workers)
		if err != nil {
			return failAttempt(&result, counters, state, err)
		}
		reason := layoutReasonAtOrAbove
		if adaptiveClass.missingBytes < opts.AdaptivePackThresholdBytes {
			state.Layout = layoutPlain
			reason = layoutReasonBelow
		} else {
			state.Layout = layoutPack
		}
		measuredBytes, measuredChunks := adaptiveClass.missingBytes, adaptiveClass.missingChunks
		result.LayoutDecision = &LayoutDecision{
			ActualMissingBytes:  &measuredBytes,
			ActualMissingChunks: &measuredChunks,
			ThresholdBytes:      opts.AdaptivePackThresholdBytes,
			Chosen:              state.Layout,
			Reason:              reason,
		}
	} else if opts.AdaptivePackThresholdBytes != 0 {
		// Sticky retry of an already-decided artifact: keep the recorded
		// layout and do not re-probe just for telemetry — the chosen
		// stage reclassifies inline exactly as a non-adaptive attempt
		// would, so a retry's probes are never skipped. The actual-missing
		// pointers stay nil: a sticky retry did not measure, and a
		// synthetic zero would be ambiguous telemetry.
		result.LayoutDecision = &LayoutDecision{
			ThresholdBytes: opts.AdaptivePackThresholdBytes,
			Chosen:         state.Layout,
			Reason:         layoutReasonSticky,
		}
	}
	// Auto-base resolution: only when the feature is enabled, and only
	// when we know the attempt is entering the packed stage. A plain
	// layout (adaptive-chosen or forced) never reads the manifest hint.
	goingToPack := (opts.AdaptivePackThresholdBytes != 0 && state.Layout == layoutPack) ||
		(opts.AdaptivePackThresholdBytes == 0 && opts.PackBytes > 0)
	if opts.PackAutoBase {
		opts, result.AutoBase = resolveAutoBase(opts, checkpointDir, id, goingToPack)
	}
	if opts.AdaptivePackThresholdBytes != 0 {
		// The adaptive decision is authoritative: plain falls through to
		// the plain stage below even though PackBytes is configured (the
		// feature requires it as the pack-size definition).
		if state.Layout == layoutPack {
			return runPacked(ctx, checkpointDir, id, store, manifest, state, result, opts, adaptiveClass)
		}
	} else if opts.PackBytes > 0 {
		// Explicit packing without adaptive keeps its forced semantics.
		return runPacked(ctx, checkpointDir, id, store, manifest, state, result, opts, nil)
	}
	if opts.CompressChunks {
		// Compressed chunk objects live under explicit keys; a backend
		// without keyed access cannot host them. Fail before any state
		// or object changes.
		if _, ok := store.(chunkstore.Keyed); !ok {
			return failAttempt(&result, counters, state, errors.New("compressed chunk publication requires a keyed store"))
		}
	}

	if err := writeStateMeasured(state, &result.StateTimings.Publishing); err != nil {
		return result, err
	}

	memory, err := os.Open(filepath.Join(checkpointDir, manifest.File))
	if err != nil {
		return failAttempt(&result, counters, state, err)
	}
	defer memory.Close()
	uploadStart := time.Now()

	// O-1: parallel chunk upload. Sequential PUTs bound the publish wall
	// clock by per-request latency (~25ms/object, 54s for 2,200 chunks at
	// 4GiB); overlapping round trips with a worker pool compresses the
	// same bytes into the bandwidth-bound floor.
	// Error slot: every read and write goes through errMu; failedFlag is
	// the lock-free fast path workers check per job. (A sync.Once around
	// the first writer does not guard concurrent readers — the race the
	// source review reproduced with injected HEAD errors.)
	var errMu sync.Mutex
	uploadErr := error(nil)
	failedFlag := atomic.Bool{}
	failUpload := func(cause error) {
		errMu.Lock()
		if uploadErr == nil {
			uploadErr = cause
		}
		errMu.Unlock()
		failedFlag.Store(true)
	}
	readUploadErr := func() error {
		errMu.Lock()
		defer errMu.Unlock()
		return uploadErr
	}
	// P2: request dedup by digest. Entries repeat digests heavily (the
	// all-zero chunk alone recurs thousands of times at 4GiB); Has/Put is
	// keyed by content, so one representative entry per unique digest
	// serves every duplicate. This collapses the HEAD count from
	// len(Entries) to the number of distinct chunks.
	uniqueChunks := make([]checkpointchunks.Chunk, 0, len(manifest.Entries))
	seenDigest := make(map[string]struct{}, len(manifest.Entries))
	for _, chunk := range manifest.Entries {
		if _, dup := seenDigest[chunk.Digest]; dup {
			continue
		}
		seenDigest[chunk.Digest] = struct{}{}
		uniqueChunks = append(uniqueChunks, chunk)
	}
	type uploadJob struct {
		chunk checkpointchunks.Chunk
	}
	// heldClaim pairs a fenced object key with the EXACT acquisition's
	// handle: the release must match the generation that was acquired, not
	// whatever claim may sit on the key by the time the upload completes.
	type heldClaim struct {
		key  string
		body string
	}
	upload := make(chan uploadJob, workers*2)
	keyed := store.(chunkstore.Keyed)
	var skippedCount int64
	var wg sync.WaitGroup
	var progress int64
	var progressMu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, manifest.ChunkBytes)
			for job := range upload {
				if failedFlag.Load() {
					continue // drain
				}
				// The per-job closure gives every failure path ONE release
				// point: whatever claims this job acquired are dropped by
				// the deferred release when the job ends, no matter which
				// intermediate step failed (a leaked claim would block every
				// later sweep and publish on the key for up to the claim
				// grace). releaseClaims is idempotent — the fenced success
				// path may release early and let the defer no-op.
				func() {
					// heldClaims tracks each claim this job holds from a
					// fenced Has hit until after the re-upload completes;
					// each release carries the EXACT acquisition's handle,
					// so a replaced claim can never be dropped by mistake.
					var heldClaims []heldClaim
					releaseClaims := func() {
						for _, h := range heldClaims {
							gcReleaseClaim(ctx, keyed, h.key, h.body)
						}
						heldClaims = nil
					}
					defer releaseClaims()
					if adaptiveClass != nil {
						// Adaptive plain: reuse the decision-time
						// classification — no second Has round. Present
						// chunks skip; sweep-marked chunks take the fence
						// claim at their own upload point (a narrower claim
						// window than the probe-time acquisition below — the
						// safe direction). Inherited entries arrive here as
						// classification FACTS (missing/refresh): the plain
						// stage cannot serve a hole, so the inherited checks
						// below fail the attempt closed BEFORE any local
						// byte is read.
						switch adaptiveClass.classByDigest[job.chunk.Digest] {
						case classPresent:
							atomic.AddInt64(&skippedCount, 1)
							return
						case classRefresh:
							plainClaim, fenced, err := gcFenceClaim(ctx, keyed, chunkstore.PlainKey(job.chunk.Digest))
							if err != nil {
								failUpload(err)
								return
							}
							if !fenced {
								// The mark vanished between the probe and
								// the claim: the object is safe to reuse.
								atomic.AddInt64(&skippedCount, 1)
								return
							}
							heldClaims = append(heldClaims, heldClaim{key: chunkstore.PlainKey(job.chunk.Digest), body: plainClaim})
						default:
							// classMissing: fall through and upload.
						}
					} else if ok, err := store.Has(ctx, job.chunk.Digest); err != nil {
						failUpload(fmt.Errorf("has chunk %s: %w", job.chunk.Digest[:12], err))
						return
					} else if ok {
						// Sweep fence: a marked object is scheduled for
						// collection once its mark ages past the sweep's
						// grace, and min-age offers no protection because a
						// reused object is old by construction. Refresh it
						// by re-uploading — unless the local artifact is a
						// hole (an inherited digest), whose bytes are the
						// parent's and exist only in the store: a marked
						// parent means the parent generation is going away,
						// and this artifact cannot be published against it.
						plainClaim, fenced, err := gcFenceClaim(ctx, keyed, chunkstore.PlainKey(job.chunk.Digest))
						if err != nil {
							failUpload(err)
							return
						}
						if !fenced {
							atomic.AddInt64(&skippedCount, 1)
							return
						}
						heldClaims = append(heldClaims, heldClaim{key: chunkstore.PlainKey(job.chunk.Digest), body: plainClaim})
						if job.chunk.Inherited {
							failUpload(fmt.Errorf(
								"inherited chunk %s at %d is marked for collection by a bucket sweep; the parent generation's object must be republished before this artifact",
								job.chunk.Digest[:12], job.chunk.Offset))
							return // deferred releaseClaims drops the claim
						}
					}
					if opts.CompressChunks {
						// Resume and cross-run idempotence: a compressed
						// object from an interrupted earlier run already
						// satisfies this digest. Only the plain probe above
						// stays global — a chunk that exists uncompressed
						// is reused as-is and a reader's fallback finds it.
						if ok, err := keyed.HasKey(ctx, chunkstore.CompressedKey(job.chunk.Digest)); err != nil {
							failUpload(fmt.Errorf("has compressed chunk %s: %w", job.chunk.Digest[:12], err))
							return
						} else if ok {
							// Same fence as the plain probe, on the object
							// actually being reused (the .z body).
							compClaim, fenced, err := gcFenceClaim(ctx, keyed, chunkstore.CompressedKey(job.chunk.Digest))
							if err != nil {
								failUpload(err)
								return
							}
							if !fenced {
								atomic.AddInt64(&skippedCount, 1)
								return
							}
							heldClaims = append(heldClaims, heldClaim{key: chunkstore.CompressedKey(job.chunk.Digest), body: compClaim})
							if job.chunk.Inherited {
								failUpload(fmt.Errorf(
									"inherited chunk %s at %d has only a sweep-marked compressed object; the parent generation's object must be republished before this artifact",
									job.chunk.Digest[:12], job.chunk.Offset))
								return
							}
							// Fenced but locally representable: fall through
							// and re-upload the compressed body.
						}
					}
					if job.chunk.Inherited {
						// The local artifact is a hole here (digest-inherited
						// generation): its real bytes live in the store under
						// this very digest. A store miss means the parent
						// object is gone — NEVER upload local hole bytes under
						// the parent's key, that would poison the namespace
						// with zeros the digest vouches against.
						failUpload(fmt.Errorf(
							"inherited chunk %s at %d missing from the store; the parent generation's object must be republished before this artifact",
							job.chunk.Digest[:12], job.chunk.Offset))
						return
					}
					if _, err := memory.ReadAt(buf, job.chunk.Offset); err != nil &&
						!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
						failUpload(fmt.Errorf("read chunk at %d: %w", job.chunk.Offset, err))
						return
					}
					end := int(manifest.FileSize - job.chunk.Offset)
					if end > manifest.ChunkBytes {
						end = manifest.ChunkBytes
					}
					putChunk := func() error {
						if opts.CompressChunks {
							// The object body is a zstd stream; the digest still
							// names the uncompressed bytes and the transport
							// sidecar carries the compression marker.
							compStart := time.Now()
							body, err := chunkstore.CompressChunkBody(buf[:end])
							counters.addCompress(time.Since(compStart))
							if err != nil {
								return fmt.Errorf("compress chunk at %d: %w", job.chunk.Offset, err)
							}
							if err := keyed.PutKey(ctx, chunkstore.CompressedKey(job.chunk.Digest), bytes.NewReader(body)); err != nil {
								return fmt.Errorf("put compressed chunk at %d: %w", job.chunk.Offset, err)
							}
							return nil
						}
						if err := store.Put(ctx, job.chunk.Digest, bytes.NewReader(buf[:end])); err != nil {
							return fmt.Errorf("put chunk at %d: %w", job.chunk.Offset, err)
						}
						return nil
					}
					if err := putChunk(); err != nil {
						failUpload(err)
						return // deferred releaseClaims drops any held claim
					}
					if len(heldClaims) > 0 {
						// Fenced re-upload complete: end these claims'
						// protection early; the deferred release no-ops.
						releaseClaims()
					} else {
						// Fresh-upload guard: a collector may have deleted the
						// object seconds ago while still holding its claim, and
						// a SECOND collector can then act on its pre-deletion
						// observation against this recreated key. When the key
						// carries a mark, redo the upload under the claim so the
						// object provably exists once the claim is released.
						guardKey := chunkstore.PlainKey(job.chunk.Digest)
						if opts.CompressChunks {
							guardKey = chunkstore.CompressedKey(job.chunk.Digest)
						}
						if err := gcGuardFreshUpload(ctx, keyed, guardKey, putChunk); err != nil {
							failUpload(err)
							return
						}
					}
					progressMu.Lock()
					progress++
					state.ChunksPut = int(progress)
					progressMu.Unlock()
				}()
			}
		}()
	}
	// O-1b: workers run Has+Put together; the producer feeds only unique
	// digests (P2) and stops at the first failure or cancellation.
	put := 0
	skipped := 0
	for _, chunk := range uniqueChunks {
		if failedFlag.Load() {
			break
		}
		if err := ctx.Err(); err != nil {
			failUpload(err)
			break
		}
		upload <- uploadJob{chunk: chunk}
	}
	close(upload)
	wg.Wait()
	// Recorded BEFORE the error check: an upload stage that died on a
	// failed Has/PUT still keeps its wall, not only its request counters.
	phases.UploadWall = time.Since(uploadStart)
	if err := readUploadErr(); err != nil {
		return failAttempt(&result, counters, state, err)
	}
	put = int(progress)
	skipped = int(atomic.LoadInt64(&skippedCount))

	// Artifact set: everything a blind node needs to materialize the
	// checkpoint except the memory bytes themselves.
	if keyed, ok := store.(chunkstore.Keyed); ok {
		// Compressed publication advertises itself on the transport
		// sidecar (the sealed file is never rewritten): same entries,
		// same root, plus the compression marker readers consult.
		var transport *checkpointchunks.Manifest
		if opts.CompressChunks {
			view := *manifest
			view.Compression = checkpointchunks.CompressionZstd
			transport = &view
		}
		if err := publishArtifactSetWithTransport(ctx, checkpointDir, id, keyed, &state, transport, phases, opts.OverlayWorkers); err != nil {
			return failAttempt(&result, counters, state, err)
		}
	} else {
		return failAttempt(&result, counters, state, errors.New("store backend cannot host artifact sets"))
	}

	state.State = StatePublished
	state.PublishedAt = time.Now().UTC()
	state.ChunksPut = put + skipped
	state.LastError = ""
	if err := writeStateMeasured(state, &result.StateTimings.Published); err != nil {
		return result, err
	}
	result.State = state
	result.ChunksPut, result.ChunksSkip = put, skipped
	return result, nil
}

// finalizeAttemptPhases freezes the request counters into the phases and
// derives the state-persistence wall from the attempt's measured state
// writes (sequential local writes; additive).
func finalizeAttemptPhases(phases *PublishPhases, counters *phaseCounters, timings *StateTimings) {
	if phases == nil || counters == nil {
		return
	}
	snap := counters.snapshot()
	phases.HasReqs = snap.HasReqs
	phases.HasTimeTotal = snap.HasTimeTotal
	phases.GetReqs = snap.GetReqs
	phases.GetOpenTimeTotal = snap.GetOpenTimeTotal
	phases.GetTimeTotal = snap.GetTimeTotal
	phases.GetBytes = snap.GetBytes
	phases.PutReqs = snap.PutReqs
	phases.PutBytes = snap.PutBytes
	phases.PutTimeTotal = snap.PutTimeTotal
	phases.CompressTimeTotal = snap.CompressTimeTotal
	phases.ControlReqs = snap.ControlReqs
	phases.ControlTimeTotal = snap.ControlTimeTotal
	if timings != nil {
		phases.StateWall = timings.Publishing.Total + timings.Published.Total + timings.Failed.Total
	}
}

// failAttempt is the publish attempt's failure terminal: it persists the
// publish_failed record (with retry bookkeeping), records the failed
// state-write timing, and FINALIZES the attribution so failed attempts
// keep every stage wall and request counter observed so far — a fresh
// empty Result would erase exactly the evidence of where the attempt died.
func failAttempt(result *Result, counters *phaseCounters, state State, cause error) (Result, error) {
	state.State = StatePublishFailed
	state.LastError = cause.Error()
	// Backoff bookkeeping (M1): count the attempt and stamp it so the
	// scanner defers the retry by StateNextAttempt instead of hammering a
	// down store every round. Pre-M1 records had no Retries and retried
	// immediately; only failed attempts from now on carry the fields.
	state.Retries++
	now := time.Now().UTC()
	state.FailedAt = &now
	// The ATTEMPTED transition is reflected on the result BEFORE the state
	// write: if the failed-state write itself errors, the returned Result
	// still reports publish_failed (what was attempted), the write's
	// duration is kept in StateTimings.Failed (writeStateMeasured times
	// errors too), and the attempt's counters are frozen by RunWithOptions's
	// unified defer regardless of which return fires.
	result.State = state
	if result.StateTimings == nil {
		result.StateTimings = &StateTimings{}
	}
	if err := writeStateMeasured(state, &result.StateTimings.Failed); err != nil {
		return *result, err
	}
	return *result, cause
}
