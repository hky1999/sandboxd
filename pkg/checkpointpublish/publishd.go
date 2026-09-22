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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// ScanRoundOptions bounds one cn-publishd discovery-and-publish round and
// carries the persistence-lifecycle knobs (M1). Zero values keep the
// historical behavior except where a default is documented on the field.
type ScanRoundOptions struct {
	// Roots are the artifact roots to scan (comma-separated is split by the
	// caller or SplitRoots).
	Roots []string
	// Store is the chunk store publications target.
	Store chunkstore.Store
	// StoreName is the persisted store label written into publish states.
	StoreName string
	// Timeout bounds one artifact's publish attempt.
	Timeout time.Duration
	// CompressChunks passes through to RunWithOptions.
	CompressChunks bool

	// StaleAfter re-queues a "publishing" record older than this (crash
	// leftover; historical default 10m).
	StaleAfter time.Duration
	// BackoffBase/BackoffCap bound the exponential retry delay recorded on
	// publish_failed records: next attempt = base * 2^retries, capped.
	// Zero values disable delay (historical behavior: retry every round).
	BackoffBase time.Duration
	BackoffCap  time.Duration
	// StarveAfter promotes pending artifacts older than this to the front
	// (oldest first among them) so a newest-first queue cannot starve a
	// must-keep old artifact forever. Zero disables promotion.
	StarveAfter time.Duration
	// PriorityIDs names artifacts the operator (or migration controller)
	// is actively waiting on: they are published first, in the given
	// order, ahead of both starvation promotion and newest-first. This is
	// the durable "migration-waiting" priority entry — a plain CLI flag a
	// caller re-invokes with (or a supervisor restarts with), not a
	// test-only construct.
	PriorityIDs []string
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// ArtifactPhases is the per-artifact breakdown of the seal→remote_ready
// span as observed by the daemon: SealedAt is the manifest's mtime (the
// local_ready transition), DiscoveredAt the scan's observation, and
// PublishStart/End bound the attempt (reconcile probe + publish). QueueWait
// and DiscoveryLag are derived. Publish carries the attempt's attribution
// (walls + request counters; see PublishPhases). This is the publishd-side
// decomposition of T_remote; a CLI cn-publish wall time is a DIFFERENT span
// (no queue, no discovery) and must not be mixed with it.
type ArtifactPhases struct {
	ID            string        `json:"id"`
	SealedAt      time.Time     `json:"sealed_at"`
	DiscoveredAt  time.Time     `json:"discovered_at"`
	PublishStart  time.Time     `json:"publish_start"`
	PublishEnd    time.Time     `json:"publish_end"`
	DiscoveryLag  time.Duration `json:"discovery_lag"`
	QueueWait     time.Duration `json:"queue_wait"`
	PublishWall   time.Duration `json:"publish_wall"`
	SealToReady   time.Duration `json:"seal_to_ready"`
	Publish       PublishPhases `json:"publish"`
	Reconciled    bool          `json:"reconciled,omitempty"`
	RetriesBefore int           `json:"retries_before,omitempty"`
}

// RoundResult is the machine-readable summary of one scan round. It
// supersedes cmd/cn-publishd's roundOutcome (same fields, plus the M1
// lifecycle signals); Pending is the queue-depth gauge and
// UnpublishedBytes/OldestPendingAge are the backpressure observables.
type RoundResult struct {
	StartedAt        time.Time         `json:"started_at"`
	Duration         time.Duration     `json:"duration"`
	ScanWall         time.Duration     `json:"scan_wall"`
	Pending          int               `json:"pending"`
	Published        []string          `json:"published"`
	Skipped          int               `json:"skipped"`
	Reconciled       []string          `json:"reconciled,omitempty"`
	Deferred         map[string]string `json:"deferred,omitempty"` // id -> reason (backoff not due, etc.)
	Failed           map[string]string `json:"failed,omitempty"`
	UnpublishedBytes int64             `json:"unpublished_bytes"`
	OldestPendingAge time.Duration     `json:"oldest_pending_age,omitempty"`
	Phases           []ArtifactPhases  `json:"phases,omitempty"`
}

// pendingArtifact is one discovered work item.
type pendingArtifact struct {
	dir          string
	id           string
	created      time.Time // sealed transition (manifest mtime or state StartedAt)
	sealedAt     time.Time
	discoveredAt time.Time // the scan's observation instant (fixed at enqueue)
	retries      int       // prior failed attempts (from publish_failed state)
	foundInScan  bool
}

// SplitRoots splits a comma-separated root list.
func SplitRoots(list string) []string {
	return strings.Split(strings.ReplaceAll(list, " ", ""), ",")
}

// ScanRound walks the roots once, orders the pending set (starvation-aware),
// defers artifacts whose recorded backoff has not elapsed, and publishes (or
// reconciles) each. It is the testable core of cn-publishd; the CLI is a thin
// wrapper. Existing invariants are unchanged: published skips, young
// "publishing" records are a live concurrent publisher's, publication is
// idempotent and runs under the Run-level flock/intent protocol.
func ScanRound(ctx context.Context, opts ScanRoundOptions) RoundResult {
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	result := RoundResult{
		StartedAt: nowFn().UTC(),
		Failed:    map[string]string{},
		Deferred:  map[string]string{},
	}
	scanStart := nowFn()
	var pending []*pendingArtifact
	for _, root := range opts.Roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			result.Failed[root] = err.Error()
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				// Dot-prefixed directories are system namespaces (publish
				// state, materialization staging), never publish targets.
				continue
			}
			dir := filepath.Join(root, entry.Name())
			sealedAt, ok := sealedTimestamp(dir, entry)
			if !ok {
				continue
			}
			// Fix the discovery instant AT ENQUEUE time: it anchors
			// QueueWait, so it must be the scan's observation of this
			// artifact, not the later moment its turn comes up in the
			// publish loop (where the blocking by earlier artifacts would
			// otherwise be erased).
			discoveredAt := nowFn()
			state, err := Status(dir)
			if err != nil || state == nil {
				// Never published: an implicit local_ready. Persist the
				// queued record so the enqueue itself survives crashes and
				// is observable as a lifecycle state (M1).
				writeQueuedState(dir, entry.Name(), opts.StoreName, nowFn())
				pending = append(pending, &pendingArtifact{dir: dir, id: entry.Name(), created: sealedAt, sealedAt: sealedAt, discoveredAt: discoveredAt})
				continue
			}
			switch state.State {
			case StatePublished:
				result.Skipped++
			case StatePublishing:
				if nowFn().Sub(state.StartedAt) > opts.StaleAfter {
					pending = append(pending, &pendingArtifact{dir: dir, id: entry.Name(), created: state.StartedAt, sealedAt: sealedAt, discoveredAt: discoveredAt, retries: state.Retries})
				} else {
					result.Skipped++ // may belong to a live concurrent publisher
				}
			case StatePublishFailed:
				pending = append(pending, &pendingArtifact{dir: dir, id: entry.Name(), created: state.StartedAt, sealedAt: sealedAt, discoveredAt: discoveredAt, retries: state.Retries})
			case StateQueued:
				pending = append(pending, &pendingArtifact{dir: dir, id: entry.Name(), created: state.StartedAt, sealedAt: sealedAt, discoveredAt: discoveredAt, retries: state.Retries})
			}
		}
	}
	result.ScanWall = nowFn().Sub(scanStart).Round(time.Millisecond)

	// Ordering: explicit migration priority first (in caller order), then
	// starvation-aware promotion (old artifacts, oldest first), then the
	// newest-first default — ONE comparator so the phases cannot reshuffle
	// each other.
	priority := make(map[string]int, len(opts.PriorityIDs))
	for i, id := range opts.PriorityIDs {
		priority[id] = i
	}
	sortPendingMerged(pending, priority, opts.StarveAfter, nowFn)

	result.Pending = len(pending)
	for _, artifact := range pending {
		result.UnpublishedBytes += artifactBytes(artifact.dir)
		if age := nowFn().Sub(artifact.sealedAt); age > result.OldestPendingAge {
			result.OldestPendingAge = age
		}
	}

	for _, artifact := range pending {
		// Bounded backoff: a publish_failed record's next attempt is
		// base*2^retries after its last failure; not-yet-due artifacts are
		// deferred (still protected, still counted) rather than hammered.
		if opts.BackoffBase > 0 && artifact.retries > 0 {
			next := StateNextAttempt(artifact.retries, opts.BackoffBase, opts.BackoffCap)
			state, _ := Status(artifact.dir)
			if state != nil && state.FailedAt != nil && nowFn().Before(state.FailedAt.Add(next)) {
				result.Deferred[artifact.id] = fmt.Sprintf("backoff: next attempt at %s (retry #%d)", state.FailedAt.Add(next).UTC().Format(time.RFC3339), artifact.retries)
				continue
			}
		}
		phases := ArtifactPhases{ID: artifact.id, SealedAt: artifact.sealedAt, DiscoveredAt: artifact.discoveredAt, RetriesBefore: artifact.retries}
		phases.DiscoveryLag = phases.DiscoveredAt.Sub(phases.SealedAt).Round(time.Millisecond)
		// QueueWait measures the time this artifact spent blocked behind
		// earlier artifacts of the round: from the scan's discovery to the
		// moment it actually enters reconcile/publish. PublishStart is
		// fixed here, once, for BOTH paths — the reconcile branch must not
		// reset it to DiscoveredAt, which would erase exactly the blocking
		// being measured.
		phases.PublishStart = nowFn()
		phases.QueueWait = phases.PublishStart.Sub(phases.DiscoveredAt).Round(time.Millisecond)

		// ONE per-artifact deadline covers the whole attempt: the
		// reconciliation probe (remote INDEX/BUNDLE GETs and dependency
		// HEADs) runs BEFORE any upload and must not outlive the round's
		// own timeout budget — a hung store answering neither yes nor no
		// fails the attempt at the deadline instead of blocking the round.
		attemptCtx, cancelAttempt := ctx, context.CancelFunc(func() {})
		if opts.Timeout > 0 {
			attemptCtx, cancelAttempt = context.WithTimeout(ctx, opts.Timeout)
		}
		// Reconciliation probes are read-only; count their Has/HEAD
		// traffic into the phases so the converge path's attribution shows
		// probes with ZERO PUTs (it uploads nothing by construction).
		probeCounters := &phaseCounters{}
		probeStore := instrumentStore(opts.Store, probeCounters)
		reconciled, rerr := ReconcilePublished(attemptCtx, artifact.dir, artifact.id, probeStore, nowFn)

		// Crash-after-INDEX-commit reconciliation: if the remote already
		// holds THIS artifact's committed INDEX (identity-checked), converge
		// the local state to published without re-scanning or re-uploading.
		if reconciled {
			cancelAttempt()
			phases.Publish.HasReqs, phases.Publish.HasTimeTotal, phases.Publish.GetReqs, phases.Publish.GetOpenTimeTotal, phases.Publish.GetTimeTotal, phases.Publish.GetBytes = probeCounters.hasAndGet()
			phases.PublishEnd = nowFn()
			phases.Reconciled = true
			phases.PublishWall = phases.PublishEnd.Sub(phases.PublishStart).Round(time.Millisecond)
			phases.SealToReady = phases.PublishEnd.Sub(phases.SealedAt).Round(time.Millisecond)
			result.Reconciled = append(result.Reconciled, artifact.id)
			result.Phases = append(result.Phases, phases)
			continue
		} else if rerr != nil {
			// A store that cannot answer the reconciliation probe cannot
			// host a provable remote_ready either; treat as a normal
			// publish attempt, which will surface the store error.
			_ = rerr
		}

		runRes, err := RunWithOptions(attemptCtx, artifact.dir, artifact.id, opts.Store, opts.StoreName, Options{CompressChunks: opts.CompressChunks})
		cancelAttempt()
		if runRes.Phases != nil {
			phases.Publish = *runRes.Phases
		}
		// Merge the reconcile probe traffic either way (fall-through
		// attempts repeat the INDEX GET but upload nothing while failing).
		if hasReqs, hasTotal, getReqs, getOpenTotal, getTotal, getBytes := probeCounters.hasAndGet(); hasReqs+getReqs > 0 {
			phases.Publish.HasReqs += hasReqs
			phases.Publish.HasTimeTotal += hasTotal
			phases.Publish.GetReqs += getReqs
			phases.Publish.GetOpenTimeTotal += getOpenTotal
			phases.Publish.GetTimeTotal += getTotal
			phases.Publish.GetBytes += getBytes
		}
		phases.PublishEnd = nowFn()
		phases.PublishWall = phases.PublishEnd.Sub(phases.PublishStart).Round(time.Millisecond)
		phases.SealToReady = phases.PublishEnd.Sub(phases.SealedAt).Round(time.Millisecond)
		if err != nil {
			result.Failed[artifact.id] = err.Error()
			// Failed attempts keep their attribution: the phases observed
			// so far are exactly the evidence of where the attempt died.
			result.Phases = append(result.Phases, phases)
			continue
		}
		result.Published = append(result.Published, artifact.id)
		result.Phases = append(result.Phases, phases)
	}
	// Recompute the queue gauges from the post-round state so the metrics
	// reflect the CURRENT backlog, not a stale snapshot from scan time: a
	// fully drained round reports 0 pending/bytes/age on the gauges; a
	// partial round (failures, deferrals) retains the real residue. The
	// per-item counts (Published/Failed/Deferred) remain this round's
	// outcome counters.
	remaining := SnapshotBackpressure(opts.Roots, BackpressureLimits{}, nowFn)
	result.Pending = remaining.Pending
	result.UnpublishedBytes = remaining.UnpublishedBytes
	result.OldestPendingAge = remaining.OldestPendingAge
	result.Duration = nowFn().Sub(result.StartedAt).Round(time.Millisecond)
	return result
}

// sealedTimestamp reports the directory's seal instant (manifest mtime) —
// the local_ready transition — and whether the directory is a sealed
// artifact at all.
func sealedTimestamp(dir string, entry os.DirEntry) (time.Time, bool) {
	info, err := os.Stat(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

// writeQueuedState persists the enqueue (queued) so a crash between
// discovery and publish leaves an explicit lifecycle record instead of an
// implicit no-state directory. Failures are non-fatal: the historical
// no-state discovery path still finds the artifact next round.
func writeQueuedState(dir, id, storeName string, now time.Time) {
	state := State{
		CheckpointID: id,
		Dir:          dir,
		State:        StateQueued,
		Store:        storeName,
		StartedAt:    now.UTC(),
	}
	_ = writeState(state)
}

// sortPendingMerged orders the queue with ONE comparator: explicit
// migration priority first (caller order), then starvation-promoted old
// artifacts (oldest first), then newest-first. The old two-pass
// prioritize+sort had a bug where sortPending's comparator was unaware of
// priority and could reshuffle explicitly-prioritized items.
func sortPendingMerged(pending []*pendingArtifact, priority map[string]int, starveAfter time.Duration, now func() time.Time) {
	sort.SliceStable(pending, func(i, j int) bool {
		pi, pj := pending[i], pending[j]
		ri, oki := priority[pi.id]
		rj, okj := priority[pj.id]
		if oki != okj {
			return oki // explicit priority always first
		}
		if oki && okj {
			return ri < rj // among priority: caller order
		}
		iOld := starveAfter > 0 && now().Sub(pi.sealedAt) > starveAfter
		jOld := starveAfter > 0 && now().Sub(pj.sealedAt) > starveAfter
		if iOld != jOld {
			return iOld // promoted artifacts sort first
		}
		if iOld && jOld {
			return pi.sealedAt.Before(pj.sealedAt) // among promoted: oldest first
		}
		return pi.created.After(pj.created) // default: newest first
	})
}

// artifactBytes is the on-disk size of the unpublished artifact (the
// unique-copy bytes the backpressure budget must account for).
func artifactBytes(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, ierr := d.Info(); ierr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// MarshalRound renders a RoundResult as indented JSON (CLI -json output).
func MarshalRound(r RoundResult) string {
	encoded, _ := json.MarshalIndent(r, "", "  ")
	return string(encoded)
}
