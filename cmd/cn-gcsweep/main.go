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

// Command cn-gcsweep reclaims unreferenced objects from a checkpoint
// chunk store served over the anonymous S3 REST subset (MinIO public
// bucket, the same endpoint cn-publish/cn-fetch use).
//
// Content-addressed chunk objects are SHARED across artifacts and
// generations, so they cannot expire by age. The sweep is reference
// counting instead: every surviving artifact's INDEX (and the sidecars it
// names, bundle or per-file) contributes the exact set of live keys —
// plain and .z chunk objects, memory packs, overlay chunks — and only
// objects referenced by NO surviving artifact are deletion candidates,
// additionally guarded by -min-age so chunks of an in-flight publication
// (objects land before their INDEX) are never caught mid-publish.
//
// Deletion itself is MARK-THEN-SWEEP: a candidate is recorded as a
// gc-marks/<key> object and collected only once that mark has aged past
// -mark-grace. min-age alone cannot make a single-pass delete safe: a
// publisher that reuses an OLD object (a Has hit — unchanged chunks are
// skipped, never re-uploaded) publishes no young bytes for the sweep to
// spare, and its INDEX lands last. The grace window plus two coordinated
// checks close that race: publishers probe the mark at every Has-hit
// reuse and refresh the object instead of skipping (checkpointpublish's
// gc fence), and the sweep re-lists the bucket immediately before
// deleting — an object that vanished, was refreshed, or is referenced by
// an artifact set that appeared mid-sweep is spared and its mark cleared.
//
// Artifact SETS (artifacts/<id>/*) are ID-named and exclusive, so they
// may age out wholesale: -max-artifact-age drops sets whose INDEX is
// older than the bound, -drop names IDs explicitly. Dropping an artifact
// removes its objects and stops its chunks from counting as references —
// a chunk dies only when its LAST referencing artifact is gone. A dropped
// set whose INDEX appeared or changed since the listing is spared for a
// later run (a publication committed under that ID mid-sweep).
//
// The tool is fail-closed: if any surviving artifact's INDEX or sidecar
// cannot be fetched and decoded, NOTHING is deleted, because the live set
// cannot be proven. Objects with unrecognized key shapes are never
// touched. Deletion requires -delete; without it the run reports only
// and writes nothing — no marks either.
//
//	cn-gcsweep -store http://172.18.0.1:19000/cn-chunks            # report
//	cn-gcsweep -store ... -delete -max-artifact-age 168h -min-age 24h  # marks
//	cn-gcsweep -store ... -delete ... -mark-grace 0                 # also collect
//
// Exit codes: 0 report/deletion ran, 1 error, 2 usage.
package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

type objectInfo struct {
	Key      string
	Size     int64
	Modified time.Time
}

type sweepReport struct {
	Store              string `json:"store"`
	ObjectsTotal       int    `json:"objects_total"`
	BytesTotal         int64  `json:"bytes_total"`
	ArtifactsKept      int    `json:"artifacts_kept"`
	ArtifactsDropped   int    `json:"artifacts_dropped"`
	ArtifactsIndexless int    `json:"artifacts_indexless"`
	ChunkObjectsLive   int    `json:"chunk_objects_live"`
	ChunkObjectsDead   int    `json:"chunk_objects_dead"`
	DeadYoung          int    `json:"dead_young"`     // unreferenced but younger than min-age
	ForeignKept        int    `json:"foreign_kept"`   // unrecognized key shapes
	MarksTracked       int    `json:"marks_tracked"`  // sweep marks present before this run
	MarksCreated       int    `json:"marks_created"`  // victims marked this run (dry-run: would mark)
	WaitGrace          int    `json:"wait_grace"`     // victims whose mark has not aged past mark-grace
	RaceSpared         int    `json:"race_spared"`    // stale-mark candidates spared by the delete-time recheck
	ClaimsSpared       int    `json:"claims_spared"`  // candidates skipped: a fenced publisher holds the claim
	ClaimsCleared      int    `json:"claims_cleared"` // stale claims removed
	MarksCleared       int    `json:"marks_cleared"`  // obsolete marks removed (object gone/refreshed/referenced)
	NewArtifacts       int    `json:"new_artifacts"`  // artifact sets that appeared mid-sweep (refs merged)
	Deletions          int    `json:"deletions"`
	DeletionBytes      int64  `json:"deletion_bytes"`
	DeleteErrors       int    `json:"delete_errors"`
	DryRun             bool   `json:"dry_run"`
}

func main() {
	storeSpec := flag.String("store", "", "chunk store endpoint (http(s):// URL of the bucket root)")
	del := flag.Bool("delete", false, "actually delete (default is a dry-run report)")
	maxArtifactAge := flag.Duration("max-artifact-age", 0, "drop artifact sets whose INDEX is older (0 keeps all)")
	drop := flag.String("drop", "", "comma-separated artifact IDs to drop regardless of age")
	minAge := flag.Duration("min-age", 24*time.Hour, "never delete unreferenced chunk/pack/overlay objects younger than this (in-flight publish guard)")
	markGrace := flag.Duration("mark-grace", 24*time.Hour, "a deletion candidate is collected only once its sweep mark is older than this (concurrent-reuse fence; keep >= the longest publish)")
	workers := flag.Int("workers", 8, "concurrent INDEX/sidecar fetches")
	jsonOut := flag.Bool("json", false, "machine-readable report")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-gcsweep -store URL [-delete] [-max-artifact-age 168h] [-drop ID,ID] [-min-age 24h] [-mark-grace 24h]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *storeSpec == "" || *minAge < 0 || *maxArtifactAge < 0 || *markGrace < 0 || *workers < 1 || *workers > 64 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(context.Background(), *storeSpec, *del, *maxArtifactAge, strings.Split(*drop, ","), *minAge, *markGrace, *workers, *jsonOut); err != nil {
		fmt.Fprintf(os.Stderr, "gcsweep: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, spec string, del bool, maxArtifactAge time.Duration, dropIDs []string, minAge, markGrace time.Duration, workers int, jsonOut bool) error {
	if !strings.HasPrefix(spec, "http://") && !strings.HasPrefix(spec, "https://") {
		return fmt.Errorf("cn-gcsweep sweeps HTTP stores; use cn-gc for local caches")
	}
	base := strings.TrimRight(spec, "/")
	client := &http.Client{Timeout: 120 * time.Second}
	objects, err := listAll(ctx, client, base)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	dropped := make(map[string]bool)
	for _, id := range dropIDs {
		if id = strings.TrimSpace(id); id != "" {
			dropped[id] = true
		}
	}

	// Partition: artifacts/<id>/<file> vs sweep marks vs everything else.
	// Marks are sweep bookkeeping, not payload: they are counted separately
	// and never join the object totals.
	type artifactSet struct {
		objects  []objectInfo
		indexAt  time.Time
		hasIndex bool
	}
	artifacts := make(map[string]*artifactSet)
	var chunkish []objectInfo
	marks := make(map[string]time.Time)  // swept object key -> marking instant
	claims := make(map[string]time.Time) // swept object key -> claim creation instant
	report := sweepReport{Store: spec, DryRun: !del}
	for _, o := range objects {
		if victim, ok := strings.CutPrefix(o.Key, checkpointpublish.GCMarkNamespace+"/"); ok && victim != "" {
			marks[victim] = o.Modified
			continue
		}
		if owner, ok := strings.CutPrefix(o.Key, checkpointpublish.GCClaimNamespace+"/"); ok && owner != "" {
			claims[owner] = o.Modified
			continue
		}
		report.ObjectsTotal++
		report.BytesTotal += o.Size
		if id, ok := artifactIDOfKey(o.Key); ok {
			set := artifacts[id]
			if set == nil {
				set = &artifactSet{}
				artifacts[id] = set
			}
			set.objects = append(set.objects, o)
			if strings.HasSuffix(o.Key, "/"+checkpointpublish.IndexName) {
				set.hasIndex = true
				set.indexAt = o.Modified
			}
			continue
		}
		chunkish = append(chunkish, o)
	}
	report.MarksTracked = len(marks)

	// Resolve references of every KEPT artifact. Fail-closed: one
	// unresolvable manifest aborts the whole sweep.
	type refJob struct {
		id  string
		set *artifactSet
	}
	jobs := make(chan refJob)
	refs := make(map[string]struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup
	var resolveErr error
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				live, err := artifactReferences(ctx, client, base, job.id)
				if err != nil {
					mu.Lock()
					if resolveErr == nil {
						resolveErr = fmt.Errorf("artifact %s: %w", job.id, err)
					}
					mu.Unlock()
					continue
				}
				mu.Lock()
				for key := range live {
					refs[key] = struct{}{}
				}
				mu.Unlock()
			}
		}()
	}
	now := time.Now()
	var dropObjects []objectInfo
	for id, set := range artifacts {
		switch {
		case dropped[id]:
			report.ArtifactsDropped++
			dropObjects = append(dropObjects, set.objects...)
		case !set.hasIndex:
			// Objects without an INDEX are partial publications (INDEX
			// lands last): keep them and count them; young orphan chunks
			// are separately guarded by min-age.
			report.ArtifactsIndexless++
		case maxArtifactAge > 0 && now.Sub(set.indexAt) > maxArtifactAge:
			report.ArtifactsDropped++
			dropObjects = append(dropObjects, set.objects...)
		default:
			report.ArtifactsKept++
			jobs <- refJob{id: id, set: set}
		}
	}
	close(jobs)
	wg.Wait()
	if resolveErr != nil {
		return fmt.Errorf("live set unprovable, nothing deleted: %w", resolveErr)
	}

	// Classify non-artifact objects against the live set.
	chunkKey := regexp.MustCompile(`^[0-9a-f]{2}/[0-9a-f]{64}(\.z)?$`)
	overlayKey := regexp.MustCompile(`^overlay-chunks/[0-9a-f]{2}/[0-9a-f]{64}$`)
	packKey := regexp.MustCompile(`^(memory-packs|memory-chunk-packs-v1)/[0-9a-f]{64}$`)
	var victims []objectInfo
	for _, o := range chunkish {
		shape := chunkKey.MatchString(o.Key) || overlayKey.MatchString(o.Key) || packKey.MatchString(o.Key)
		if !shape {
			report.ForeignKept++
			continue
		}
		if _, live := refs[o.Key]; live {
			report.ChunkObjectsLive++
			continue
		}
		report.ChunkObjectsDead++
		if now.Sub(o.Modified) < minAge {
			report.DeadYoung++
			continue
		}
		victims = append(victims, o)
	}

	// Mark-then-sweep: a victim is never deleted in the run that found it.
	// It is recorded as gc-marks/<key> and becomes collectable only once the
	// mark has aged past -mark-grace. The grace window is the
	// concurrent-publish fence: a publisher that leans on an existing object
	// (a Has hit — min-age cannot protect this, the object is old by
	// construction) probes the mark at reuse time and refreshes the object
	// instead of skipping the upload, and a publication that commits during
	// the window appears as a new artifact set whose references the
	// delete-time recheck merges. An existing mark keeps its original
	// timestamp: rewriting it would reset the grace and let an unlucky
	// object cycle marks forever.
	victimSet := make(map[string]struct{}, len(victims))
	for _, o := range victims {
		victimSet[o.Key] = struct{}{}
		if _, marked := marks[o.Key]; marked {
			continue
		}
		if del {
			if err := putMark(ctx, client, base, o.Key, now); err != nil {
				return fmt.Errorf("mark %s: %w", o.Key, err)
			}
			marks[o.Key] = now
		}
		report.MarksCreated++
	}
	type candidate struct {
		key  string
		size int64
	}
	var candidates []candidate
	for _, o := range victims {
		if marked, ok := marks[o.Key]; ok && now.Sub(marked) >= markGrace {
			candidates = append(candidates, candidate{key: o.Key, size: o.Size})
		} else {
			report.WaitGrace++
		}
	}

	// Delete-time recheck. Everything is re-verified against a fresh
	// listing: objects that vanished, were refreshed (a publisher's fence
	// re-uploaded them), or became referenced — including through artifact
	// sets that appeared while this sweep ran — are spared and their marks
	// cleared. Artifact-set objects dropped by age or -drop stay immediate
	// and ID-exclusive, but a set whose INDEX changed since the listing is
	// spared wholesale: something re-published under that ID mid-sweep.
	freshObjects := map[string]objectInfo{}
	freshIndexAt := map[string]time.Time{}
	if del && (len(candidates) > 0 || len(dropObjects) > 0) {
		// Deletion requires conditional writes: every candidate is taken
		// under an exclusive gc-claims/<key> create, which is the only way
		// to close the window between this relisting and the DELETE — a
		// publisher refreshing an object and committing its INDEX inside
		// that window holds the claim first, and the claim attempt below
		// fails closed. A store that does not honor If-None-Match refuses
		// the whole run before anything is deleted.
		if err := preflightConditionalWrites(ctx, client, base); err != nil {
			return fmt.Errorf("store unusable for safe deletion: %w", err)
		}
		fresh, err := listAll(ctx, client, base)
		if err != nil {
			return fmt.Errorf("relist before delete: %w", err)
		}
		for _, o := range fresh {
			if victim, ok := strings.CutPrefix(o.Key, checkpointpublish.GCMarkNamespace+"/"); ok && victim != "" {
				continue
			}
			if owner, ok := strings.CutPrefix(o.Key, checkpointpublish.GCClaimNamespace+"/"); ok && owner != "" {
				continue
			}
			freshObjects[o.Key] = o
			if id, ok := artifactIDOfKey(o.Key); ok && strings.HasSuffix(o.Key, "/"+checkpointpublish.IndexName) {
				freshIndexAt[id] = o.Modified
			}
		}
		for id := range freshIndexAt {
			set, seen := artifacts[id]
			if seen && (set.hasIndex && freshIndexAt[id].Equal(set.indexAt)) {
				continue
			}
			// A set that appeared (or had its INDEX rewritten) after the
			// scan: its references were invisible to the live set above.
			live, err := artifactReferences(ctx, client, base, id)
			if err != nil {
				return fmt.Errorf("live set unprovable after concurrent publication, nothing deleted: artifact %s: %w", id, err)
			}
			for key := range live {
				refs[key] = struct{}{}
			}
			report.NewArtifacts++
		}
	}
	deleteObject := func(key string) bool {
		return deleteKey(ctx, client, base, key) == nil
	}
	clearMark := func(key string) {
		if err := deleteKey(ctx, client, base, checkpointpublish.GCMarkKey(key)); err != nil {
			report.DeleteErrors++
			return
		}
		report.MarksCleared++
	}
	// Deletion runs in three phases, per the claim-first discipline: protect
	// first, re-derive the basis under the protection, then act.
	claimNonce := sweepClaimBody()
	type owned struct {
		key  string
		size int64
	}
	report.Deletions += len(candidates)
	for _, c := range candidates {
		report.DeletionBytes += c.size
	}
	var held []owned
	for _, c := range candidates {
		if !del {
			break
		}
		// Phase 1 — win the exclusive claim BEFORE acting: every writer that
		// can make this object matter again (fenced re-upload, Has-miss
		// recreate) contends for the same atomic create, so a 412 here means
		// the object is spoken for regardless of what any earlier
		// observation said.
		created, cerr := putClaimIfAbsent(ctx, client, base, c.key, claimNonce)
		if cerr != nil {
			// Fail closed mid-batch: release what this run holds.
			for _, o := range held {
				releaseClaimIfMine(ctx, client, base, o.key, claimNonce)
			}
			return fmt.Errorf("claim %s: %w", c.key, cerr)
		}
		if created {
			held = append(held, owned{key: c.key, size: c.size})
		} else {
			report.ClaimsSpared++
		}
	}
	if del && len(held) > 0 {
		// Phase 2 — re-derive the reference basis UNDER the claims: the
		// relisting's reference set is stale by construction, and a
		// publication that committed since then must spare its objects even
		// when min-age is disabled. One fresh listing; only sets that
		// appeared or changed get their references resolved.
		fresh, err := listAll(ctx, client, base)
		if err != nil {
			for _, o := range held {
				releaseClaimIfMine(ctx, client, base, o.key, claimNonce)
			}
			return fmt.Errorf("relist references under claims: %w", err)
		}
		freshIndexAt := map[string]time.Time{}
		for _, o := range fresh {
			if id, ok := artifactIDOfKey(o.Key); ok && strings.HasSuffix(o.Key, "/"+checkpointpublish.IndexName) {
				freshIndexAt[id] = o.Modified
			}
		}
		for id, indexAt := range freshIndexAt {
			set, seen := artifacts[id]
			if seen && (set.hasIndex && indexAt.Equal(set.indexAt)) {
				continue
			}
			live, err := artifactReferences(ctx, client, base, id)
			if err != nil {
				for _, o := range held {
					releaseClaimIfMine(ctx, client, base, o.key, claimNonce)
				}
				return fmt.Errorf("live set unprovable under claims, nothing deleted: artifact %s: %w", id, err)
			}
			for key := range live {
				refs[key] = struct{}{}
			}
			report.NewArtifacts++
		}
		// Phase 3 — verdicts from FRESH observations only: the object's
		// current mtime (any recreate/refresh is visible) and the re-derived
		// reference set. The cached relisting decides nothing anymore.
		for _, o := range held {
			mod, exists, herr := headObjectModified(ctx, client, base, o.key)
			_, live := refs[o.key]
			switch {
			case herr != nil:
				report.DeleteErrors++
			case !exists:
				// The object vanished (another sweeper, an operator): the
				// mark is obsolete either way.
				clearMark(o.key)
			case time.Since(mod) < minAge:
				// Freshly (re-)written while this sweep ran: a fenced
				// publisher or a Has-miss recreate. No longer at risk; drop
				// the mark and let a later sweep re-evaluate.
				report.RaceSpared++
				clearMark(o.key)
			case live:
				// Referenced by an artifact INDEX — including one that
				// committed while this sweep ran.
				report.RaceSpared++
				clearMark(o.key)
			case !deleteObject(o.key):
				report.DeleteErrors++
			default:
				clearMark(o.key)
			}
			releaseClaimIfMine(ctx, client, base, o.key, claimNonce)
		}
	}
	for _, o := range dropObjects {
		report.Deletions++
		report.DeletionBytes += o.Size
		if !del {
			continue
		}
		if id, ok := artifactIDOfKey(o.Key); ok {
			if indexAt, has := freshIndexAt[id]; has {
				if set, seen := artifacts[id]; !seen || !set.hasIndex || !indexAt.Equal(set.indexAt) {
					// The INDEX appeared or changed since the listing: a
					// publication committed under this ID mid-sweep.
					report.RaceSpared++
					continue
				}
			}
		}
		if !deleteObject(o.Key) {
			report.DeleteErrors++
		}
	}
	// Obsolete marks: the underlying key is no longer a victim (became
	// referenced, or the object is gone). Leaving them would fence reuse
	// forever on the publisher side.
	if del {
		for key := range marks {
			if _, still := victimSet[key]; still {
				continue
			}
			clearMark(key)
		}
	}
	// Stale claims: a publisher's claim outlives the publish it protected
	// only when the publisher died mid-fence. Past the mark grace — the
	// same bound that covers the longest legitimate publish — it protects
	// nothing a later run cannot re-derive; clear it, but only the exact
	// generation observed NOW: fetch the claim fresh, require it to still
	// be grace-old, and bind the delete to its ETag so a claim another
	// participant created in the meantime survives (a fixed body would be
	// no credential; every owner mints a unique nonce).
	if del {
		for key := range claims {
			claimKey := checkpointpublish.GCClaimKey(key)
			etag, modified, err := headClaim(ctx, client, base, claimKey)
			if err != nil {
				report.DeleteErrors++
				continue
			}
			if now.Sub(modified) < markGrace {
				continue
			}
			if deleteClaimIfMatch(ctx, client, base, claimKey, etag) {
				report.ClaimsCleared++
			}
			// 412: the claim was replaced by a live participant — leave it.
		}
	}

	if jsonOut {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Printf("gcsweep: store=%s objects=%d (%dMiB) artifacts kept/dropped/indexless=%d/%d/%d "+
			"chunk-objects live/dead/young/foreign=%d/%d/%d/%d "+
			"marks tracked/created/wait-grace=%d/%d/%d spared/cleared/new-artifacts=%d/%d/%d "+
			"reclaim %d objects (%dMiB) errors=%d dry-run=%v\n",
			spec, report.ObjectsTotal, report.BytesTotal>>20,
			report.ArtifactsKept, report.ArtifactsDropped, report.ArtifactsIndexless,
			report.ChunkObjectsLive, report.ChunkObjectsDead, report.DeadYoung, report.ForeignKept,
			report.MarksTracked, report.MarksCreated, report.WaitGrace,
			report.RaceSpared, report.MarksCleared, report.NewArtifacts,
			report.Deletions, report.DeletionBytes>>20, report.DeleteErrors, report.DryRun)
	}
	return nil
}

// artifactIDOfKey reports the checkpoint ID for artifacts/<id>/<file>
// keys, rejecting path escapes.
func artifactIDOfKey(key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, checkpointpublish.ArtifactNamespace+"/")
	if !ok || !strings.Contains(rest, "/") {
		return "", false
	}
	id := rest[:strings.IndexByte(rest, '/')]
	if id == "" || strings.ContainsAny(id, "/.") {
		return "", false
	}
	return id, true
}

// artifactReferences returns every store key a published artifact needs
// to stay restorable: its memory sidecar's chunk objects (both plain and
// compressed forms), the packs it maps chunks into, and its overlay
// chunks. INDEX and artifact-set objects of the ID namespace are handled
// by the caller (they live or die with the artifact).
func artifactReferences(ctx context.Context, client *http.Client, base, id string) (map[string]struct{}, error) {
	refs := make(map[string]struct{})
	raw, err := getObject(ctx, client, base, checkpointpublish.ArtifactKey(id, checkpointpublish.IndexName))
	if err != nil {
		return nil, fmt.Errorf("fetch INDEX: %w", err)
	}
	var index checkpointpublish.ArtifactIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("decode INDEX: %w", err)
	}
	sidecars := []string{checkpointchunks.ManifestName}
	if index.OverlayChunks {
		sidecars = append(sidecars, checkpointpublish.OverlaySidecarName)
	}
	for _, name := range sidecars {
		raw, err := artifactFile(ctx, client, base, id, &index, name)
		if err != nil {
			return nil, fmt.Errorf("fetch sidecar %s: %w", name, err)
		}
		m, err := checkpointchunks.DecodeTransport(raw)
		if err != nil {
			return nil, fmt.Errorf("decode sidecar %s: %w", name, err)
		}
		// Overlay chunks live in their own global namespace
		// (overlay-chunks/<aa>/<digest>) and are never uploaded compressed
		// or packed: registering the memory-style key for them would leave
		// every live overlay object unreferenced, turning surviving blocks
		// into deletion candidates the moment they age past min-age.
		overlay := name == checkpointpublish.OverlaySidecarName
		for _, entry := range m.Entries {
			if overlay {
				refs[checkpointpublish.OverlayChunkKey(entry.Digest)] = struct{}{}
				continue
			}
			refs[entry.Digest[:2]+"/"+entry.Digest] = struct{}{}
			refs[chunkstore.CompressedKey(entry.Digest)] = struct{}{}
		}
		if name == checkpointchunks.ManifestName {
			for _, ref := range m.Packs {
				key, err := ref.Key()
				if err != nil {
					return nil, fmt.Errorf("pack reference: %w", err)
				}
				refs[key] = struct{}{}
			}
		}
	}
	return refs, nil
}

// artifactFile returns one artifact-set file's bytes, from the bundle
// object when the INDEX advertises one or the per-file object otherwise.
func artifactFile(ctx context.Context, client *http.Client, base, id string, index *checkpointpublish.ArtifactIndex, name string) ([]byte, error) {
	if index.Bundle == nil {
		return getObject(ctx, client, base, checkpointpublish.ArtifactKey(id, name))
	}
	bundle, err := getObject(ctx, client, base, checkpointpublish.ArtifactKey(id, checkpointpublish.BundleName))
	if err != nil {
		return nil, err
	}
	for _, part := range index.Bundle.Parts {
		if part.Name != name {
			continue
		}
		if part.Offset < 8 || part.Offset+part.Length > int64(len(bundle)) {
			return nil, fmt.Errorf("bundle part %s span out of range", name)
		}
		return bundle[part.Offset : part.Offset+part.Length], nil
	}
	return nil, fmt.Errorf("bundle has no part %s", name)
}

func getObject(ctx context.Context, client *http.Client, base, key string) ([]byte, error) {
	resp, err := client.Do(mustRequest(ctx, http.MethodGet, base+"/"+key))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", key, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, checkpointchunks.MaxManifestBytes+1<<20))
}

// putMark records a deletion candidate: a small object whose store
// modification time is the marking instant (the body repeats it for
// operators reading the bucket by hand). Publishers probe marks at Has-hit
// reuse and refresh the object instead of leaning on it; the sweep collects
// only marks older than the grace and re-verifies everything at delete time.
func putMark(ctx context.Context, client *http.Client, base, key string, at time.Time) error {
	body := strings.NewReader(at.UTC().Format(time.RFC3339Nano))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/"+checkpointpublish.GCMarkKey(key), body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("PUT mark %s: status %d", key, resp.StatusCode)
	}
	return nil
}

// sweepClaimBody is this run's unique owner token: the generation every
// release and cleanup of this run's claims must match. A fixed string is
// not a credential — a replacement claim by another participant must never
// be deletable through an older observation.
func sweepClaimBody() string {
	return "sweep-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" +
		strconv.FormatInt(int64(os.Getpid()), 36)
}

func bodyETag(body string) string {
	sum := md5.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

// putClaimIfAbsent atomically creates the exclusive claim for key (S3
// conditional write If-None-Match:*), verifying by read-back that the store
// honored the condition — a store that ignores the header answers 200 for
// an overwrite too, which would make the mutual exclusion fiction.
func putClaimIfAbsent(ctx context.Context, client *http.Client, base, key, body string) (bool, error) {
	claimKey := checkpointpublish.GCClaimKey(key)
	url := base + "/" + claimKey
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("If-None-Match", "*")
	req.ContentLength = int64(len(body))
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusPreconditionFailed:
		return false, nil
	case http.StatusOK, http.StatusNoContent:
		// Read the claim back: only a genuinely conditional create can be
		// trusted to have excluded every other writer.
		got, err := getObject(ctx, client, base, claimKey)
		if err != nil {
			return false, fmt.Errorf("verify claim %s: %w", key, err)
		}
		if string(got) != body {
			return false, fmt.Errorf("store does not honor If-None-Match on %s: claim was overwritten", claimKey)
		}
		return true, nil
	default:
		return false, fmt.Errorf("conditional PUT claim %s: status %d", key, resp.StatusCode)
	}
}

// releaseClaimIfMine drops a claim this run created, and only this
// generation: the conditional delete (If-Match on the claim body's ETag)
// answers 412 when another participant already replaced the claim, which is
// the desired outcome — their protection must survive our release.
func releaseClaimIfMine(ctx context.Context, client *http.Client, base, key, body string) {
	deleteClaimIfMatch(ctx, client, base, checkpointpublish.GCClaimKey(key), bodyETag(body))
}

// deleteClaimIfMatch removes a claim only while it still carries the
// observed generation (S3 conditional DELETE If-Match).
func deleteClaimIfMatch(ctx context.Context, client *http.Client, base, claimKey, etag string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/"+claimKey, nil)
	if err != nil {
		return false
	}
	req.Header.Set("If-Match", etag)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return true
	default: // 412 replaced, 404 gone: nothing of that generation remains
		return false
	}
}

// headObjectModified returns the object's CURRENT modification time (and
// existence) — the fresh observation verdicts are re-derived from after the
// claim is won, never from the cached relisting.
func headObjectModified(ctx context.Context, client *http.Client, base, key string) (time.Time, bool, error) {
	resp, err := client.Do(mustRequest(ctx, http.MethodHead, base+"/"+key))
	if err != nil {
		return time.Time{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return time.Time{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, false, fmt.Errorf("HEAD %s: status %d", key, resp.StatusCode)
	}
	mod, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		return time.Time{}, true, fmt.Errorf("HEAD %s: bad Last-Modified %q", key, resp.Header.Get("Last-Modified"))
	}
	return mod, true, nil
}

// preflightConditionalWrites proves the store supports create-only PUTs
// before any deletion happens: create a probe claim, then lose to it. A
// store that lets the second writer win disables the whole deletion path.
func preflightConditionalWrites(ctx context.Context, client *http.Client, base string) error {
	probe := checkpointpublish.GCClaimKey(".preflight-" + strconv.FormatInt(time.Now().UnixNano(), 10))
	url := base + "/" + probe
	first, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader("first"))
	if err != nil {
		return err
	}
	first.Header.Set("If-None-Match", "*")
	first.ContentLength = 5
	resp, err := client.Do(first)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("preflight claim: status %d", resp.StatusCode)
	}
	second, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader("second"))
	if err != nil {
		return err
	}
	second.Header.Set("If-None-Match", "*")
	second.ContentLength = 6
	resp2, err := client.Do(second)
	if err != nil {
		return err
	}
	resp2.Body.Close()
	defer deleteKey(ctx, client, base, probe)
	if resp2.StatusCode != http.StatusPreconditionFailed {
		return fmt.Errorf("conditional writes not honored (second create answered %d, want 412)", resp2.StatusCode)
	}
	// Conditional DELETE (If-Match) is opportunistic, not required: stores
	// that honor it get an atomic confirm→delete for claim cleanup, and
	// stores that ignore the header degrade to a plain delete whose safety
	// is carried by the fresh observation — the cleanup re-GETs the claim
	// and requires it to STILL be grace-old, and a grace-old claim has no
	// live releaser inside the documented publish/grace bound (live owners
	// release within milliseconds of claiming). The residual is exactly the
	// long-publish boundary the contract already states.
	_ = deleteKey(ctx, client, base, probe)
	return nil
}

// headClaim fetches a claim's current ETag and modification time — the
// fresh generation observation the stale cleanup binds its delete to.
func headClaim(ctx context.Context, client *http.Client, base, claimKey string) (etag string, modified time.Time, err error) {
	resp, err := client.Do(mustRequest(ctx, http.MethodGet, base+"/"+claimKey))
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("GET claim: status %d", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return "", time.Time{}, err
	}
	mod, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("GET claim: bad Last-Modified")
	}
	return strings.Trim(resp.Header.Get("ETag"), `"`), mod, nil
}

// deleteKey removes one object (a collected victim, an obsolete mark, or a
// dropped artifact-set file). A missing object is success: sweeps are
// idempotent and a concurrent sweeper may have won.
func deleteKey(ctx context.Context, client *http.Client, base, key string) error {
	resp, err := client.Do(mustRequest(ctx, http.MethodDelete, base+"/"+key))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("DELETE %s: status %d", key, resp.StatusCode)
	}
	return nil
}

func mustRequest(ctx context.Context, method, url string) *http.Request {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		panic(err)
	}
	return req
}

// listAll paginates ListObjectsV2 over the anonymous S3 subset.
func listAll(ctx context.Context, client *http.Client, base string) ([]objectInfo, error) {
	var out []objectInfo
	token := ""
	for {
		q := url.Values{"list-type": {"2"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := client.Do(mustRequest(ctx, http.MethodGet, base+"?"+q.Encode()))
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list: status %d", resp.StatusCode)
		}
		var page struct {
			XMLName     xml.Name `xml:"ListBucketResult"`
			IsTruncated bool     `xml:"IsTruncated"`
			NextToken   string   `xml:"NextContinuationToken"`
			Contents    []struct {
				Key      string `xml:"Key"`
				Size     int64  `xml:"Size"`
				Modified string `xml:"LastModified"`
			} `xml:"Contents"`
		}
		if err := xml.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		for _, c := range page.Contents {
			mod, _ := time.Parse(time.RFC3339, c.Modified)
			out = append(out, objectInfo{Key: c.Key, Size: c.Size, Modified: mod})
		}
		if !page.IsTruncated || page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}
