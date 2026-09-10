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
// Artifact SETS (artifacts/<id>/*) are ID-named and exclusive, so they
// may age out wholesale: -max-artifact-age drops sets whose INDEX is
// older than the bound, -drop names IDs explicitly. Dropping an artifact
// removes its objects and stops its chunks from counting as references —
// a chunk dies only when its LAST referencing artifact is gone.
//
// The tool is fail-closed: if any surviving artifact's INDEX or sidecar
// cannot be fetched and decoded, NOTHING is deleted, because the live set
// cannot be proven. Objects with unrecognized key shapes are never
// touched. Deletion requires -delete; without it the run reports only.
//
//	cn-gcsweep -store http://172.18.0.1:19000/cn-chunks            # report
//	cn-gcsweep -store ... -delete -max-artifact-age 168h -min-age 24h
//
// Exit codes: 0 report/deletion ran, 1 error, 2 usage.
package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	DeadYoung          int    `json:"dead_young"`   // unreferenced but younger than min-age
	ForeignKept        int    `json:"foreign_kept"` // unrecognized key shapes
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
	workers := flag.Int("workers", 8, "concurrent INDEX/sidecar fetches")
	jsonOut := flag.Bool("json", false, "machine-readable report")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-gcsweep -store URL [-delete] [-max-artifact-age 168h] [-drop ID,ID] [-min-age 24h]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *storeSpec == "" || *minAge < 0 || *maxArtifactAge < 0 || *workers < 1 || *workers > 64 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(context.Background(), *storeSpec, *del, *maxArtifactAge, strings.Split(*drop, ","), *minAge, *workers, *jsonOut); err != nil {
		fmt.Fprintf(os.Stderr, "gcsweep: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, spec string, del bool, maxArtifactAge time.Duration, dropIDs []string, minAge time.Duration, workers int, jsonOut bool) error {
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

	// Partition: artifacts/<id>/<file> vs everything else.
	type artifactSet struct {
		objects  []objectInfo
		indexAt  time.Time
		hasIndex bool
	}
	artifacts := make(map[string]*artifactSet)
	var chunkish []objectInfo
	report := sweepReport{Store: spec, DryRun: !del}
	for _, o := range objects {
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
	victims = append(victims, dropObjects...)

	// Delete (or report). Artifact-set objects dropped by age or -drop
	// carry no min-age guard: they are ID-exclusive and their age was the
	// criterion.
	for _, o := range victims {
		report.Deletions++
		report.DeletionBytes += o.Size
		if !del {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/"+o.Key, nil)
		if err != nil {
			report.DeleteErrors++
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			report.DeleteErrors++
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			report.DeleteErrors++
		}
	}

	if jsonOut {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Printf("gcsweep: store=%s objects=%d (%dMiB) artifacts kept/dropped/indexless=%d/%d/%d "+
			"chunk-objects live/dead/young/foreign=%d/%d/%d/%d "+
			"reclaim %d objects (%dMiB) errors=%d dry-run=%v\n",
			spec, report.ObjectsTotal, report.BytesTotal>>20,
			report.ArtifactsKept, report.ArtifactsDropped, report.ArtifactsIndexless,
			report.ChunkObjectsLive, report.ChunkObjectsDead, report.DeadYoung, report.ForeignKept,
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
		for _, entry := range m.Entries {
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
