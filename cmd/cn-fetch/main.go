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

// Command cn-fetch materializes a published checkpoint onto a node that
// never saw the source directory: it fetches the artifact set (manifest,
// chunk sidecar, vmstate, overlay) from the store, verifies every file
// against the INDEX digests, and lays down a sparse memory placeholder that
// the uffd handler serves by digest from the chunk store.
//
//	cn-fetch -into DIR -id CHECKPOINT-ID -store http://minio:19000/bucket
//
// With -verify-memory it instead verifies a PUBLISHED artifact's memory
// transport (see the flag help) without materializing anything.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkcache"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// cacheSettler is the settle/report surface cn-fetch needs from the node
// cache manager. `armed` selects the authoritative settle operation:
// watermarks armed -> EvictIfNeeded (a capacity pass includes a rescan);
// 0/0 -> an explicit Rescan (EvictIfNeeded is a no-op there). In BOTH
// cases Status is snapshotted only after the settle operation succeeds,
// so the printed summary always describes a post-pass, index-ready view.
type cacheSettler interface {
	EvictIfNeeded(ctx context.Context) error
	Rescan(ctx context.Context) error
	Status() chunkcache.Status
}

// settleCache runs the authoritative settle operation FIRST and only then
// snapshots the status, and a SUCCESSFUL settle must yield index_ready:
// returning a not-ready status as settled would let a summary line
// masquerade as an authoritative view it does not have. A settle failure
// (operation error OR !IndexReady) is returned with the zero status: the
// caller must fail loudly rather than print a summary that could be
// mistaken for a settled one. The armed path must NOT additionally rescan
// — the capacity pass already rebuilds the index from disk.
func settleCache(ctx context.Context, c cacheSettler, armed bool) (chunkcache.Status, error) {
	if armed {
		if err := c.EvictIfNeeded(ctx); err != nil {
			return chunkcache.Status{}, fmt.Errorf("chunk-cache capacity pass: %w", err)
		}
	} else {
		if err := c.Rescan(ctx); err != nil {
			return chunkcache.Status{}, fmt.Errorf("chunk-cache index scan: %w", err)
		}
	}
	s := c.Status()
	if !s.IndexReady {
		return chunkcache.Status{}, fmt.Errorf("chunk-cache settle finished without an authoritative index view (index_ready=false)")
	}
	return s, nil
}

// printCacheSummary emits the settled summary line. The field set is
// stable (parsers depend on it); index_ready states whether the
// authoritative index view is available after the settle operation.
func printCacheSummary(s chunkcache.Status) {
	fmt.Printf("chunk-cache: entries=%d logical=%d allocated=%d hits=%d misses=%d hit_bytes=%d miss_bytes=%d evictions=%d pinned=%d index_ready=%v\n",
		s.Entries, s.LogicalBytes, s.AllocatedBytes, s.Hits, s.Misses, s.HitBytes, s.MissBytes, s.Evictions, s.PinnedEntries, s.IndexReady)
}

// inferArtifactID resolves which artifact a -verify-memory run names: the
// explicit -id wins; otherwise the checkpoint directory's basename. The
// directory is only ever an ID source — verification reads the REMOTE
// sidecar via the INDEX, never the local copy.
func inferArtifactID(verifyMemory bool, id, checkpointDir string) (string, error) {
	if id != "" {
		return id, nil
	}
	if verifyMemory && checkpointDir != "" {
		return filepath.Base(filepath.Clean(checkpointDir)), nil
	}
	return "", nil
}

// validateMode enforces the CLI's mode contract:
//   - -verify-memory and -into are mutually exclusive (verification never
//     materializes);
//   - verify mode needs an artifact id (explicit -id or -checkpoint-dir
//     basename) and a store;
//   - materialize mode needs -into, -id and -store.
func validateMode(verifyMemory bool, into, id, checkpointDir, store string) error {
	if verifyMemory && into != "" {
		return fmt.Errorf("-verify-memory and -into are mutually exclusive")
	}
	if store == "" {
		return fmt.Errorf("-store is required")
	}
	if verifyMemory {
		if id == "" && checkpointDir == "" {
			return fmt.Errorf("-verify-memory needs -id or -checkpoint-dir")
		}
		return nil
	}
	if into == "" || id == "" {
		return fmt.Errorf("materialize mode needs -into and -id")
	}
	return nil
}

func main() {
	into := flag.String("into", "", "target checkpoint directory to materialize")
	id := flag.String("id", "", "checkpoint id (artifact namespace)")
	storePath := flag.String("store", "", "chunk store spec (http://bucket-endpoint or directory)")
	verifyMemory := flag.Bool("verify-memory", false,
		"verify a PUBLISHED artifact's memory transport instead of materializing: resolve the transport sidecar from the remote INDEX (pack/compress encodings live only there), then fetch every chunk from -store and digest-check it; -id names the artifact")
	checkpointDir := flag.String("checkpoint-dir", "",
		"optional: infer the artifact id for -verify-memory from this directory's basename (verification reads the REMOTE sidecar via the INDEX, never this local copy)")
	cacheDir := flag.String("chunk-cache", "", "local content-addressed cache directory fronting an http chunk-store: hits never touch the network, misses are verified and persisted here")
	cacheHighMB := flag.Int64("cache-high-mb", 0, "node cache high watermark in MiB (0 keeps the historical unbounded cache)")
	cacheLowMB := flag.Int64("cache-low-mb", 0, "node cache low watermark in MiB; eviction (when enabled) stops here")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall deadline")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-fetch -into DIR -id ID -store SPEC [-chunk-cache DIR] | cn-fetch -verify-memory -checkpoint-dir DIR -store SPEC\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	// Mode validation FIRST — pure, no external side effects: an invalid
	// mode combination must be refused before ANY store is opened, and a
	// verify-only invocation must never be rejected over cache flags it
	// does not use.
	if modeErr := validateMode(*verifyMemory, *into, *id, *checkpointDir, *storePath); modeErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", modeErr)
		flag.Usage()
		os.Exit(2)
	}
	artifact, _ := inferArtifactID(*verifyMemory, *id, *checkpointDir)
	if !*verifyMemory {
		// Cache watermarks only gate the materialize path that uses them.
		if err := chunkcache.ValidWatermarkMiB(*cacheHighMB, *cacheLowMB); err != nil {
			fmt.Fprintf(os.Stderr, "error: -cache-high-mb/-cache-low-mb: %v\n", err)
			os.Exit(2)
		}
	}
	store, err := chunkstore.Open(*storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	keyed, ok := store.(chunkstore.Keyed)
	if !ok {
		fmt.Fprintln(os.Stderr, "error: store backend cannot serve artifact sets")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *verifyMemory {
		// Verification resolves the encoding view from the REMOTE INDEX;
		// a local sealed sidecar cannot describe compress/pack transport.
		// It returns BEFORE any cache manager is created: verification
		// does not use -chunk-cache and must not touch a cache root.
		start := time.Now()
		verif, err := checkpointpublish.VerifyMemoryArtifact(ctx, artifact, keyed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify-memory failed after %d chunks: %v\n", verif.ChunksVerified, err)
			os.Exit(1)
		}
		summary, merr := json.Marshal(verif)
		if merr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", merr)
			os.Exit(1)
		}
		fmt.Printf("verify-memory ok in %s: %s\n", time.Since(start).Round(time.Millisecond), summary)
		return
	}
	opts := checkpointpublish.MaterializeOptions{}
	if *cacheDir != "" {
		manager, err := chunkcache.Open(chunkcache.Config{
			Root:          *cacheDir,
			HighWatermark: *cacheHighMB << 20,
			LowWatermark:  *cacheLowMB << 20,
			StoreDomain:   *storePath,
			Logger:        log.New(os.Stderr, "cn-fetch-chunkcache ", log.LstdFlags|log.Lmicroseconds),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		defer manager.Close()
		opts.Cache = manager
	}
	start := time.Now()
	if err := checkpointpublish.MaterializeWithOptions(ctx, *into, *id, keyed, opts); err != nil {
		fmt.Fprintf(os.Stderr, "materialize failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("materialized %s into %s in %s\n", *id, *into,
		time.Since(start).Round(time.Millisecond))
	if opts.Cache != nil {
		// Settle BEFORE printing: the summary must describe the state
		// AFTER the authoritative settle operation, and a settle failure
		// must fail the CLI — the bytes may be correct, but a cache that
		// cannot complete its settle is not a healthy exit.
		s, err := settleCache(ctx, opts.Cache, *cacheHighMB > 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		printCacheSummary(s)
	}
}
