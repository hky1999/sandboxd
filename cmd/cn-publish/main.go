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

// Command cn-publish distributes a checkpoint's memory chunks to a chunk
// store and drives the publish state machine
// (local_ready -> publishing -> published | publish_failed).
//
// Publishing is an external orchestration step: the checkpoint RPC has long
// returned, local restores keep working regardless of outcome (fail-open),
// and only the `published` state unlocks cross-node placement in
// cn-locator. Re-running resumes and re-puts only missing objects.
//
// Usage:
//
//	cn-publish -checkpoint-dir DIR -store /path/to/chunk-store
//	cn-publish -status -checkpoint-dir DIR
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func main() {
	checkpointDir := flag.String("checkpoint-dir", "", "checkpoint directory to publish")
	storePath := flag.String("store", "", "chunk store path (directory backend)")
	packIdentity := flag.String("pack-identity", "", "pack identity: empty for legacy SHA256, chunks-v1 for versioned chunk root (requires -pack-mib)")
	packBatchHash := flag.Bool("pack-batch-hash", false, "verify packed chunks using synchronous SHA256 batches (requires -pack-mib)")
	packSkipChunkProbe := flag.Bool("pack-skip-chunk-probe", false, "skip standalone chunk reuse checks; may upload duplicate content in packs (requires -pack-mib)")
	cpuProfile := flag.String("cpu-profile", "", "write an optional CPU profile to a new file (diagnostic runs only)")
	status := flag.Bool("status", false, "print the persisted publish state and exit")
	packPayloadMiB := flag.Int("pack-payload-mib", 0, "active pack payload budget (0 = 16MiB; up to 64MiB, requires packing)")
	packMiB := flag.Int("pack-mib", 0, "pack memory into 1-8MiB objects (0 disables; candidate 4)")
	baseID := flag.String("base-id", "", "verified published baseline in the same store for pack reuse")
	workers := flag.Int("workers", 0, "memory upload concurrency (1-64; 0 = at most 8 GOMAXPROCS workers)")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall deadline")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-publish -checkpoint-dir DIR -store DIR | cn-publish -status -checkpoint-dir DIR\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *packBatchHash && *packMiB == 0 {
		fmt.Fprintln(os.Stderr, "error: -pack-batch-hash requires -pack-mib")
		os.Exit(2)
	}
	if *packSkipChunkProbe && *packMiB == 0 {
		fmt.Fprintln(os.Stderr, "error: -pack-skip-chunk-probe requires -pack-mib")
		os.Exit(2)
	}
	if *packMiB < 0 || *packMiB > 8 {
		fmt.Fprintln(os.Stderr, "error: -pack-mib must be between 0 and 8")
		os.Exit(2)
	}
	if *packPayloadMiB < 0 || *packPayloadMiB > 64 || (*packPayloadMiB != 0 && (*packMiB == 0 || *packPayloadMiB < *packMiB)) {
		fmt.Fprintln(os.Stderr, "error: -pack-payload-mib requires packing and must fit a pack, up to 64MiB")
		os.Exit(2)
	}
	if *baseID != "" && *packMiB == 0 {
		fmt.Fprintln(os.Stderr, "error: -base-id requires -pack-mib")
		os.Exit(2)
	}
	if *workers < 0 || *workers > 64 {
		fmt.Fprintln(os.Stderr, "error: -workers must be between 0 and 64")
		os.Exit(2)
	}
	if *checkpointDir == "" || (!*status && *storePath == "") {
		flag.Usage()
		os.Exit(2)
	}

	id := filepath.Base(*checkpointDir)

	if *status {
		state, err := checkpointpublish.Status(*checkpointDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		if state == nil {
			fmt.Printf("%s: never published\n", id)
			return
		}
		encoded, _ := json.MarshalIndent(state, "", "  ")
		fmt.Println(string(encoded))
		return
	}

	store, err := chunkstore.Open(*storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	stopProfile := func() {}
	if *cpuProfile != "" {
		file, err := os.OpenFile(*cpuProfile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "CPU profile: %v\n", err)
			os.Exit(2)
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			file.Close()
			fmt.Fprintf(os.Stderr, "CPU profile: %v\n", err)
			os.Exit(2)
		}
		stopProfile = func() { pprof.StopCPUProfile(); file.Close() }
	}
	start := time.Now()
	result, err := checkpointpublish.RunWithOptions(ctx, *checkpointDir, id, store, *storePath, checkpointpublish.Options{PackBatchHash: *packBatchHash, PackSkipChunkProbe: *packSkipChunkProbe, PackPayloadBytes: *packPayloadMiB << 20, PackIdentity: *packIdentity, Workers: *workers, PackBytes: *packMiB << 20, BaseID: *baseID})
	elapsed := time.Since(start)
	stopProfile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "publish failed (state persisted, retry resumes): %v\n", err)
		encoded, _ := json.MarshalIndent(result.State, "", "  ")
		fmt.Fprintln(os.Stderr, string(encoded))
		os.Exit(1)
	}
	if *packMiB > 0 {
		fmt.Printf("packs: %d uploaded, %d reused\n", result.PacksPut, result.PacksSkip)
		fmt.Printf("pack_payload budget=%d peak=%d\n", result.PackPayloadBudget, result.PackPayloadPeak)
	}
	if result.StateTimings != nil {
		encoded, _ := json.Marshal(result.StateTimings)
		fmt.Printf("state_timings=%s\n", encoded)
	}
	if result.PackTimings != nil {
		encoded, _ := json.Marshal(result.PackTimings)
		fmt.Printf("pack_timings=%s\n", encoded)
	}
	fmt.Printf("published %s: %d logical chunks, %d unique (%d written, %d reused), artifact_set=%v workers=%d in %s\n",
		id, result.State.ChunksTotal, result.State.ChunksPut,
		result.ChunksPut, result.ChunksSkip, result.State.ArtifactSet, result.Workers,
		elapsed.Round(time.Millisecond))
}
