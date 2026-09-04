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
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func main() {
	checkpointDir := flag.String("checkpoint-dir", "", "checkpoint directory to publish")
	storePath := flag.String("store", "", "chunk store path (directory backend)")
	status := flag.Bool("status", false, "print the persisted publish state and exit")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall deadline")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-publish -checkpoint-dir DIR -store DIR | cn-publish -status -checkpoint-dir DIR\n")
		flag.PrintDefaults()
	}
	flag.Parse()
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

	start := time.Now()
	result, err := checkpointpublish.Run(ctx, *checkpointDir, id, store, *storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "publish failed (state persisted, retry resumes): %v\n", err)
		encoded, _ := json.MarshalIndent(result.State, "", "  ")
		fmt.Fprintln(os.Stderr, string(encoded))
		os.Exit(1)
	}
	fmt.Printf("published %s: %d/%d chunks (%d put, %d skipped), artifact_set=%v in %s\n",
		id, result.State.ChunksPut, result.State.ChunksTotal,
		result.ChunksPut, result.ChunksSkip, result.State.ArtifactSet,
		time.Since(start).Round(time.Millisecond))
}
