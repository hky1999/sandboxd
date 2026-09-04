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
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func main() {
	into := flag.String("into", "", "target checkpoint directory to materialize")
	id := flag.String("id", "", "checkpoint id (artifact namespace)")
	storePath := flag.String("store", "", "chunk store spec (http://bucket-endpoint or directory)")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall deadline")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-fetch -into DIR -id ID -store SPEC\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *into == "" || *id == "" || *storePath == "" {
		flag.Usage()
		os.Exit(2)
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
	start := time.Now()
	if err := checkpointpublish.Materialize(ctx, *into, *id, keyed); err != nil {
		fmt.Fprintf(os.Stderr, "materialize failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("materialized %s into %s in %s\n", *id, *into,
		time.Since(start).Round(time.Millisecond))
}
