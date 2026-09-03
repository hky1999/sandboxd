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

// Command cn-locator decides which node should restore a checkpoint.
//
// It federates the node records served by each node's checkpoint catalog
// (/api/v1/node), reads the checkpoint's compatibility tuple from its
// manifest, and runs the placement tree: the origin node wins when it is
// registered; otherwise the earliest compatible candidate in stable node
// order; an unsatisfiable request fails closed with per-node reasons.
//
// Exit codes: 0 placement decided, 1 no valid placement, 2 usage or
// environment error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointlocator"
)

func main() {
	nodes := flag.String("nodes", "", "comma-separated node catalog addresses (http://host:port)")
	checkpointDir := flag.String("checkpoint-dir", "", "local path to the checkpoint directory")
	templateID := flag.String("template-id", "", "content-addressed template id to derive from")
	templateCompat := flag.String("template-compat", "",
		"local template directory to read the compat tuple from (default: the manifest next to -template-root)")
	templateRoot := flag.String("template-root", "", "local template root holding <id>/manifest.json for -template-id")
	origin := flag.String("origin", "", "origin node ID (placement prefers it when registered)")
	pin := flag.Bool("pin", false, "forbid cross-node placement even when a compatible peer exists")
	timeout := flag.Duration("timeout", 10*time.Second, "overall deadline")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-locator -nodes http://n1:18090,http://n2:18090 (-checkpoint-dir DIR [-origin ID] [-pin] | -template-id ID [-template-compat DIR])\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *nodes == "" || (*checkpointDir == "" && *templateID == "") || (*checkpointDir != "" && *templateID != "") {
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	addresses := strings.Split(*nodes, ",")
	records, fetchErrs := checkpointlocator.FetchAll(ctx, addresses)
	for _, err := range fetchErrs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "error: no node records available")
		os.Exit(2)
	}

	var compat *checkpointlocator.CheckpointCompat
	var err error
	id := strings.TrimRight(strings.ReplaceAll(*checkpointDir, "\\", "/"), "/")
	if idx := strings.LastIndexByte(id, '/'); idx >= 0 {
		id = id[idx+1:]
	}

	var placement checkpointlocator.Placement
	if *templateID != "" {
		dir := *templateCompat
		if dir == "" {
			dir = filepath.Join(*templateRoot, *templateID)
		}
		compat, err = checkpointlocator.ReadCheckpointCompat(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		holders := make([]checkpointlocator.NodeHolder, 0, len(records))
		for _, record := range records {
			ids, ferr := checkpointlocator.FetchTemplates(ctx, record.Address)
			if ferr != nil {
				fmt.Fprintf(os.Stderr, "warning: %v\n", ferr)
				ids = nil
			}
			holders = append(holders, checkpointlocator.NodeHolder{Record: record, Holds: ids})
		}
		placement, err = checkpointlocator.DecideTemplate(checkpointlocator.TemplateInput{
			TemplateID: *templateID,
			Compat:     compat,
			Nodes:      holders,
		})
	} else {
		compat, err = checkpointlocator.ReadCheckpointCompat(*checkpointDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		placement, err = checkpointlocator.Decide(checkpointlocator.Input{
			CheckpointID: id,
			Compat:       compat,
			OriginNodeID: *origin,
			PinToOrigin:  *pin,
			Nodes:        records,
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	encoded, _ := json.MarshalIndent(placement, "", "  ")
	fmt.Println(string(encoded))
}
