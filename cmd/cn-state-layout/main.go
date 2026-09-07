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

// Command cn-state-layout explicitly initializes external publication state
// for a fresh checkpoint root. It never migrates an existing .publish directory.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
)

func main() {
	root := flag.String("checkpoint-root", "", "existing checkpoint root to initialize")
	base := flag.String("state-base", "", "existing directory outside checkpoint root for durable publication state")
	flag.Parse()
	if *root == "" || *base == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: cn-state-layout -checkpoint-root ROOT -state-base BASE")
		os.Exit(2)
	}
	layout, err := checkpointpublish.InitStateLayout(context.Background(), *root, *base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "state layout:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(layout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
