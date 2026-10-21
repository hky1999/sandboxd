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

package runsc

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

var _ runtimecore.StrictDeleteHandler = (*Handler)(nil)
var _ runtimecore.CheckpointRootVerifier = (*Handler)(nil)

type runscRootVerificationClient interface {
	SupportsCheckpointRootVerification() bool
}
type runscStrictDeleteClient interface {
	DeleteIfGeneration(context.Context, string, string) error
}

func (c *Client) SupportsCheckpointRootVerification() bool { return true }

func (r *Handler) SupportsCheckpointRootVerification() bool {
	verifier, ok := r.runsc.(runscRootVerificationClient)
	return ok && verifier.SupportsCheckpointRootVerification()
}

func (r *Handler) verifyExpectedCheckpointRoot(ctx context.Context, cfg runtimecore.StartConfig) error {
	if cfg.ExpectedCheckpointRoot == "" {
		return nil
	}
	if !r.SupportsCheckpointRootVerification() {
		return fmt.Errorf("runsc client cannot verify expected checkpoint root: %w", errord.ErrFailedPrecondition)
	}
	_, err := readRunscManifestView(ctx, cfg.CheckpointDir, cfg.ExpectedCheckpointRoot)
	if err != nil {
		return fmt.Errorf("verify runsc restore identity before create: %w", err)
	}
	return nil
}

// DeleteStrict never falls back to legacy delete or treats "not found" as a
// proof. The pinned runsc binary must implement the generation + pidfd contract.
func (r *Handler) DeleteStrict(ctx context.Context, id, expected string) error {
	if expected == "" {
		return fmt.Errorf("strict runsc delete requires a generation: %w", errord.ErrFailedPrecondition)
	}
	strict, ok := r.runsc.(runscStrictDeleteClient)
	if !ok {
		return fmt.Errorf("runsc client lacks strict deletion: %w", errord.ErrFailedPrecondition)
	}
	bundle, err := util.JoinWithinRoot(r.sandboxRoot, id)
	if err != nil {
		return err
	}
	if err := strict.DeleteIfGeneration(ctx, id, expected); err != nil {
		return err
	}
	return cleanupRunscNVProxyRootfs(bundle)
}

func (c *Client) DeleteIfGeneration(ctx context.Context, id, expected string) error {
	if id == "" || expected == "" {
		return fmt.Errorf("strict runsc delete requires id and generation: %w", errord.ErrFailedPrecondition)
	}
	args := append(c.globalArgs(), "delete", "--force", "--expected-generation="+expected, "--", id)
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("strict runsc delete %s failed: %w: %s", id, err, string(output))
	}
	return nil
}
