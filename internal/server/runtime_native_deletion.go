// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"

	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func deleteOriginalRuntime(ctx context.Context, handler svc.Handler, id, generation string) error {
	if generation != "" {
		if native, ok := handler.(svc.GenerationRuntimeDeleter); ok {
			return native.DeleteRuntimeIfGeneration(ctx, id, generation)
		}
		if _, ok := handler.(svc.RuntimeGenerationVerifier); ok {
			return errors.New("runtime generation verification cannot authorize unconditional deletion")
		}
	}
	return handler.Delete(ctx, id)
}
