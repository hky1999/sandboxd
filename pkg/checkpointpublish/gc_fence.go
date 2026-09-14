// Copyright 2026 Ant Group Corporation.
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

package checkpointpublish

import (
	"context"
	"fmt"

	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// GCMarkNamespace is the key prefix under which cn-gcsweep records deletion
// candidates: gc-marks/<object-key>. A mark is a small object whose store
// modification time is the marking instant. Marks never gate reads — they
// exist so a publisher that is about to lean on an EXISTING object (a Has
// hit) can notice the object is on its way out and refresh it instead.
const GCMarkNamespace = "gc-marks"

// GCMarkKey is the mark object's key for a swept store object.
func GCMarkKey(key string) string {
	return GCMarkNamespace + "/" + key
}

// gcReuseFenced reports whether reusing the store object at key is fenced by
// a sweep mark. A fenced Has hit must NOT skip the upload: the mark says a
// sweep judged this object dead and may collect it once the mark ages past
// its grace, and min-age offers no protection because the object is old by
// construction. Re-uploading the bytes from the local artifact refreshes the
// object's store timestamp, which the sweep's delete-time recheck observes
// and spares — the fence and the recheck are one protocol, not two guards.
//
// An error is returned, not swallowed: a fence that cannot be proven is not
// a pass, and failing the publish is the fail-closed outcome. This probe
// costs one extra GET per Has hit (marks are absent in steady state).
func gcReuseFenced(ctx context.Context, store chunkstore.Keyed, key string) (bool, error) {
	ok, err := store.HasKey(ctx, GCMarkKey(key))
	if err != nil {
		return false, fmt.Errorf("probe sweep mark for %s: %w", key, err)
	}
	return ok, nil
}
