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

package chunkstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestLocalPutGetHas(t *testing.T) {
	store, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	content := []byte("chunk-bytes")
	digest := digestOf(content)

	if has, err := store.Has(ctx, digest); err != nil || has {
		t.Fatalf("has before put = %v, %v", has, err)
	}
	if err := store.Put(ctx, digest, bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}
	if has, err := store.Has(ctx, digest); err != nil || !has {
		t.Fatalf("has after put = %v, %v", has, err)
	}
	// Re-put of identical content is a no-op, not an error.
	if err := store.Put(ctx, digest, bytes.NewReader(content)); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	rc, err := store.Get(ctx, digest)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer rc.Close()
	got := make([]byte, len(content))
	if _, err := rc.Read(got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("roundtrip corrupted content")
	}

	// Content that does not hash to its claimed digest is rejected.
	wrong := digestOf([]byte("other"))
	if err := store.Put(ctx, wrong, bytes.NewReader(content)); err == nil {
		t.Fatal("mislabeled content accepted")
	}
	if _, err := store.Has(ctx, "not-a-digest"); err == nil {
		t.Fatal("invalid digest accepted")
	}
	if _, err := store.Get(ctx, digestOf([]byte("missing"))); err == nil ||
		!strings.Contains(err.Error(), "not in store") {
		t.Fatalf("missing get = %v", err)
	}
}
