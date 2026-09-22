// Copyright (c) 2026 Ant Group Corporation.
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

// Capability-preservation and counter-classification tests for the
// attribution wrappers. The fakes below define EXACT method sets (no
// embedding of *chunkstore.Local — that would promote its conditional
// methods and fake capabilities the backend does not have).

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// storeOnlyFake implements chunkstore.Store and nothing more.
type storeOnlyFake struct{ inner *chunkstore.Local }

func (s *storeOnlyFake) Put(ctx context.Context, digest string, r io.Reader) error {
	return s.inner.Put(ctx, digest, r)
}
func (s *storeOnlyFake) Get(ctx context.Context, digest string) (io.ReadCloser, error) {
	return s.inner.Get(ctx, digest)
}
func (s *storeOnlyFake) Has(ctx context.Context, digest string) (bool, error) {
	return s.inner.Has(ctx, digest)
}

// keyedNoExclFake adds the Keyed surface but NOT ExclusivePutter.
type keyedNoExclFake struct{ inner *chunkstore.Local }

func (s *keyedNoExclFake) Put(ctx context.Context, digest string, r io.Reader) error {
	return s.inner.Put(ctx, digest, r)
}
func (s *keyedNoExclFake) Get(ctx context.Context, digest string) (io.ReadCloser, error) {
	return s.inner.Get(ctx, digest)
}
func (s *keyedNoExclFake) Has(ctx context.Context, digest string) (bool, error) {
	return s.inner.Has(ctx, digest)
}
func (s *keyedNoExclFake) PutKey(ctx context.Context, key string, r io.Reader) error {
	return s.inner.PutKey(ctx, key, r)
}
func (s *keyedNoExclFake) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.inner.GetKey(ctx, key)
}
func (s *keyedNoExclFake) HasKey(ctx context.Context, key string) (bool, error) {
	return s.inner.HasKey(ctx, key)
}

// TestInstrumentStoreCapabilityPreservation: wrapping must not change any
// optional-interface assertion outcome — the GC fence and the artifact-set
// branch select real fallbacks through those assertions, and a wrapper
// whose type always satisfied them would make incapable backends look
// capable. Three tiers are proven: Store-only, Keyed-without-ExclusivePutter,
// and full (Local).
func TestInstrumentStoreCapabilityPreservation(t *testing.T) {
	ctx := context.Background()
	c := &phaseCounters{}

	t.Run("store-only-stores-store-only", func(t *testing.T) {
		inner := &storeOnlyFake{inner: mustLocal(t)}
		wrapped := instrumentStore(inner, c)
		if _, ok := wrapped.(chunkstore.Keyed); ok {
			t.Fatal("Store-only backend must stay non-Keyed through the wrapper")
		}
		if _, ok := wrapped.(chunkstore.ExclusivePutter); ok {
			t.Fatal("Store-only backend must stay non-ExclusivePutter through the wrapper")
		}
		// A bare Store-only backend cannot even be passed to the fence as
		// chunkstore.Keyed (it does not implement it) — the wrapper must
		// keep that exactly: no code path may suddenly see keyed access.
	})

	t.Run("keyed-without-exclusive-keeps-fallback", func(t *testing.T) {
		inner := &keyedNoExclFake{inner: mustLocal(t)}
		wrapped := instrumentStore(inner, c)
		if _, ok := wrapped.(chunkstore.Keyed); !ok {
			t.Fatal("Keyed backend must stay Keyed through the wrapper")
		}
		if _, ok := wrapped.(chunkstore.ExclusivePutter); ok {
			t.Fatal("Keyed-but-not-exclusive backend must stay non-ExclusivePutter")
		}
		bareErr := func() string {
			_, err := gcAcquireClaim(ctx, inner, "bb/somedigest")
			if err == nil {
				t.Fatal("bare keyed-no-excl unexpectedly fenced")
			}
			return err.Error()
		}()
		_, wrappedErr := gcAcquireClaim(ctx, wrapped.(chunkstore.Keyed), "bb/somedigest")
		if wrappedErr == nil || wrappedErr.Error() != bareErr {
			t.Fatalf("fence error changed through the wrapper: bare=%q wrapped=%v", bareErr, wrappedErr)
		}
	})

	t.Run("full-backend-keeps-conditional-writes-as-control", func(t *testing.T) {
		local := mustLocal(t)
		wrapped := instrumentStore(local, c)
		if _, ok := wrapped.(chunkstore.Keyed); !ok {
			t.Fatal("Local must stay Keyed through the wrapper")
		}
		if _, ok := wrapped.(chunkstore.ExclusivePutter); !ok {
			t.Fatal("Local must stay ExclusivePutter through the wrapper")
		}
		body, err := gcAcquireClaim(ctx, wrapped.(chunkstore.Keyed), "cc/somedigest")
		if err != nil {
			t.Fatalf("claim through wrapped Local: %v", err)
		}
		if got := c.snapshot().ControlReqs; got != 1 {
			t.Fatalf("control_reqs = %d, want 1 (the claim create)", got)
		}
		if got := c.snapshot().PutReqs; got != 0 {
			t.Fatalf("claim leaked into data put_reqs = %d", got)
		}
		gcReleaseClaim(ctx, wrapped.(chunkstore.Keyed), "cc/somedigest", body)
		if got := c.snapshot().ControlReqs; got != 2 {
			t.Fatalf("control_reqs = %d, want 2 (create + conditional delete)", got)
		}
	})
}

// TestInstrumentStoreCounterClassification: data PUTs (with bytes), GETs
// (with request count and streamed bytes), Has probes, control-namespace
// keyed writes, and compression never borrow each other's columns.
func TestInstrumentStoreCounterClassification(t *testing.T) {
	local := mustLocal(t)
	c := &phaseCounters{}
	wrapped := instrumentStore(local, c)
	keyed := wrapped.(chunkstore.Keyed)
	ctx := context.Background()

	// Data PUT through the keyed surface.
	if err := keyed.PutKey(ctx, "dd/somedigest", strings.NewReader("data-body")); err != nil {
		t.Fatal(err)
	}
	// Control-namespace PUT through the same surface (an intent write).
	if err := keyed.PutKey(ctx, GCPubIntentNamespace+"/ck-1/nonce", strings.NewReader("nonce")); err != nil {
		t.Fatal(err)
	}
	// GET: request counted at open; the FULL elapsed (open through body
	// end) and the bytes settle at EOF/Close — the body transfer time must
	// not be invisible the way a headers-only metric would make it.
	rc, err := keyed.GetKey(ctx, "dd/somedigest")
	if err != nil {
		t.Fatal(err)
	}
	// Before any body read: the request is counted but nothing settled.
	if got := c.snapshot(); got.GetReqs != 1 {
		t.Fatalf("get_reqs before body = %d, want 1", got.GetReqs)
	}
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if string(body) != "data-body" {
		t.Fatalf("body = %q", body)
	}
	// An errored GET settles immediately at its open latency.
	if _, err := keyed.GetKey(ctx, "ff/absentdigest"); err == nil {
		t.Fatal("expected error for absent object")
	}
	if _, err := keyed.HasKey(ctx, "ee/otherdigest"); err != nil {
		t.Fatal(err)
	}
	c.addCompress(0) // classification only

	snap := c.snapshot()
	if snap.PutReqs != 1 || snap.PutBytes != int64(len("data-body")) {
		t.Fatalf("data put = %d reqs %d bytes, want 1 and %d", snap.PutReqs, snap.PutBytes, len("data-body"))
	}
	if snap.ControlReqs != 1 {
		t.Fatalf("control_reqs = %d, want 1 (the intent write)", snap.ControlReqs)
	}
	if snap.GetReqs != 2 {
		t.Fatalf("get_reqs = %d, want 2 (one success, one error)", snap.GetReqs)
	}
	if snap.GetBytes != int64(len("data-body")) {
		t.Fatalf("get_bytes = %d, want %d", snap.GetBytes, len("data-body"))
	}
	if snap.GetTimeTotal < snap.GetOpenTimeTotal {
		t.Fatalf("get_time_total %v < get_open_time_total %v (full elapsed must include the body)",
			snap.GetTimeTotal, snap.GetOpenTimeTotal)
	}
	if snap.HasReqs != 1 {
		t.Fatalf("has_reqs = %d, want 1", snap.HasReqs)
	}
}
