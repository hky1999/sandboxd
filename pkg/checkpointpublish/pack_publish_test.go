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

package checkpointpublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func packSource(t *testing.T, data []byte, chunkBytes int) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0600); err != nil {
		t.Fatal(err)
	}
	writeFullArtifact(t, dir)
	m, err := checkpointchunks.Compute(context.Background(), dir, chunkBytes)
	if err != nil {
		t.Fatal(err)
	}
	m.FileDigestMode = checkpointchunks.FileDigestChunks
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	if err := checkpointchunks.Write(dir, m); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"memory_size": len(data), "memory_digest_mode": "chunks", "digests": map[string]string{"memory": m.FileDigest}})
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}
func packData(chunks, size int) []byte {
	b := make([]byte, chunks*size)
	for i := range b {
		b[i] = byte(i/size + 1)
	}
	return b
}
func assertPackedBytes(t *testing.T, store *chunkstore.Local, id string, want []byte) *checkpointchunks.Manifest {
	t.Helper()
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "blind")
	if err := Materialize(ctx, target, id, store); err != nil {
		t.Fatal(err)
	}
	m, err := checkpointchunks.LoadTransport(target)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 2 && m.Version != 3 {
		t.Fatal("not packed transport")
	}
	var got []byte
	for _, c := range m.Entries {
		length := min(int64(m.ChunkBytes), m.FileSize-c.Offset)
		var data []byte
		if c.Digest == checkpointchunks.ZeroChunkDigest(int(length)) {
			data = make([]byte, length)
		} else if r, ok := m.Packs[c.Digest]; ok {
			key, keyErr := r.Key()
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			data, err = store.ReadKeyRange(ctx, key, chunkstore.ObjectRange{Offset: r.Offset, Length: r.Length, ObjectSize: r.ObjectSize})
		} else {
			var f io.ReadCloser
			f, err = store.Get(ctx, c.Digest)
			if err == nil {
				data, err = io.ReadAll(f)
				f.Close()
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != c.Digest {
			t.Fatal("wrong digest")
		}
		got = append(got, data...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("restored bytes differ")
	}
	return m
}

func TestPackPublishBaselineRetryAndMissingPack(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		for _, skip := range []bool{false, true} {
			for _, batch := range []bool{false, true} {
				t.Run(fmt.Sprintf("identity=%s/skip=%t/batch=%t", identity, skip, batch), func(t *testing.T) { packPublishBaselineRetryAndMissingPack(t, identity, skip, batch) })
			}
		}
	}
}
func packPublishBaselineRetryAndMissingPack(t *testing.T, identity string, skip, batch bool) {
	ctx := context.Background()
	data := packData(4, 4096)
	source := packSource(t, data, 4096)
	root := t.TempDir()
	store, _ := chunkstore.NewLocal(root)
	before, _ := os.ReadFile(filepath.Join(source, "chunks.json"))
	opts := Options{PackBatchHash: batch, PackSkipChunkProbe: skip, PackIdentity: identity, Workers: 4, PackBytes: 8192}
	first, err := RunWithOptions(ctx, source, "base", store, "local", opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.PacksPut != 2 {
		t.Fatalf("packs put %d", first.PacksPut)
	}
	m := assertPackedBytes(t, store, "base", data)
	after, _ := os.ReadFile(filepath.Join(source, "chunks.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("sealed source sidecar mutated")
	}
	retry, err := RunWithOptions(ctx, source, "base", store, "local", opts)
	if err != nil {
		t.Fatal(err)
	}
	if retry.PacksPut != 0 || retry.PacksSkip != 2 {
		t.Fatalf("retry: %+v", retry)
	}
	opts.BaseID = "base"
	warm, err := RunWithOptions(ctx, source, "warm", store, "local", opts)
	if err != nil {
		t.Fatal(err)
	}
	if warm.PacksPut != 0 || warm.PacksSkip != 2 {
		t.Fatalf("baseline reuse: %+v", warm)
	}
	changed := append([]byte(nil), data...)
	changed[0] ^= 7
	delta := packSource(t, changed, 4096)
	r, err := RunWithOptions(ctx, delta, "delta", store, "local", opts)
	if err != nil {
		t.Fatal(err)
	}
	if r.PacksPut != 1 || r.ChunksPut != 1 {
		t.Fatalf("delta uploaded unchanged content: %+v", r)
	}
	assertPackedBytes(t, store, "delta", changed)
	var missing string
	for _, ref := range m.Packs {
		missing, err = ref.Key()
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if err := os.Remove(filepath.Join(root, missing)); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := RunWithOptions(ctx, source, "rebuilt", store, "local", opts)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.PacksPut != 1 {
		t.Fatalf("missing parent pack was not rebuilt: %+v", rebuilt)
	}
	assertPackedBytes(t, store, "rebuilt", data)
}

type packFailureStore struct {
	*chunkstore.Local
	calls atomic.Int64
	fail  atomic.Bool
}

func (s *packFailureStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if (strings.HasPrefix(key, "memory-packs/") || strings.HasPrefix(key, "memory-chunk-packs-v1/")) && s.calls.Add(1) == 2 && s.fail.Load() {
		return errors.New("injected pack failure")
	}
	return s.Local.PutKey(ctx, key, r)
}
func TestPackFailureBeforeIndexAndResumption(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		for _, skip := range []bool{false, true} {
			for _, batch := range []bool{false, true} {
				t.Run(fmt.Sprintf("identity=%s/skip=%t/batch=%t", identity, skip, batch), func(t *testing.T) { packFailureBeforeIndexAndResumption(t, identity, skip, batch) })
			}
		}
	}
}
func packFailureBeforeIndexAndResumption(t *testing.T, identity string, skip, batch bool) {
	ctx := context.Background()
	data := packData(6, 4096)
	source := packSource(t, data, 4096)
	local, _ := chunkstore.NewLocal(t.TempDir())
	store := &packFailureStore{Local: local}
	store.fail.Store(true)
	opts := Options{PackBatchHash: batch, PackSkipChunkProbe: skip, PackIdentity: identity, Workers: 1, PackBytes: 8192}
	if _, err := RunWithOptions(ctx, source, "retry", store, "local", opts); err == nil {
		t.Fatal("failure ignored")
	}
	if ok, _ := local.HasKey(ctx, ArtifactKey("retry", IndexName)); ok {
		t.Fatal("INDEX committed before all packs")
	}
	state, err := Status(source)
	if err != nil || state.State != StatePublishFailed {
		t.Fatalf("state: %+v %v", state, err)
	}
	store.fail.Store(false)
	result, err := RunWithOptions(ctx, source, "retry", store, "local", opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.PacksSkip != 1 || result.PacksPut != 2 {
		t.Fatalf("did not reuse first completed pack: %+v", result)
	}
	assertPackedBytes(t, local, "retry", data)
}
func TestPackRejectsBadBaselineAndSource(t *testing.T) {
	for _, mode := range []string{"bad-baseline", "changed-source", "placeholder", "missing-baseline", "empty"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			data := packData(3, 4096)
			if mode == "empty" {
				data = nil
			}
			source := packSource(t, data, 4096)
			store, _ := chunkstore.NewLocal(t.TempDir())
			opts := Options{Workers: 2, PackBytes: 8192}
			switch mode {
			case "bad-baseline":
				if _, err := RunWithOptions(ctx, source, "base", store, "local", opts); err != nil {
					t.Fatal(err)
				}
				// Bundle-era baselines carry the small files in one
				// object; corrupting it must fail the baseline load
				// (bundle digest check) instead of being bypassed.
				if err := store.PutKey(ctx, ArtifactKey("base", BundleName), strings.NewReader("{}")); err != nil {
					t.Fatal(err)
				}
				opts.BaseID = "base"
			case "missing-baseline":
				opts.BaseID = "absent"
			case "changed-source":
				data[0] ^= 1
				if err := os.WriteFile(filepath.Join(source, "memory"), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "placeholder":
				if err := os.WriteFile(filepath.Join(source, MaterializedMarker), []byte("owned"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := RunWithOptions(ctx, source, "bad", store, "local", opts); err == nil {
				t.Fatal("bad input accepted")
			}
			if ok, _ := store.HasKey(ctx, ArtifactKey("bad", IndexName)); ok {
				t.Fatal("bad input committed")
			}
		})
	}
}
func TestPackMixedCASZeroAndTail(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		t.Run("identity="+identity, func(t *testing.T) { packMixedCASZeroAndTail(t, identity) })
	}
}
func packMixedCASZeroAndTail(t *testing.T, identity string) {
	ctx := context.Background()
	data := append(packData(2, 4096), make([]byte, 4096)...)
	data = append(data, []byte("short-tail")...)
	source := packSource(t, data, 4096)
	store, _ := chunkstore.NewLocal(t.TempDir())
	m, _ := checkpointchunks.Load(source)
	if err := store.Put(ctx, m.Entries[0].Digest, bytes.NewReader(data[:4096])); err != nil {
		t.Fatal(err)
	}
	result, err := RunWithOptions(ctx, source, "mixed", store, "local", Options{PackIdentity: identity, Workers: 4, PackBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChunksSkip != 2 || result.ChunksPut != 2 || result.PacksPut != 1 {
		t.Fatalf("mixed: %+v", result)
	}
	transport := assertPackedBytes(t, store, "mixed", data)
	if _, ok := transport.Packs[m.Entries[0].Digest]; ok {
		t.Fatal("existing CAS repacked")
	}
	if _, ok := transport.Packs[m.Entries[2].Digest]; ok {
		t.Fatal("zero packed")
	}
}

type packBudgetStore struct {
	wantActive int
	*chunkstore.Local
	mu                                   sync.Mutex
	activeBytes, peakBytes, active, peak int
	started                              chan struct{}
	release                              chan struct{}
	once                                 sync.Once
}

func (s *packBudgetStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if !strings.HasPrefix(key, "memory-packs/") && !strings.HasPrefix(key, "memory-chunk-packs-v1/") {
		return s.Local.PutKey(ctx, key, r)
	}
	n := r.(*bytes.Reader).Len()
	s.mu.Lock()
	s.activeBytes += n
	s.active++
	s.peakBytes = max(s.peakBytes, s.activeBytes)
	s.peak = max(s.peak, s.active)
	want := s.wantActive
	if want == 0 {
		want = 4
	}
	if s.active == want {
		s.once.Do(func() { close(s.started) })
	}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.activeBytes -= n; s.active--; s.mu.Unlock() }()
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.Local.PutKey(ctx, key, r)
}
func TestPackPayloadConcurrencyBudget(t *testing.T) {
	source := packSource(t, packData(20, 1<<20), 1<<20)
	local, _ := chunkstore.NewLocal(t.TempDir())
	store := &packBudgetStore{Local: local, started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, err := RunWithOptions(ctx, source, "budget", store, "local", Options{Workers: 64, PackBytes: 4 << 20})
		done <- err
	}()
	select {
	case <-store.started:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("four uploads did not overlap")
	}
	store.mu.Lock()
	peakBytes, peak := store.peakBytes, store.peak
	store.mu.Unlock()
	close(store.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if peak != 4 || peakBytes > packPayloadBudget {
		t.Fatalf("budget exceeded: %d workers %d bytes", peak, peakBytes)
	}
}

func TestPackMixedIdentityGenerations(t *testing.T) {
	ctx := context.Background()
	data := packData(4, 4096)
	local, _ := chunkstore.NewLocal(t.TempDir())
	opts := Options{Workers: 4, PackBytes: 8192}
	if _, err := RunWithOptions(ctx, packSource(t, data, 4096), "old", local, "local", opts); err != nil {
		t.Fatal(err)
	}
	data[0] ^= 7
	opts.BaseID = "old"
	opts.PackIdentity = checkpointchunks.PackIdentityChunks
	if _, err := RunWithOptions(ctx, packSource(t, data, 4096), "root", local, "local", opts); err != nil {
		t.Fatal(err)
	}
	m := assertPackedBytes(t, local, "root", data)
	modes := map[string]int{}
	for _, r := range m.Packs {
		modes[r.Identity]++
	}
	if m.Version != 3 || modes[""] != 3 || modes[checkpointchunks.PackIdentityChunks] != 1 {
		t.Fatalf("not mixed v3: %d %v", m.Version, modes)
	}
	// New legacy packs can coexist with inherited root packs, but the envelope
	// must stay v3 rather than silently giving an old reader unreadable refs.
	data[4096] ^= 3
	opts.BaseID = "root"
	opts.PackIdentity = ""
	if _, err := RunWithOptions(ctx, packSource(t, data, 4096), "mixed", local, "local", opts); err != nil {
		t.Fatal(err)
	}
	m = assertPackedBytes(t, local, "mixed", data)
	if m.Version != 3 {
		t.Fatal("inherited root pack downgraded to v2")
	}
}

func TestRootPackRejectsChangedPayload(t *testing.T) {
	ctx := context.Background()
	data := packData(2, 4096)
	dir := packSource(t, data, 4096)
	data[0] ^= 1
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0600); err != nil {
		t.Fatal(err)
	}
	local, _ := chunkstore.NewLocal(t.TempDir())
	if _, err := RunWithOptions(ctx, dir, "bad", local, "local", Options{Workers: 1, PackBytes: 8192, PackIdentity: checkpointchunks.PackIdentityChunks}); err == nil {
		t.Fatal("unverified root pack published")
	}
	if ok, err := local.HasKey(ctx, ArtifactKey("bad", IndexName)); err != nil || ok {
		t.Fatalf("INDEX exists=%v err=%v", ok, err)
	}
}

func TestExplicitPackPayloadBudgets(t *testing.T) {
	data := append(packData(69, 1<<20), bytes.Repeat([]byte{211}, 123)...)
	source := packSource(t, data, 1<<20)
	for _, tc := range []struct {
		budget, workers int
		cancel          bool
	}{{16, 64, false}, {32, 64, false}, {64, 64, false}, {64, 2, false}, {64, 64, true}} {
		t.Run(fmt.Sprintf("%d/%d/cancel=%v", tc.budget, tc.workers, tc.cancel), func(t *testing.T) {
			local, _ := chunkstore.NewLocal(t.TempDir())
			want := min(tc.workers, tc.budget/4)
			store := &packBudgetStore{Local: local, wantActive: want, started: make(chan struct{}), release: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var result Result
			var runErr error
			done := make(chan struct{})
			go func() {
				defer close(done)
				result, runErr = RunWithOptions(ctx, source, "explicit", store, "local", Options{Workers: tc.workers, PackBytes: 4 << 20, PackPayloadBytes: tc.budget << 20, PackIdentity: checkpointchunks.PackIdentityChunks})
			}()
			select {
			case <-store.started:
			case <-time.After(10 * time.Second):
				cancel()
				<-done
				t.Fatal("budget did not permit expected concurrency")
			}
			if tc.cancel {
				cancel()
			} else {
				close(store.release)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("workers did not converge")
			}
			store.mu.Lock()
			active, activeBytes, peak, peakBytes := store.active, store.activeBytes, store.peak, store.peakBytes
			store.mu.Unlock()
			if active != 0 || activeBytes != 0 || peak != want || peakBytes > tc.budget<<20 {
				t.Fatalf("active %d/%d peak %d/%d", active, activeBytes, peak, peakBytes)
			}
			if tc.cancel {
				if runErr == nil {
					t.Fatal("cancel ignored")
				}
				if exists, _ := local.HasKey(context.Background(), ArtifactKey("explicit", IndexName)); exists {
					t.Fatal("cancelled INDEX published")
				}
				return
			}
			if runErr != nil {
				t.Fatal(runErr)
			}
			if result.Workers != want || result.PackPayloadBudget != tc.budget<<20 || result.PackPayloadPeak > int64(tc.budget<<20) || result.PackPayloadPeak < int64(peakBytes) {
				t.Fatalf("incorrect measured budget: %+v", result)
			}
			assertPackedBytes(t, local, "explicit", data)
		})
	}
}
func TestInvalidPackPayloadHasNoSideEffects(t *testing.T) {
	for _, opts := range []Options{{PackPayloadBytes: 1}, {PackBytes: 4096, PackPayloadBytes: -1}, {PackBytes: 8192, PackPayloadBytes: 4096}, {PackBytes: 4096, PackPayloadBytes: (64 << 20) + 1}} {
		dir := t.TempDir()
		localRoot := t.TempDir()
		store, _ := chunkstore.NewLocal(localRoot)
		if _, err := RunWithOptions(context.Background(), dir, "invalid", store, "local", opts); err == nil {
			t.Fatal("invalid budget accepted")
		}
		files, _ := os.ReadDir(dir)
		objects, _ := os.ReadDir(localRoot)
		if len(files) != 0 || len(objects) != 0 {
			t.Fatal("invalid options changed state/store")
		}
	}
}
