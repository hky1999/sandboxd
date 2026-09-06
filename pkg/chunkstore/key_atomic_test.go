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
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type brokenKeyReader struct{}

func (brokenKeyReader) Read(b []byte) (int, error) {
	return copy(b, "partial"), errors.New("injected reader failure")
}
func TestLocalKeyFailurePreservesCommittedObject(t *testing.T) {
	root := t.TempDir()
	store, _ := NewLocal(root)
	ctx := context.Background()
	if err := store.PutKey(ctx, "packs/existing", strings.NewReader("committed")); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"packs/existing", "packs/absent"} {
		if err := store.PutKey(ctx, key, brokenKeyReader{}); err == nil {
			t.Fatal("failure swallowed")
		}
	}
	f, err := store.GetKey(ctx, "packs/existing")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(data) != "committed" {
		t.Fatalf("old object lost: %q %v", data, err)
	}
	if ok, _ := store.HasKey(ctx, "packs/absent"); ok {
		t.Fatal("partial object visible")
	}
	entries, err := os.ReadDir(filepath.Join(root, "packs"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temp files remain: %v %v", entries, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.PutKey(cancelled, "packs/existing", strings.NewReader("bad")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

type pausedKeyReader struct {
	started, release chan struct{}
	once             bool
}

func (r *pausedKeyReader) Read(b []byte) (int, error) {
	if !r.once {
		r.once = true
		close(r.started)
		return copy(b, "first"), nil
	}
	<-r.release
	return 0, io.EOF
}
func TestLocalKeyIsInvisibleUntilComplete(t *testing.T) {
	store, _ := NewLocal(t.TempDir())
	reader := &pausedKeyReader{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- store.PutKey(context.Background(), "packs/new", reader) }()
	<-reader.started
	visible, err := store.HasKey(context.Background(), "packs/new")
	close(reader.release)
	if writeErr := <-done; writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil || visible {
		t.Fatalf("partial key visible: %v %v", visible, err)
	}
	if exists, err := store.HasKey(context.Background(), "packs/new"); err != nil || !exists {
		t.Fatalf("completed key missing: %v %v", exists, err)
	}
}
