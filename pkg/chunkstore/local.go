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

// Package chunkstore is the content-addressed blob store checkpoint chunks
// are published to. Objects are immutable and identified by their sha256:
// publishing the same bytes twice is a no-op, two generations sharing a
// page range share objects, and a consumer that fetches by digest can never
// receive the wrong bytes from a correct store.
//
// The first backend is a plain directory tree (root/<aa>/<digest>); the
// interface is deliberately shaped for object-storage and datasystem
// backends to follow without touching publishers or consumers.
package chunkstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// Store is the chunk blob backend contract.
type Store interface {
	// Put stores the bytes under their digest. Storing content that does
	// not hash to digest is an error; re-putting existing content is a
	// no-op (objects are immutable).
	Put(ctx context.Context, digest string, r io.Reader) error
	// Get streams the stored object for digest.
	Get(ctx context.Context, digest string) (io.ReadCloser, error)
	// Has reports whether digest is already stored.
	Has(ctx context.Context, digest string) (bool, error)
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Local is a directory-tree Store: root/<first two hex>/<digest>.
type Local struct {
	root string
}

// NewLocal opens (and creates) a directory-backed store.
func NewLocal(root string) (*Local, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &Local{root: root}, nil
}

func (l *Local) objectPath(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return filepath.Join(l.root, digest[:2], digest), nil
}

func (l *Local) Put(ctx context.Context, digest string, r io.Reader) error {
	path, err := l.objectPath(digest)
	if err != nil {
		return err
	}
	if ok, err := l.Has(ctx, digest); err != nil {
		return err
	} else if ok {
		return nil // immutable: the bytes are already there
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	hash := sha256.New()
	if _, err := io.Copy(tmp, io.TeeReader(r, hash)); err != nil {
		tmp.Close()
		return err
	}
	if got := hashHex(hash); got != digest {
		tmp.Close()
		return fmt.Errorf("content hashes to %s, claimed %s", got, digest)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Objects are immutable: an exclusive link loses only a concurrent
	// duplicate put of identical bytes.
	if err := os.Link(tmp.Name(), path); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func (l *Local) Get(ctx context.Context, digest string) (io.ReadCloser, error) {
	path, err := l.objectPath(digest)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("chunk %s not in store", digest)
	}
	return f, err
}

func (l *Local) Has(ctx context.Context, digest string) (bool, error) {
	path, err := l.objectPath(digest)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// ErrClosedChain guards against silent nil readers.
var ErrClosedChain = errors.New("chunkstore: nil reader")

func hashHex(h hashWriter) string { return hex.EncodeToString(h.Sum(nil)) }

// hashWriter is the small surface Put needs from a running hash.
type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}
