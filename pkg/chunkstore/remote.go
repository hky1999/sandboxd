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
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// Remote is an HTTP object backend speaking the anonymous subset of the S3
// REST API (PUT/GET/HEAD on plain object keys) — MinIO with a public bucket
// policy is the reference endpoint, and any S3-compatible service with an
// anonymous-readable+writable bucket works unchanged. Object keys mirror the
// Local layout (<aa>/<digest>), so a store is portable between backends.
//
// Authentication (SigV4) is deliberately out of scope here: the deployment
// model is a cluster-internal endpoint, and adding signed access for public
// clouds is a client-wrapper change, not a layout change.
type Remote struct {
	baseURL string
	client  *http.Client
}

// maxRemotePutBytes bounds Remote.Put: chunks are 256KiB-1MiB; anything
// larger must use PutKey with streaming (artifact files do).
const maxRemotePutBytes = 8 << 20

// Open resolves a store specification to a backend: an http(s):// URL names
// the object backend (bucket endpoint root), anything else is a local
// directory tree.
func Open(spec string) (Store, error) {
	if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") {
		return &Remote{
			baseURL: strings.TrimRight(spec, "/"),
			client:  &http.Client{Timeout: 120 * time.Second},
		}, nil
	}
	return NewLocal(spec)
}

// Keyed is the streaming object surface artifact-set publication and
// materialization use; both backends implement it alongside Store.
type Keyed interface {
	// PutKey uploads an object at an arbitrary key, streaming (no size
	// bound, no digest check — callers hash and verify what they fetch).
	PutKey(ctx context.Context, key string, r io.Reader) error
	// GetKey streams an object by key; 404 surfaces as an error.
	GetKey(ctx context.Context, key string) (io.ReadCloser, error)
	// HasKey reports whether a keyed object exists.
	HasKey(ctx context.Context, key string) (bool, error)
}

func (r *Remote) objectURL(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return r.baseURL + "/" + digest[:2] + "/" + digest, nil
}

func (r *Remote) Put(ctx context.Context, digest string, body io.Reader) error {
	// Chunks are small: buffer to verify the content hashes to its claimed
	// digest before the object ever lands (S3 PUTs are not transactional).
	buf, err := io.ReadAll(io.LimitReader(body, maxRemotePutBytes+1))
	if err != nil {
		return err
	}
	if len(buf) > maxRemotePutBytes {
		return fmt.Errorf("remote Put is for chunks (>%d bytes); use PutKey", maxRemotePutBytes)
	}
	if got := sha256Hex(buf); got != digest {
		return fmt.Errorf("content hashes to %s, claimed %s", got, digest)
	}
	return r.PutKey(ctx, path.Join(digest[:2], digest), bytes.NewReader(buf))
}

func (r *Remote) Get(ctx context.Context, digest string) (io.ReadCloser, error) {
	url, err := r.objectURL(digest)
	if err != nil {
		return nil, err
	}
	return r.getKey(ctx, url)
}

func (r *Remote) Has(ctx context.Context, digest string) (bool, error) {
	url, err := r.objectURL(digest)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HEAD %s: status %d", url, resp.StatusCode)
	}
	return true, nil
}

func (r *Remote) PutKey(ctx context.Context, key string, body io.Reader) error {
	url := r.baseURL + "/" + strings.TrimLeft(key, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, body)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PUT %s: status %d", url, resp.StatusCode)
	}
	return nil
}

func (r *Remote) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return r.getKey(ctx, r.baseURL+"/"+strings.TrimLeft(key, "/"))
}

func (r *Remote) HasKey(ctx context.Context, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, r.baseURL+"/"+strings.TrimLeft(key, "/"), nil)
	if err != nil {
		return false, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return resp.StatusCode == http.StatusOK, nil
}

func (r *Remote) getKey(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, fmt.Errorf("object %s not in store", url)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Local implements Keyed with the same key layout as object paths.
func (l *Local) PutKey(ctx context.Context, key string, r io.Reader) error {
	target := path.Join(l.root, strings.TrimLeft(key, "/"))
	if err := os.MkdirAll(path.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.Create(target)
	if err != nil {
		if os.IsExist(err) {
			return nil // objects are immutable; identical key, identical bytes
		}
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}

func (l *Local) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	f, err := os.Open(path.Join(l.root, strings.TrimLeft(key, "/")))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("object %s not in store", key)
	}
	return f, err
}

func (l *Local) HasKey(ctx context.Context, key string) (bool, error) {
	_, err := os.Stat(path.Join(l.root, strings.TrimLeft(key, "/")))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
