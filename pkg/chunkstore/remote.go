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
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
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

// String names the endpoint in publish states and logs.
func (r *Remote) String() string { return r.baseURL }

// maxRemotePutBytes bounds Remote.Put: chunks are 256KiB-1MiB; anything
// larger must use PutKey with streaming (artifact files do).
const maxRemotePutBytes = 8 << 20

// All Remote instances share a bounded idle pool, including per-fault packed
// readers. Clone the standard transport rather than changing process globals.
// Applications that installed a custom RoundTripper retain that behavior.
var remoteTransport = sync.OnceValue(func() http.RoundTripper {
	return pooledRemoteTransport(http.DefaultTransport)
})

func pooledRemoteTransport(base http.RoundTripper) http.RoundTripper {
	if transport, ok := base.(*http.Transport); ok {
		clone := transport.Clone()
		clone.MaxIdleConnsPerHost = 64
		clone.MaxIdleConns = 128
		return clone
	}
	return base
}

// Open resolves a store specification to a backend: an http(s):// URL names
// the object backend (bucket endpoint root), anything else is a local
// directory tree.
func Open(spec string) (Store, error) {
	if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") {
		return &Remote{
			baseURL: strings.TrimRight(spec, "/"),
			client:  &http.Client{Transport: remoteTransport(), Timeout: 120 * time.Second},
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

// readRemoteChunk takes a stable copy before digest verification and upload.
// Only concrete standard memory readers provide a trusted remaining length;
// arbitrary Len methods and seekable files must not bypass the bounded path.
func readRemoteChunk(body io.Reader) ([]byte, error) {
	size := -1
	switch r := body.(type) {
	case *bytes.Reader:
		size = r.Len()
	case *bytes.Buffer:
		size = r.Len()
	case *strings.Reader:
		size = r.Len()
	}
	if size > maxRemotePutBytes {
		return nil, fmt.Errorf("remote Put is for chunks (>%d bytes); use PutKey", maxRemotePutBytes)
	}
	if size >= 0 {
		buf := make([]byte, size)
		if _, err := io.ReadFull(body, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	buf, err := io.ReadAll(io.LimitReader(body, maxRemotePutBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxRemotePutBytes {
		return nil, fmt.Errorf("remote Put is for chunks (>%d bytes); use PutKey", maxRemotePutBytes)
	}
	return buf, nil
}

func (r *Remote) Put(ctx context.Context, digest string, body io.Reader) error {
	// Chunks are small: buffer to verify the content hashes to its claimed
	// digest before the object ever lands (S3 PUTs are not transactional).
	buf, err := readRemoteChunk(body)
	if err != nil {
		return err
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
	// The S3 REST API rejects PUTs without a Content-Length (MinIO answers
	// 411); Go only sets it for known-length bodies, so spool anything else
	// through a buffer. Artifact files are KBs-to-overlay-sized; genuinely
	// huge objects want multipart, which this subset deliberately omits.
	if f, ok := body.(*os.File); ok {
		if info, err := f.Stat(); err == nil {
			body = io.NewSectionReader(f, 0, info.Size())
		}
	}
	if _, ok := body.(io.Seeker); !ok {
		buf, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	} else {
		// Seekables still need an explicit length or Go sends chunked
		// encoding, which S3 answers with 411.
		if end, err := body.(io.Seeker).Seek(0, io.SeekEnd); err == nil {
			if _, err := body.(io.Seeker).Seek(0, io.SeekStart); err == nil {
				if req2, err2 := http.NewRequestWithContext(ctx, http.MethodPut, url, body); err2 == nil {
					req2.ContentLength = end
					resp2, err3 := r.client.Do(req2)
					if err3 != nil {
						return err3
					}
					defer resp2.Body.Close()
					if resp2.StatusCode != http.StatusOK {
						return fmt.Errorf("PUT %s: status %d", url, resp2.StatusCode)
					}
					return nil
				}
			}
		}
	}
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

// ExclusivePutter is the atomic claim primitive over keyed objects: the PUT
// succeeds only when the key does not already exist (S3 conditional write
// If-None-Match:*; O_EXCL locally), and the conditional DELETE removes the
// object only while it still carries the caller's generation. The bucket
// sweep and the publishers use it to make deletion authority and reuse
// authority mutually exclusive per object — whoever wins the claim owns the
// key for the duration of one delete or one fenced re-upload, and only the
// owner (or a cleanup matching the observed generation) can end it.
type ExclusivePutter interface {
	// PutKeyIfAbsent uploads an object only when the key is free, reporting
	// whether this call created it. A store that cannot make the create
	// atomic must not implement the interface at all.
	PutKeyIfAbsent(ctx context.Context, key string, body io.Reader) (created bool, err error)
	// DeleteKeyIfMatch removes the object only while its ETag still equals
	// the caller's observation (S3 conditional DELETE If-Match). A 412
	// reports lost the race (someone replaced the object) as (false, nil).
	// The ETag of a claim body is the hex MD5 of its bytes (single-part
	// PUTs), so callers that know their own body never need a prior GET.
	DeleteKeyIfMatch(ctx context.Context, key, etag string) (deleted bool, err error)
}

// PutKeyIfAbsent implements the S3 conditional write: If-None-Match:* is
// honored as "create only" and answers 412 Precondition Failed when the
// object exists. Servers without conditional-write support answer 200 for
// the second writer too, which this method reports as an error rather than
// a silent win — callers rely on the mutual exclusion for correctness.
func (r *Remote) PutKeyIfAbsent(ctx context.Context, key string, body io.Reader) (bool, error) {
	buf, err := io.ReadAll(body)
	if err != nil {
		return false, err
	}
	url := r.baseURL + "/" + strings.TrimLeft(key, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(buf))
	if err != nil {
		return false, err
	}
	req.Header.Set("If-None-Match", "*")
	req.ContentLength = int64(len(buf))
	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// Prove ownership by reading the claim back: a store that ignores
		// If-None-Match answers 200 for an overwrite too, and mutual
		// exclusion would be fiction. Only the writer whose token reads
		// back owns the claim; anything else fails loud.
		got, err := r.GetKey(ctx, key)
		if err != nil {
			return false, fmt.Errorf("verify conditional PUT %s: %w", key, err)
		}
		defer got.Close()
		back, err := io.ReadAll(got)
		if err != nil {
			return false, fmt.Errorf("read back conditional PUT %s: %w", key, err)
		}
		if !bytes.Equal(back, buf) {
			return false, fmt.Errorf(
				"store does not honor If-None-Match on %s: claim was overwritten by a concurrent writer", key)
		}
		return true, nil
	case http.StatusPreconditionFailed:
		return false, nil
	default:
		return false, fmt.Errorf("conditional PUT %s: status %d", key, resp.StatusCode)
	}
}

// DeleteKeyIfMatch implements the S3 conditional delete: the DELETE only
// takes effect while the object's ETag still equals the observed one, so a
// claim replaced between observation and removal answers 412 and survives.
func (r *Remote) DeleteKeyIfMatch(ctx context.Context, key, etag string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, r.baseURL+"/"+strings.TrimLeft(key, "/"), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("If-Match", strings.Trim(etag, `"`))
	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return true, nil
	case http.StatusPreconditionFailed:
		return false, nil
	case http.StatusNotFound:
		// Already gone: nothing of that generation remains to protect.
		return false, nil
	default:
		return false, fmt.Errorf("conditional DELETE %s: status %d", key, resp.StatusCode)
	}
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
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.CreateTemp(path.Dir(target), ".key-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	if err := ctx.Err(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), target); err != nil {
		return err
	}
	dir, err := os.Open(path.Dir(target))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
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

// PutKeyIfAbsent creates the object exclusively: O_EXCL makes the create
// atomic, so exactly one concurrent writer can win a local claim.
func (l *Local) PutKeyIfAbsent(ctx context.Context, key string, r io.Reader) (bool, error) {
	target := path.Join(l.root, strings.TrimLeft(key, "/"))
	if err := os.MkdirAll(path.Dir(target), 0o755); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		os.Remove(target)
		return false, err
	}
	if err := ctx.Err(); err != nil {
		os.Remove(target)
		return false, err
	}
	if err := f.Sync(); err != nil {
		os.Remove(target)
		return false, err
	}
	dir, err := os.Open(path.Dir(target))
	if err != nil {
		return false, err
	}
	defer dir.Close()
	return true, dir.Sync()
}

// DeleteKeyIfMatch removes the object only while its content still hashes to
// the observed ETag: read, compare, and unlink under the local rename race
// window (single-writer stores make this exact; the guard is for parity with
// the remote conditional delete).
func (l *Local) DeleteKeyIfMatch(ctx context.Context, key, etag string) (bool, error) {
	target := path.Join(l.root, strings.TrimLeft(key, "/"))
	body, err := os.ReadFile(target)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	sum := md5.Sum(body)
	if strings.Trim(etag, `"`) != hex.EncodeToString(sum[:]) {
		return false, nil
	}
	return true, os.Remove(target)
}
