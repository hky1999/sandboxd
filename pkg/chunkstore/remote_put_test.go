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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type readerOnly struct{ io.Reader }
type misleadingLenReader struct{ io.Reader }

func (misleadingLenReader) Len() int { return 1 }

type failingChunkReader struct{}

func (failingChunkReader) Read(p []byte) (int, error) {
	copy(p, "bad")
	return 3, errors.New("injected read error")
}

func TestRemotePutPreservesBytesAndOffset(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		data, err := io.ReadAll(r.Body)
		if err != nil || r.Method != "PUT" || r.URL.Path != "/"+sha256Hex(data)[:2]+"/"+sha256Hex(data) || r.ContentLength != int64(len(data)) {
			t.Errorf("request method=%s path=%s length=%d bytes=%d err=%v", r.Method, r.URL.Path, r.ContentLength, len(data), err)
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	store, _ := Open(server.URL)
	for _, n := range []int{0, 7, 262144, maxRemotePutBytes} {
		data := bytes.Repeat([]byte{37}, n)
		for _, kind := range []string{"bytes", "string", "buffer", "unknown", "misleading"} {
			t.Run(fmt.Sprintf("%s/%d", kind, n), func(t *testing.T) {
				full := append([]byte("prefix"), data...)
				var reader io.Reader
				switch kind {
				case "bytes":
					r := bytes.NewReader(full)
					r.Seek(6, io.SeekStart)
					reader = r
				case "string":
					r := strings.NewReader(string(full))
					r.Seek(6, io.SeekStart)
					reader = r
				case "buffer":
					r := bytes.NewBuffer(full)
					r.Next(6)
					reader = r
				case "unknown":
					reader = readerOnly{bytes.NewReader(data)}
				case "misleading":
					reader = misleadingLenReader{bytes.NewReader(data)}
				}
				before := requests.Load()
				if err := store.Put(context.Background(), sha256Hex(data), reader); err != nil {
					t.Fatal(err)
				}
				if requests.Load() != before+1 {
					t.Fatal("request not sent")
				}
			})
		}
	}
}

func TestRemotePutRejectsBeforeHTTP(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	store, _ := Open(server.URL)
	for name, reader := range map[string]io.Reader{
		"known-oversized":   bytes.NewReader(make([]byte, maxRemotePutBytes+1)),
		"unknown-oversized": readerOnly{bytes.NewReader(make([]byte, maxRemotePutBytes+1))},
		"read-error":        failingChunkReader{}, "wrong-digest": bytes.NewReader([]byte("bad")),
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.Put(context.Background(), sha256Hex([]byte("good")), reader); err == nil {
				t.Fatal("bad upload accepted")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatal("unverified bytes reached HTTP")
	}
}

func TestRemotePutConcurrentHTTP(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil || !strings.HasSuffix(r.URL.Path, "/"+sha256Hex(data)) {
			t.Error("corrupted concurrent body")
			w.WriteHeader(400)
			return
		}
		requests.Add(1)
	}))
	defer server.Close()
	store, _ := Open(server.URL)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := bytes.Repeat([]byte{byte(i)}, 262144)
			if err := store.Put(context.Background(), sha256Hex(data), bytes.NewReader(data)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if requests.Load() != 64 {
		t.Fatalf("requests %d", requests.Load())
	}
}

type discardUploadTransport struct{}

func (discardUploadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	_, err := io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header), Request: r}, nil
}
func BenchmarkRemotePutBuffered(b *testing.B) {
	for _, n := range []int{262144, 1048576} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			data := bytes.Repeat([]byte{37}, n)
			digest := sha256Hex(data)
			store := &Remote{baseURL: "http://store.invalid", client: &http.Client{Transport: discardUploadTransport{}}}
			b.ReportAllocs()
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := store.Put(context.Background(), digest, bytes.NewReader(data)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type uploadTransportFunc func(*http.Request) (*http.Response, error)

func (f uploadTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRemotePutOwnsVerifiedBuffer(t *testing.T) {
	data := []byte("verified payload")
	want := append([]byte(nil), data...)
	store := &Remote{baseURL: "http://store.invalid", client: &http.Client{Transport: uploadTransportFunc(func(r *http.Request) (*http.Response, error) {
		// Runs after verification, before the transport consumes the body. Mutation
		// is synchronous: this tests ownership, not an unsupported reader data race.
		clear(data)
		got, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("verified body was borrowed: %q %v", got, err)
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header), Request: r}, nil
	})}}
	if err := store.Put(context.Background(), sha256Hex(want), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
}
