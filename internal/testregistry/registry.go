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

// Package testregistry provides a real OCI registry whose response can be held until cancellation.
package testregistry

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type Registry struct {
	ImageURL    string
	Entered     chan struct{}
	Canceled    chan struct{}
	Release     chan struct{}
	server      *httptest.Server
	releaseOnce sync.Once
}

// New serves a valid one-layer image and holds the selected manifest/config/layer response.
func New(t testing.TB, stage string) *Registry {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "file", Mode: 0644, Size: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := img.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	config, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	configHash, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := layer.Digest()
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := layer.Compressed()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(compressed)
	compressed.Close()
	if err != nil {
		t.Fatal(err)
	}
	r := &Registry{Entered: make(chan struct{}), Canceled: make(chan struct{}), Release: make(chan struct{})}
	var entered, canceled sync.Once
	r.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body []byte
		var current string
		switch {
		case req.URL.Path == "/v2/":
			w.WriteHeader(200)
			return
		case strings.Contains(req.URL.Path, "/manifests/"):
			body = manifest
			current = "manifest"
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		case strings.HasSuffix(req.URL.Path, configHash.String()):
			body = config
			current = "config"
		case strings.HasSuffix(req.URL.Path, hash.String()):
			body = data
			current = "layer"
		default:
			http.NotFound(w, req)
			return
		}
		if current == stage && req.Method == http.MethodGet {
			// Flush headers to exercise cancellation while a body read is blocked.
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			entered.Do(func() { close(r.Entered) })
			select {
			case <-req.Context().Done():
				canceled.Do(func() { close(r.Canceled) })
				return
			case <-r.Release:
			}
		}
		_, _ = w.Write(body)
	}))
	r.ImageURL = strings.TrimPrefix(r.server.URL, "https://") + "/image:latest"
	t.Cleanup(func() { r.Unblock(); r.server.Close() })
	return r
}

func (r *Registry) Unblock() { r.releaseOnce.Do(func() { close(r.Release) }) }
