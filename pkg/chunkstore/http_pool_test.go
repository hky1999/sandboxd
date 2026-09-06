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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Each wave requires all sixteen simultaneous requests to reach the server
// before any response completes. This exposes idle eviction between waves.
func connectionWaves(t *testing.T, transport http.RoundTripper) int64 {
	t.Helper()
	const workers = 16
	var connections atomic.Int64
	gates := make([]chan struct{}, 4)
	arrivals := make([]chan struct{}, 4)
	for i := range gates {
		gates[i] = make(chan struct{})
		arrivals[i] = make(chan struct{}, workers)
	}
	payload := bytes.Repeat([]byte{37}, 4096)
	digest := sha256Hex(payload)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		wave, err := strconv.Atoi(parts[0])
		if err != nil || wave < 0 || wave >= len(gates) {
			t.Error("bad wave")
			w.WriteHeader(400)
			return
		}
		arrivals[wave] <- struct{}{}
		select {
		case <-gates[wave]:
		case <-r.Context().Done():
			return
		}
		switch r.Method {
		case "HEAD":
			w.Header().Set("Content-Length", "4096")
			w.WriteHeader(200)
		case "PUT":
			body, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(body, payload) || !strings.HasSuffix(r.URL.Path, "/"+digest) {
				t.Error("bad PUT payload")
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(200)
		case "GET":
			http.ServeContent(w, r, "pack", time.Time{}, bytes.NewReader([]byte("abcdefgh")))
		default:
			t.Error("bad method")
			w.WriteHeader(400)
		}
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for wave := range gates {
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store := &Remote{baseURL: fmt.Sprintf("%s/%d", server.URL, wave), client: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
				switch wave {
				case 0, 3:
					ok, err := store.Has(ctx, digest)
					if err != nil || !ok {
						t.Errorf("HEAD %v %v", ok, err)
					}
				case 1:
					if err := store.Put(ctx, digest, bytes.NewReader(payload)); err != nil {
						t.Error(err)
					}
				case 2:
					data, err := store.ReadKeyRange(ctx, "pack", ObjectRange{Offset: 2, Length: 4, ObjectSize: 8})
					if err != nil || string(data) != "cdef" {
						t.Errorf("range %q %v", data, err)
					}
				}
			}()
		}
		for i := 0; i < workers; i++ {
			select {
			case <-arrivals[wave]:
			case <-ctx.Done():
				t.Fatal("wave failed to arrive")
			}
		}
		close(gates[wave])
		wg.Wait()
	}
	return connections.Load()
}

func TestHTTPPoolWaveProbe(t *testing.T) {
	for _, idle := range []int{2, 64} {
		t.Run(fmt.Sprint(idle), func(t *testing.T) {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.MaxIdleConnsPerHost = idle
			transport.MaxIdleConns = 128
			defer transport.CloseIdleConnections()
			connections := connectionWaves(t, transport)
			t.Logf("64 requests, idle_per_host=%d, TCP connections=%d", idle, connections)
			if idle == 64 && connections != 16 {
				t.Fatalf("pool did not retain connections: %d", connections)
			}
			if idle == 2 && connections <= 16 {
				t.Fatalf("probe did not expose eviction: %d", connections)
			}
		})
	}
}

func TestRemotePoolSharedWithoutGlobalMutation(t *testing.T) {
	base := http.DefaultTransport.(*http.Transport)
	oldHost, oldGlobal := base.MaxIdleConnsPerHost, base.MaxIdleConns
	a, _ := Open("http://127.0.0.1:1/a")
	b, _ := Open("http://127.0.0.1:2/b")
	at := a.(*Remote).client.Transport
	bt := b.(*Remote).client.Transport
	if at != bt || at == base {
		t.Fatal("Remote pool is not shared and private")
	}
	tr := at.(*http.Transport)
	if tr.MaxIdleConnsPerHost != 64 || tr.MaxIdleConns != 128 || tr.IdleConnTimeout != base.IdleConnTimeout || tr.ForceAttemptHTTP2 != base.ForceAttemptHTTP2 || tr.TLSHandshakeTimeout != base.TLSHandshakeTimeout {
		t.Fatal("wrong pool/defaults")
	}
	if base.MaxIdleConnsPerHost != oldHost || base.MaxIdleConns != oldGlobal || http.DefaultTransport != base {
		t.Fatal("mutated process default")
	}
	local := pooledRemoteTransport(base).(*http.Transport)
	defer local.CloseIdleConnections()
	if got := connectionWaves(t, local); got != 16 {
		t.Fatalf("factory lost reuse: %d", got)
	}
}

func TestRemotePoolHonorsCustomRoundTripper(t *testing.T) {
	var calls atomic.Int64
	custom := uploadTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header), Request: r}, nil
	})
	client := &http.Client{Transport: pooledRemoteTransport(custom)}
	resp, err := client.Get("http://unused.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls.Load() != 1 {
		t.Fatal("custom transport bypassed")
	}
}

func TestRemotePoolEndpointIsolationAndCancellation(t *testing.T) {
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "a") }))
	defer a.Close()
	started := make(chan struct{})
	b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wait" {
			close(started)
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "b")
	}))
	defer b.Close()
	tr := pooledRemoteTransport(a.Client().Transport).(*http.Transport)
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		for _, tc := range []struct{ url, want string }{{a.URL, "a"}, {b.URL, "b"}} {
			resp, err := client.Get(tc.url)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != tc.want {
				t.Fatalf("crossed endpoints: %q %v", body, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", b.URL+"/wait", nil)
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request not started")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation ignored")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel hung")
	}
}
