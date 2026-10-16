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

package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/internal/testregistry"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
)

func TestHTTPMountCancellationFinishesWorkerRollback(t *testing.T) {
	registry := testregistry.New(t, "layer")
	manager, err := oci.NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	worker, err := NewHttpWorker(&HttpWorkerConfig{OCIManager: manager})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	mux := worker.prepareHttp()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); mux.ServeHTTP(w, r) }))
	defer server.Close()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	client := &HttpClient{clt: &http.Client{Transport: transport}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := client.MountOCI(ctx, &OCIMountRequest{ImageURL: registry.ImageURL}); result <- err }()
	select {
	case <-registry.Entered:
	case err := <-result:
		t.Fatalf("request failed before body: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("download not reached")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		registry.Unblock()
		<-result
		t.Fatal("HTTP client did not cancel")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		registry.Unblock()
		<-finished
		t.Fatal("HTTP worker kept running after disconnect")
	}
	mounts, err := manager.ListMountedDetails()
	if err != nil || len(mounts) != 0 {
		t.Fatalf("mounts=%v, err=%v", mounts, err)
	}
	select {
	case <-registry.Canceled:
	case <-time.After(time.Second):
		t.Fatal("registry download not closed")
	}
}
