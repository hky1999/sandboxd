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

package firecracker

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startInstanceInfoStub serves one fixed GET / answer on a unix socket and
// returns the API client for it.
func startInstanceInfoStub(t *testing.T, handler http.HandlerFunc) *firecrackerAPI {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		<-serverDone
		_ = os.Remove(socket)
	})
	return newFirecrackerAPI(socket)
}

// TestInstanceInfoReadsBoundedInstanceInfo proves the happy read: one 200
// answer with the real InstanceInfo shape decodes into the bounded subset.
func TestInstanceInfoReadsBoundedInstanceInfo(t *testing.T) {
	api := startInstanceInfoStub(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/" {
			t.Errorf("instance info request = %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(
			`{"app_name":"Firecracker","id":"sbox-1","state":"Running","vmm_version":"1.9.0"}`,
		))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := api.instanceInfo(ctx)
	if err != nil {
		t.Fatalf("instanceInfo = %v", err)
	}
	if info.ID != "sbox-1" || info.State != firecrackerInstanceInfoStateRunning {
		t.Fatalf("instanceInfo = %+v", info)
	}
}

// TestInstanceInfoRefusesUnusableAnswers proves every unusable answer fails
// closed: another status, a non-JSON body, trailing content, a missing
// instance id, an unknown state, and an oversized body are all explicit
// errors, never a guessed state.
func TestInstanceInfoRefusesUnusableAnswers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		fragment string
	}{
		{name: "internal error", status: http.StatusInternalServerError, body: `{"error":"boom"}`, fragment: "500"},
		{name: "not json", status: http.StatusOK, body: `<html>nope</html>`, fragment: "not InstanceInfo JSON"},
		{name: "trailing content", status: http.StatusOK, body: `{"id":"s","state":"Running"}{}`, fragment: "trailing content"},
		{name: "missing id", status: http.StatusOK, body: `{"state":"Running"}`, fragment: "no instance id"},
		{name: "unknown state", status: http.StatusOK, body: `{"id":"s","state":"Halting"}`, fragment: "unknown MicroVM state"},
		{name: "missing state", status: http.StatusOK, body: `{"id":"s"}`, fragment: "unknown MicroVM state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := startInstanceInfoStub(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(tc.status)
				_, _ = writer.Write([]byte(tc.body))
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := api.instanceInfo(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.fragment) {
				t.Fatalf("instanceInfo(%s) = %v, want refusal naming %q", tc.name, err, tc.fragment)
			}
		})
	}
	t.Run("oversized body", func(t *testing.T) {
		api := startInstanceInfoStub(t, func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(make([]byte, firecrackerInstanceInfoMaxBytes+1))
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := api.instanceInfo(ctx)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversized instanceInfo = %v, want the size refusal", err)
		}
	})
}
