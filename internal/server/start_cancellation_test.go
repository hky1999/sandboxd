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

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/testregistry"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type cancelStartHandler struct {
	svc.Handler
	starts atomic.Int32
}

func (h *cancelStartHandler) Start(context.Context, svc.StartConfig) error {
	h.starts.Add(1)
	return nil
}

func TestStartCancellationRollsBackBlockedOCIPreparation(t *testing.T) {
	for _, stage := range []string{"manifest", "config", "layer", "volume", "deadline"} {
		t.Run(stage, func(t *testing.T) {
			registryStage := stage
			if stage == "volume" || stage == "deadline" {
				registryStage = "layer"
			}
			registry := testregistry.New(t, registryStage)
			root := t.TempDir()
			manager, err := oci.NewManager(root, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { manager.Close() })
			worker, err := imageapi.NewHttpWorker(&imageapi.HttpWorkerConfig{OCIManager: manager})
			if err != nil {
				t.Fatal(err)
			}
			handler := &cancelStartHandler{Handler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunc: handler})
			s.fsMgr = newFSManager(worker)
			req := &runtime.StartRequest{SandboxID: "sbox-cancel-" + stage, Runtime: config.RuntimeNameRunc, Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_IMAGE, Source: &runtime.RootfsConfig_ImageUrl{ImageUrl: registry.ImageURL}}}
			if stage == "volume" {
				req.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL, Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}}
				req.Mounts = []*runtime.Mount{{Target: "/data", Options: []string{"ro"}, Source: &runtime.Mount_ImageUrl{ImageUrl: registry.ImageURL}}}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := codes.Canceled
			if stage == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				want = codes.DeadlineExceeded
			}
			done := make(chan error, 1)
			go func() { _, err := s.Start(ctx, req); done <- err }()
			select {
			case <-registry.Entered:
			case err := <-done:
				t.Fatalf("Start returned before download: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("download not reached")
			}
			if stage != "deadline" {
				cancel()
			}
			select {
			case err := <-done:
				if status.Code(err) != want {
					t.Fatalf("Start error = %v, want %s", err, want)
				}
			case <-time.After(2 * time.Second):
				registry.Unblock()
				<-done
				t.Fatal("Start did not cancel blocked preparation")
			}
			select {
			case <-registry.Canceled:
			case <-time.After(time.Second):
				t.Fatal("download connection still alive")
			}
			if handler.starts.Load() != 0 {
				t.Fatal("runtime started after cancellation")
			}
			if len(s.fsMgr.rootfs.List()) != 0 || len(s.fsMgr.sandboxState) != 0 {
				t.Fatal("filesystem ownership leaked")
			}
			mounts, err := manager.ListMountedDetails()
			if err != nil || len(mounts) != 0 {
				t.Fatalf("mounted OCI state = %v, %v", mounts, err)
			}
			err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if strings.HasPrefix(d.Name(), "tmp-") {
					t.Errorf("partial extraction leaked: %s", path)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.sandboxManager.ReserveID(req.SandboxID); err != nil {
				t.Fatalf("Start reservation was not rolled back: %v", err)
			}
			s.sandboxManager.ReleaseID(req.SandboxID)
		})
	}
}

type startFailureStream struct{ trailers metadata.MD }

func (*startFailureStream) Method() string               { return "/runtime.v1.SandboxService/Start" }
func (*startFailureStream) SetHeader(metadata.MD) error  { return nil }
func (*startFailureStream) SendHeader(metadata.MD) error { return nil }
func (s *startFailureStream) SetTrailer(md metadata.MD) error {
	s.trailers = metadata.Join(s.trailers, md)
	return nil
}

func TestStartFailurePreservesStageAndApplicationTimeout(t *testing.T) {
	for _, stage := range []string{"image pull (rootfs)", "runtime start (runc)"} {
		for _, cause := range []error{os.ErrDeadlineExceeded, context.DeadlineExceeded, status.Error(codes.DeadlineExceeded, "internal timer")} {
			stream := &startFailureStream{}
			ctx := grpc.NewContextWithServerTransportStream(context.Background(), stream)
			err := startFailure(ctx, stage, fmt.Errorf("operation failed: %w", cause))
			if status.Code(err) != codes.DeadlineExceeded || !strings.Contains(status.Convert(err).Message(), stage) {
				t.Fatalf("stage lost: %v", err)
			}
			if got := stream.trailers.Get("sandboxd-start-failure"); len(got) != 1 || got[0] != "true" {
				t.Fatalf("application failure missing: %v", got)
			}
		}
	}
	stream := &startFailureStream{}
	ctx := grpc.NewContextWithServerTransportStream(context.Background(), stream)
	if err := startFailure(ctx, "runtime start (runc)", errors.New("lost reply")); status.Code(err) == codes.DeadlineExceeded || len(stream.trailers) != 0 {
		t.Fatal(err, stream.trailers)
	}
}
