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

package imageregistry

import (
	"context"
	"errors"
	"fmt"
	registrytransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/internal/testregistry"
)

func TestRegistryBodyPreservesCancellationAtEOF(t *testing.T) {
	for _, mode := range []string{"live", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := error(nil)
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
				defer cancel()
				want = context.DeadlineExceeded
			}
			transport := &registryTransport{roundTripper: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body := &eofOnCancelBody{}
				if mode == "cancel" {
					body.finish = cancel
				} else if mode == "deadline" {
					body.finish = func() { <-ctx.Done() }
				}
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			})}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://registry.example/v2/image/manifests/latest", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if mode == "cancel" {
				// A server may finish its chunked body as it observes the
				// disconnect, racing the client's cancellation error.
				want = context.Canceled
			}
			if _, err := io.ReadAll(resp.Body); !errors.Is(err, want) {
				t.Fatalf("body error = %v, want %v", err, want)
			}
		})
	}
}

type eofOnCancelBody struct{ finish func() }

func (b *eofOnCancelBody) Read([]byte) (int, error) {
	if b.finish != nil {
		b.finish()
	}
	return 0, io.EOF
}

func (*eofOnCancelBody) Close() error { return nil }

func TestFetchImageCancellationInterruptsBlockedResponse(t *testing.T) {
	for _, stage := range []string{"manifest", "config", "layer"} {
		t.Run(stage, func(t *testing.T) {
			registry := testregistry.New(t, stage)
			client, err := NewClient("")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				image, err := client.FetchImageWithFallback(ctx, registry.ImageURL, "")
				if err == nil {
					_, err = image.ConfigFile()
				}
				if err == nil {
					layers, e := image.Layers()
					err = e
					if err == nil {
						rc, e := layers[0].Uncompressed()
						err = e
						if err == nil {
							_, err = io.Copy(io.Discard, rc)
							rc.Close()
						}
					}
				}
				done <- err
			}()
			select {
			case <-registry.Entered:
			case err := <-done:
				t.Fatalf("request ended before blocked %s: %v", stage, err)
			case <-time.After(5 * time.Second):
				t.Fatal("registry was not reached")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				registry.Unblock()
				<-done
				t.Fatal("canceled request remained blocked on registry response")
			}
			select {
			case <-registry.Canceled:
			case <-time.After(time.Second):
				t.Fatal("registry did not observe disconnected download")
			}
		})
	}
}

// Cancelling one HTTP/2 stream must not close the connection carrying another
// image consumer's request, including cancellation before response headers.
func TestCancellationKeepsOtherHTTP2RequestsAlive(t *testing.T) {
	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol = %s, want HTTP/2", r.Proto)
		}
		if r.URL.Path == "/first" {
			close(firstEntered)
			<-r.Context().Done()
			return
		}
		close(secondEntered)
		select {
		case <-release:
			_, _ = w.Write([]byte("ok"))
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	base := server.Client().Transport.(*http.Transport).Clone()
	base.MaxConnsPerHost = 1
	defer base.CloseIdleConnections()
	client := &http.Client{Transport: &registryTransport{base: base}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/first", nil)
	first := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		first <- err
	}()
	select {
	case <-firstEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("first request not reached")
	}
	second := make(chan error, 1)
	go func() {
		resp, err := client.Post(server.URL+"/second", "text/plain", nil)
		if resp != nil {
			defer resp.Body.Close()
			_, err = io.Copy(io.Discard, resp.Body)
		}
		second <- err
	}()
	select {
	case <-secondEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("second stream not reached")
	}
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first request not canceled")
	}
	close(release)
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("cancelling first stream interrupted second: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second request did not finish")
	}
}

func TestRegistryRejectionsKeepTheirErrorCategory(t *testing.T) {
	for _, tc := range []struct {
		http int
		grpc codes.Code
	}{
		{400, codes.InvalidArgument}, {401, codes.Unauthenticated}, {403, codes.PermissionDenied},
		{404, codes.NotFound}, {429, codes.ResourceExhausted}, {503, codes.Unavailable},
		{408, codes.DeadlineExceeded}, {504, codes.DeadlineExceeded},
	} {
		source := &registrytransport.Error{StatusCode: tc.http}
		wrapped := ClassifyError(fmt.Errorf("manifest rejected: %w", source))
		if !errors.Is(wrapped, source) {
			t.Fatal("lost registry cause", wrapped)
		}
		if ClassifyError(wrapped) != wrapped {
			t.Fatal("classification duplicated the cause", wrapped)
		}
		got := status.Code(errord.ToGRPC(wrapped))
		if got != tc.grpc {
			t.Fatalf("HTTP %d: got %v want %v", tc.http, got, tc.grpc)
		}
	}
	source := errors.New("connection reset by peer")
	if got := ClassifyError(source); got != source {
		t.Fatal(got)
	}
}
