package identityresolver

import (
	"context"
	"encoding/json"
	"errors"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeClient struct {
	first, second *runtime.ListSandboxesResponse
	stats         *runtime.StatsResponse
	calls         int
	statsCalls    int
	err           error
}

func (f *fakeClient) List(ctx context.Context, _ *runtime.ListSandboxesRequest, _ ...grpc.CallOption) (*runtime.ListSandboxesResponse, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded resolver RPC")
	}
	f.calls++
	if f.calls == 1 {
		return f.first, f.err
	}
	return f.second, f.err
}
func (f *fakeClient) Stats(context.Context, *runtime.StatsRequest, ...grpc.CallOption) (*runtime.StatsResponse, error) {
	f.statsCalls++
	return f.stats, f.err
}
func runningStatus() *runtime.SandboxStatus {
	return &runtime.SandboxStatus{ID: "sandbox", Ip: "10.88.0.1", State: runtime.SandboxState_SANDBOX_STATE_RUNNING, Labels: map[string]string{InstanceLabel: "instance", RuntimeLabel: "runtime", GenerationLabel: "generation"}}
}
func TestResolverUsesUniqueLiveIdentityAndPhysicalReadback(t *testing.T) {
	for _, lookup := range []string{"ip", "instance"} {
		for _, mode := range []string{"valid", "duplicate", "exited", "missing-label", "missing-instance-label", "replaced", "wrong-stats-generation", "reassigned", "unavailable", "unauthorized"} {
			t.Run(lookup+"/"+mode, func(t *testing.T) {
				status := runningStatus()
				if lookup == "instance" {
					// Instance lookups must not depend on an assigned address.
					status.Ip = ""
				}
				first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{status}}
				second := proto.Clone(first).(*runtime.ListSandboxesResponse)
				client := &fakeClient{first: first, second: second, stats: &runtime.StatsResponse{ResourceGeneration: "generation"}}
				switch mode {
				case "duplicate":
					first.Sandboxes = append(first.Sandboxes, proto.Clone(status).(*runtime.SandboxStatus))
				case "exited":
					status.State = runtime.SandboxState_SANDBOX_STATE_EXITED
				case "missing-label":
					delete(status.Labels, RuntimeLabel)
				case "missing-instance-label":
					delete(status.Labels, InstanceLabel)
				case "replaced":
					second.Sandboxes[0].ID = "replacement"
				case "wrong-stats-generation":
					client.stats.ResourceGeneration = "replacement"
				case "reassigned":
					second.Sandboxes[0].Labels[GenerationLabel] = "replacement"
				case "unavailable":
					client.err = errors.New("private backend error")
				}
				token := strings.Repeat("x", 32)
				handler, err := New(client, token)
				if err != nil {
					t.Fatal(err)
				}
				query := "/resolve?ip=10.88.0.1"
				if lookup == "instance" {
					query = "/resolve?instance_id=instance"
				}
				req := httptest.NewRequest("GET", query, nil)
				if mode != "unauthorized" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				if mode == "valid" {
					var identity Identity
					if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &identity) != nil || identity.Instance != "instance" || identity.SandboxID != "sandbox" || identity.RuntimeID != "runtime" || identity.ResourceGeneration != "generation" || client.calls != 2 {
						t.Fatalf("invalid response %d %s", response.Code, response.Body.String())
					}
				} else if response.Code == 200 {
					t.Fatalf("accepted %s", mode)
				}
				if mode == "unauthorized" && client.calls != 0 {
					t.Fatal("unauthorized request queried daemon")
				}
				if strings.Contains(response.Body.String(), "private backend error") {
					t.Fatal("backend error leaked")
				}
			})
		}
	}
}
func TestResolverRejectsMalformedQueriesBeforeBackendCalls(t *testing.T) {
	queries := []string{
		"/resolve",
		"/resolve?ip=10.88.0.1&instance_id=instance",
		"/resolve?instance_id=instance&ip=10.88.0.1",
		"/resolve?ip=10.88.0.1&ip=10.88.0.1",
		"/resolve?ip=10.88.0.1&ip=10.88.0.2",
		"/resolve?instance_id=instance&instance_id=instance",
		"/resolve?ip=",
		"/resolve?instance_id=",
		"/resolve?ips=10.88.0.1",
		"/resolve?ip=10.88.0.1&instance_id=%ZZ",
		"/resolve?instance_id=%FF",
		"/resolve?ip=10.88.0.1&extra=1",
		"/resolve?ip=example",
		"/resolve?ip=2001:db8::1",
		"/resolve?instance_id=lead%20space",
		"/resolve?instance_id=tab%09x",
		"/resolve?instance_id=newline%0Ax",
		"/resolve?instance_id=del%7Fx",
		"/resolve?instance_id=" + strings.Repeat("i", 257),
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{runningStatus()}}
			client := &fakeClient{first: first, second: proto.Clone(first).(*runtime.ListSandboxesResponse), stats: &runtime.StatsResponse{ResourceGeneration: "generation"}}
			token := strings.Repeat("x", 32)
			handler, err := New(client, token)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", query, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != 400 {
				t.Fatalf("expected 400, got %d for %s", response.Code, query)
			}
			if client.calls != 0 || client.statsCalls != 0 {
				t.Fatalf("malformed query %s reached daemon", query)
			}
		})
	}
}
func TestResolverAcceptsMaximalInstanceId(t *testing.T) {
	instance := strings.Repeat("i", 256)
	status := runningStatus()
	status.Ip = ""
	status.Labels[InstanceLabel] = instance
	first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{status}}
	client := &fakeClient{first: first, second: proto.Clone(first).(*runtime.ListSandboxesResponse), stats: &runtime.StatsResponse{ResourceGeneration: "generation"}}
	token := strings.Repeat("x", 32)
	handler, err := New(client, token)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/resolve?instance_id="+instance, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	var identity Identity
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &identity) != nil || identity.Instance != instance || client.calls != 2 {
		t.Fatalf("invalid response %d %s", response.Code, response.Body.String())
	}
}
