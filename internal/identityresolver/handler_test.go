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
	return f.stats, f.err
}
func TestResolverUsesUniqueLiveIdentityAndPhysicalReadback(t *testing.T) {
	for _, mode := range []string{"valid", "duplicate", "exited", "missing-label", "wrong-stats-generation", "reassigned", "unavailable", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			status := &runtime.SandboxStatus{ID: "sandbox", Ip: "10.88.0.1", State: runtime.SandboxState_SANDBOX_STATE_RUNNING, Labels: map[string]string{InstanceLabel: "instance", RuntimeLabel: "runtime", GenerationLabel: "generation"}}
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
			req := httptest.NewRequest("GET", "/resolve?ip=10.88.0.1", nil)
			if mode != "unauthorized" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if mode == "valid" {
				var identity Identity
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &identity) != nil || identity.Instance != "instance" || identity.ResourceGeneration != "generation" || client.calls != 2 {
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
