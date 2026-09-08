package server

import (
	"context"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type checkerLegacyCheckpoint interface {
	Checkpoint(context.Context, *runtime.CheckpointRequest) (*runtime.CheckpointResponse, error)
}
type checkerLegacyCheckpointServer struct{ calls atomic.Int32 }

func (s *checkerLegacyCheckpointServer) Checkpoint(context.Context, *runtime.CheckpointRequest) (*runtime.CheckpointResponse, error) {
	s.calls.Add(1)
	return &runtime.CheckpointResponse{}, nil
}
func TestCheckerConditionalCheckpointOldServerNeverFallsBack(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	legacy := &checkerLegacyCheckpointServer{}
	// Deliberately register only the old method, not the new generated descriptor.
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: runtime.SandboxService_ServiceDesc.ServiceName,
		HandlerType: (*checkerLegacyCheckpoint)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Checkpoint", Handler: func(s any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			req := new(runtime.CheckpointRequest)
			if err := dec(req); err != nil {
				return nil, err
			}
			return s.(checkerLegacyCheckpoint).Checkpoint(ctx, req)
		}}},
	}, legacy)
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close(); <-done })
	conn, err := grpc.NewClient("passthrough:///old-checkpoint", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	require.NoError(t, err)
	defer conn.Close()
	client := runtime.NewSandboxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := &runtime.CheckpointRequest{ID: "same-id", CheckpointDir: "/unused", TimeoutSeconds: 1}
	_, err = client.CheckpointIfGeneration(ctx, &runtime.CheckpointIfGenerationRequest{Checkpoint: req, ExpectedGeneration: "original-generation"})
	require.Equal(t, codes.Unimplemented, status.Code(err))
	require.Zero(t, legacy.calls.Load())
	_, err = client.Checkpoint(ctx, req)
	require.NoError(t, err)
	require.EqualValues(t, 1, legacy.calls.Load())
}
