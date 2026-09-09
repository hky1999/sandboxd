package server

import (
	"context"
	"errors"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func sourceReviewWireClient(t *testing.T, s *sandboxService) runtime.SandboxServiceClient {
	t.Helper()
	l := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	runtime.RegisterSandboxServiceServer(server, s)
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(l) }()
	t.Cleanup(func() {
		s.checkpointOperations.shutdown()
		server.Stop()
		_ = l.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("gRPC server did not exit")
		}
	})
	conn, err := grpc.NewClient("passthrough:///source-operation", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return l.DialContext(ctx) }))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return runtime.NewSandboxServiceClient(conn)
}

func TestReviewSourceWireCallerCancelQueryReplay(t *testing.T) {
	h := newCheckpointOperationRuntimeHandler()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	h.checkpointFn = func(_ context.Context, c svc.CheckpointConfig) error {
		close(entered)
		<-release
		return writeSealedCheckpointDirectory(c.Directory)
	}
	s := newCheckpointOperationService(t, h, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-wire-cancel", "gen-wire")
	client := sourceReviewWireClient(t, s)
	req := checkpointOperationRequest("op-wire-cancel", "sbox-wire-cancel", filepath.Join(t.TempDir(), "checkpoint"), "gen-wire", 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { _, err := client.CheckpointWithOperation(ctx, req); errCh <- err }()
	awaitCheckpointOperationSignal(t, entered)
	cancel()
	select {
	case err := <-errCh:
		require.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("client cancellation did not return")
	}
	qctx, qcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer qcancel()
	query := &runtime.GetCheckpointOperationRequest{OperationID: req.OperationID}
	running, err := client.GetCheckpointOperation(qctx, query)
	require.NoError(t, err)
	require.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING, running.State)
	once.Do(func() { close(release) })
	var terminal *runtime.CheckpointOperationStatus
	require.Eventually(t, func() bool {
		r, e := client.GetCheckpointOperation(qctx, query)
		if e != nil {
			return false
		}
		terminal = r
		return r.State == runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED
	}, 4*time.Second, 10*time.Millisecond)
	replay, err := client.CheckpointWithOperation(qctx, req)
	require.NoError(t, err)
	require.Equal(t, terminal.ArtifactRootDigest, replay.ArtifactRootDigest)
	require.Equal(t, 1, h.checkpointCount())
}

func TestReviewSourceWireErrorRequiresSeparateQuery(t *testing.T) {
	h := newCheckpointOperationRuntimeHandler()
	h.checkpointFn = func(_ context.Context, c svc.CheckpointConfig) error {
		if err := writeSealedCheckpointDirectory(c.Directory); err != nil {
			return err
		}
		return errors.New("injected runtime-entered failure")
	}
	s := newCheckpointOperationService(t, h, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-wire-error", "gen-wire")
	client := sourceReviewWireClient(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := checkpointOperationRequest("op-wire-error", "sbox-wire-error", filepath.Join(t.TempDir(), "checkpoint"), "gen-wire", 5)
	response, err := client.CheckpointWithOperation(ctx, req)
	require.Error(t, err)
	require.Nil(t, response, "gRPC must not expose an error response payload")
	queried, err := client.GetCheckpointOperation(ctx, &runtime.GetCheckpointOperationRequest{OperationID: req.OperationID})
	require.NoError(t, err)
	require.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, queried.State)
	replay, err := client.CheckpointWithOperation(ctx, req)
	require.NoError(t, err)
	require.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, replay.State)
	require.Equal(t, 1, h.checkpointCount())
}
