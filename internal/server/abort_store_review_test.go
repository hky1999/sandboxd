package server

import (
	"context"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReviewAbortStorePublicationBarrier(t *testing.T) {
	root := t.TempDir()
	req := checkpointOperationRequest("op-review-abort", "sbox-review-abort", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
	draft := recoveryDraftForRequest(t, req)
	record := seededCheckpointOperationRecord(req, "runsc", draft.RequestDigest, checkpointOperationPhaseUnknown, "")
	record.Version = checkpointOperationRecordVersionAbortable
	seedCheckpointOperationRecord(t, root, record)
	service := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
	s := service.checkpointOperations
	a, joined, err := s.abortExistingContext(context.Background(), draft)
	if err != nil || a == nil || joined != nil {
		t.Fatalf("admission: %v", err)
	}
	defer a.finish()
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var writes atomic.Int32
	s.persistHook = func(r *checkpointOperationRecord) error {
		if writes.Add(1) == 1 {
			close(entered)
			<-release
		}
		return s.durablyWrite(r)
	}
	done := make(chan error, 1)
	go func() { done <- a.markAborted("confirmed by runtime") }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer never entered hook")
	}
	queried := make(chan error, 1)
	go func() {
		q, e := service.GetCheckpointOperation(context.Background(), &runtime.GetCheckpointOperationRequest{OperationID: req.OperationID})
		if e == nil && q.State != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN {
			e = context.Canceled
		}
		queried <- e
	}()
	select {
	case err := <-queried:
		if err != nil {
			t.Fatalf("query exposed terminal or failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("query blocked behind durable write")
	}
	published, _ := s.published(req.OperationID)
	if published.AbortConfirmed {
		t.Fatal("abort confirmation published before persistence")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if r, j, e := s.recoverExistingContext(ctx, draft); e == nil || r != nil || j != nil {
		t.Fatal("recovery bypassed held admission lock")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writer failed to converge")
	}
	published, _ = s.published(req.OperationID)
	if !published.AbortConfirmed || published.Phase != checkpointOperationPhaseFailed {
		t.Fatal("confirmed failure not published")
	}
	a.finish()
	retry, j, e := s.abortExistingContext(context.Background(), draft)
	if e != nil || retry == nil || j != nil || !retry.acknowledgmentOnly() {
		t.Fatalf("not ack-only: %v", e)
	}
	defer retry.finish()
	if err = retry.markAborted("replay"); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 {
		t.Fatal("ack-only replay rewrote outcome")
	}
}
