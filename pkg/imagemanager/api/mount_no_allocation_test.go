// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func noAllocationClient(t *testing.T, result MountOperationResult) *HttpClient {
	t.Helper()
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	return &HttpClient{clt: &http.Client{Transport: mountOperationTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
}

type noAllocationService struct {
	Service
	client *HttpClient
}

func (s *noAllocationService) QueryMountOperation(query *MountOperationQuery) (*MountOperationResult, error) {
	return s.client.QueryMountOperation(query)
}

func (s *noAllocationService) RetireMountOperation(req *MountOperationRetirement) (*MountOperationResult, error) {
	return s.client.RetireMountOperation(req)
}

func TestMountOperationNoAllocationClientAcceptsOriginalTerminalProof(t *testing.T) {
	query := &MountOperationQuery{OperationID: strings.Repeat("a", 64), RequestFingerprint: strings.Repeat("b", 64)}
	proof := MountOperationResult{OperationID: query.OperationID, RequestFingerprint: query.RequestFingerprint, Kind: "oss", State: "not_allocated"}
	result, err := noAllocationClient(t, proof).QueryMountOperation(query)
	require.NoError(t, err, "an original no-allocation tombstone has no physical generation or target")
	require.Equal(t, proof, *result)
}

func TestMountOperationNoAllocationConsumerAcceptsProofOnlyForCleanup(t *testing.T) {
	req := &OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	fp, err := MountRequestFingerprint(req)
	require.NoError(t, err)
	proof := MountOperationResult{OperationID: req.OperationID, RequestFingerprint: fp, Kind: "oss", State: "not_allocated"}
	client := &noAllocationService{client: noAllocationClient(t, proof)}
	_, err = QueryOriginalMountOperation(client, req, req.OperationID, "oss", false)
	require.Error(t, err, "a terminal no-allocation proof cannot authorize a new acquisition")
	result, err := QueryOriginalMountOperation(client, req, req.OperationID, "oss", true)
	require.NoError(t, err, "authorized cleanup can consume the original terminal proof")
	require.Equal(t, proof, *result)
}

func nativeNoAllocationWorker(t *testing.T) (*HttpWorker, distillfs.Manager, *distillfs.ManagerConfig) {
	t.Helper()
	m, cfg := workerOwnershipManager(t)
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: m, DBPath: filepath.Join(cfg.Root, "mounts.db")})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	return w, m, cfg
}

func noAllocationRetirement(t *testing.T, request any, id, kind, facade string) *MountOperationRetirement {
	t.Helper()
	fp, err := MountRequestFingerprint(request)
	require.NoError(t, err)
	return &MountOperationRetirement{OperationID: id, RequestFingerprint: fp, Kind: kind, ImageURL: facade}
}

func TestMountOperationNoAllocationNativeFenceSurvivesFullReopenAndRejectsLateProducer(t *testing.T) {
	for _, kind := range []string{"oss", "nydus", "oci"} {
		t.Run(kind, func(t *testing.T) {
			w, m, cfg := nativeNoAllocationWorker(t)
			id, facade := strings.Repeat("a", 64), ""
			var request any
			switch kind {
			case "oss":
				request = &OSSMountRequest{OperationID: id, Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
			case "nydus":
				request = &NydusMountRequest{OperationID: id, ImageURL: "registry.example/original:fixed"}
			case "oci":
				facade = "registry.example/original:fixed"
				request = &OCIMountRequest{OperationID: id, ImageURL: facade, RequirePhysicalGeneration: true}
			}
			req := noAllocationRetirement(t, request, id, kind, facade)
			query := &MountOperationQuery{id, req.RequestFingerprint}
			result, err := w.QueryMountOperation(query)
			require.NoError(t, err)
			require.Equal(t, "absent", result.State)
			_, err = w.executeMountOperation(id, kind, facade, "", request, func(mountBinding) (*MountInfo, error) {
				return nil, errors.New("controlled failure before native allocation")
			})
			require.Error(t, err)
			result, err = w.QueryMountOperation(query)
			require.NoError(t, err)
			require.Equal(t, "intent", result.State, "read-only absence never closes an intent")
			result, err = w.RetireMountOperation(req)
			require.NoError(t, err)
			require.Equal(t, "not_allocated", result.State)
			require.Empty(t, result.PhysicalGeneration)
			require.Empty(t, result.MountPoint)
			require.NoError(t, w.CloseWithContext(context.Background()))
			require.NoError(t, m.(distillfs.ManagerLifecycle).Close(context.Background()))
			m, err = distillfs.NewManager(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, m.(distillfs.ManagerLifecycle).Close(context.Background())) })
			w, err = NewHttpWorker(&HttpWorkerConfig{Manager: m, DBPath: filepath.Join(cfg.Root, "mounts.db")})
			require.NoError(t, err)
			t.Cleanup(w.Close)
			confirmed, err := w.QueryMountOperation(query)
			require.NoError(t, err)
			require.Equal(t, result, confirmed)
			switch r := request.(type) {
			case *OSSMountRequest:
				_, err = w.MountOSS(r)
			case *NydusMountRequest:
				_, err = w.MountNydus(r)
			case *OCIMountRequest:
				_, err = w.MountOCI(r)
			}
			require.ErrorContains(t, err, "without allocation")
			allocations, err := filepath.Glob(filepath.Join(cfg.Root, "allocations", "*"))
			require.NoError(t, err)
			require.Empty(t, allocations, "a delayed original request must not allocate after retirement")
		})
	}
}

func TestMountOperationNoAllocationPreemptiveFenceDoesNotNeedAProducerRecord(t *testing.T) {
	w, _, _ := nativeNoAllocationWorker(t)
	id := strings.Repeat("c", 64)
	r := &OSSMountRequest{OperationID: id, Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	req := noAllocationRetirement(t, r, id, "oss", "")
	proof, err := w.RetireMountOperation(req)
	require.NoError(t, err)
	require.Equal(t, "not_allocated", proof.State)
	_, err = w.MountOSS(r)
	require.Error(t, err)
	for _, change := range []func(*MountOperationRetirement){
		func(r *MountOperationRetirement) { r.RequestFingerprint = strings.Repeat("d", 64) },
		func(r *MountOperationRetirement) { r.Kind = "nydus" },
	} {
		changed := *req
		change(&changed)
		_, err := w.RetireMountOperation(&changed)
		require.Error(t, err)
	}
	// Replaying the original completion must not consult or touch a replacement.
	w.mgr = newMockManager()
	replayed, err := w.RetireMountOperation(req)
	require.NoError(t, err)
	require.Equal(t, proof, replayed)
}

func TestMountOperationNoAllocationActiveProducerCannotBeSettled(t *testing.T) {
	w, _, _ := nativeNoAllocationWorker(t)
	id := strings.Repeat("a", 64)
	r := &OSSMountRequest{OperationID: id, Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	req := noAllocationRetirement(t, r, id, "oss", "")
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	})
	go func() {
		_, err := w.executeMountOperation(id, "oss", "", "", r, func(mountBinding) (*MountInfo, error) {
			close(entered)
			<-finish
			return nil, errors.New("producer stopped before allocating")
		})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("producer did not enter")
	}
	retired := make(chan error, 1)
	go func() { _, err := w.RetireMountOperation(req); retired <- err }()
	select {
	case err := <-retired:
		require.ErrorContains(t, err, "still active")
	case <-time.After(time.Second):
		t.Fatal("cleanup waited behind the active producer")
	}
	query := &MountOperationQuery{id, req.RequestFingerprint}
	result, err := w.QueryMountOperation(query)
	require.NoError(t, err)
	require.Equal(t, "intent", result.State)
	close(finish)
	require.Error(t, <-done)
	result, err = w.RetireMountOperation(req)
	require.NoError(t, err)
	require.Equal(t, "not_allocated", result.State)
	w.operationLocksMu.Lock()
	remainingLocks := len(w.operationLocks)
	w.operationLocksMu.Unlock()
	require.Zero(t, remainingLocks, "unsuccessful try-lock must release its reference")
}

func TestMountOperationNoAllocationExistingPreparationRemainsOwnedForCleanup(t *testing.T) {
	w, m, _ := nativeNoAllocationWorker(t)
	id := strings.Repeat("b", 64)
	r := &OSSMountRequest{OperationID: id, Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	opts := &distillfs.DaemonCreateOpt{ID: generateOSSID(r.Endpoint, r.Bucket, r.Object), Name: "root.erofs"}
	_, err := w.executeMountOperation(id, "oss", "", "", r, func(bind mountBinding) (*MountInfo, error) {
		failed := *bind
		failed.publish = func(string, string, string, string) error { return errors.New("upper binding interrupted") }
		return nil, w.prepareDaemonForMount(opts, &failed)
	})
	require.Error(t, err)
	req := noAllocationRetirement(t, r, id, "oss", "")
	original, err := w.QueryMountOperation(&MountOperationQuery{id, req.RequestFingerprint})
	require.NoError(t, err)
	result, err := w.RetireMountOperation(req)
	require.NoError(t, err)
	require.Equal(t, "release_pending", result.State)
	require.Equal(t, original.PhysicalGeneration, result.PhysicalGeneration)
	require.NotEmpty(t, result.MountPoint)
	require.NoError(t, m.GetDaemon(opts.ID).UnmountIfPhysicalGeneration(result.PhysicalGeneration))
	result, err = w.RetireMountOperation(req)
	require.NoError(t, err)
	require.Equal(t, "released", result.State)
}

func TestMountOperationNoAllocationLegacyIntentAndUnsupportedManagerRemainUnknown(t *testing.T) {
	w, _, _ := nativeNoAllocationWorker(t)
	id := strings.Repeat("a", 64)
	r := &OSSMountRequest{OperationID: id, Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	req := noAllocationRetirement(t, r, id, "oss", "")
	_, _, err := w.mountStore.beginMountOperation(&mountOperationRecord{OperationID: id, RequestFingerprint: req.RequestFingerprint, Kind: "oss", Phase: "intent"})
	require.NoError(t, err)
	_, err = w.RetireMountOperation(req)
	require.ErrorContains(t, err, "legacy")
	result, err := w.QueryMountOperation(&MountOperationQuery{id, req.RequestFingerprint})
	require.NoError(t, err)
	require.Equal(t, "intent", result.State)
	w.mgr = newMockManager()
	req.OperationID = strings.Repeat("c", 64)
	_, err = w.RetireMountOperation(req)
	require.ErrorContains(t, err, "authoritative")
	w.Close()
	_, err = w.RetireMountOperation(req)
	require.ErrorContains(t, err, "closing")
}

func TestMountOperationNoAllocationHTTPStrictRequestAndIndependentReadback(t *testing.T) {
	w, _, _ := nativeNoAllocationWorker(t)
	r := &OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "objects.example", Bucket: "original", Object: "root.erofs", AccessKeyID: "controlled-private-id", AccessKeySecret: "controlled-private-value"}
	req := noAllocationRetirement(t, r, r.OperationID, "oss", "")
	posted, queried := 0, 0
	client := &HttpClient{clt: &http.Client{Transport: mountOperationTestTransport(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.NotContains(t, string(body), r.AccessKeyID)
		require.NotContains(t, string(body), r.AccessKeySecret)
		request.Body = io.NopCloser(strings.NewReader(string(body)))
		writer := httptest.NewRecorder()
		switch request.URL.Path {
		case "/mount_operation_retire":
			posted++
			w.serveMountOperationRetirement(writer, request)
		case "/mount_operation_query":
			queried++
			w.serveMountOperationQuery(writer, request)
		default:
			t.Fatalf("unexpected fallback %s", request.URL.Path)
		}
		return writer.Result(), nil
	})}}
	proof, err := RetireOriginalMountOperation(&noAllocationService{client: client}, r, r.OperationID, "oss")
	require.NoError(t, err)
	require.Equal(t, "not_allocated", proof.State)
	require.Equal(t, 1, posted)
	require.Equal(t, 1, queried, "the consumer must independently confirm the persisted proof")
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	invalid := []string{
		strings.TrimSuffix(string(raw), "}") + `,"kind":"oss"}`,
		string(raw) + ` {}`,
		strings.Replace(string(raw), `"kind"`, `"Kind"`, 1),
		strings.TrimSuffix(string(raw), "}") + `,"access_key_secret":"unexpected"}`,
		`{}`,
		strings.Repeat(" ", mountRecordLimit+1),
	}
	for _, body := range invalid {
		writer := httptest.NewRecorder()
		w.serveMountOperationRetirement(writer, httptest.NewRequest(http.MethodPost, "/mount_operation_retire", strings.NewReader(body)))
		require.Equal(t, http.StatusBadRequest, writer.Code)
	}
	writer := httptest.NewRecorder()
	w.serveMountOperationRetirement(writer, httptest.NewRequest(http.MethodGet, "/mount_operation_retire", nil))
	require.Equal(t, http.StatusMethodNotAllowed, writer.Code)
}

type noAllocationFailureManager struct {
	distillfs.Manager
	preparation       distillfs.PreparationRetirementManager
	afterConfirmation func()
}

func (m *noAllocationFailureManager) PrepareDaemon(opts *distillfs.DaemonCreateOpt, owner distillfs.PreparationOwner, bind func(string, string) error) error {
	return m.preparation.PrepareDaemon(opts, owner, bind)
}

func (m *noAllocationFailureManager) FindPreparation(owner distillfs.PreparationOwner) (*distillfs.PreparationInfo, error) {
	return m.preparation.FindPreparation(owner)
}

func (m *noAllocationFailureManager) ConfirmNoPreparation(owner distillfs.PreparationOwner) error {
	if err := m.preparation.ConfirmNoPreparation(owner); err != nil {
		return err
	}
	if m.afterConfirmation != nil {
		callback := m.afterConfirmation
		m.afterConfirmation = nil
		callback()
	}
	return nil
}

func TestMountOperationNoAllocationWriteFailureCannotPublishProof(t *testing.T) {
	w, m, _ := nativeNoAllocationWorker(t)
	path := w.mountStore.db.Path()
	w.mgr = &noAllocationFailureManager{Manager: m, preparation: m.(distillfs.PreparationRetirementManager), afterConfirmation: func() { require.NoError(t, w.mountStore.Close()) }}
	r := &OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	_, err := w.executeMountOperation(r.OperationID, "oss", "", "", r, func(mountBinding) (*MountInfo, error) { return nil, errors.New("not dispatched") })
	require.Error(t, err)
	req := noAllocationRetirement(t, r, r.OperationID, "oss", "")
	proof, err := w.RetireMountOperation(req)
	require.Error(t, err)
	require.Nil(t, proof)
	w.mountStore, err = OpenMountStore(path)
	require.NoError(t, err)
	result, err := w.QueryMountOperation(&MountOperationQuery{r.OperationID, req.RequestFingerprint})
	require.NoError(t, err)
	require.Equal(t, "intent", result.State, "native absence without a durable fence remains unknown")
	result, err = w.RetireMountOperation(req)
	require.NoError(t, err)
	require.Equal(t, "not_allocated", result.State)
}

func TestMountOperationNoAllocationJournalFullRefusesNewFence(t *testing.T) {
	w, _, _ := nativeNoAllocationWorker(t)
	// The private capacity fixture needs only occupied completion keys; these
	// opaque neighbors are not queried or used as any completion authority.
	require.NoError(t, w.mountStore.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(mountCompletionsBucket)
		for i := 0; i < mountJournalLimit; i++ {
			if err := bucket.Put([]byte(fmt.Sprintf("capacity-%08d", i)), []byte("occupied")); err != nil {
				return err
			}
		}
		return nil
	}))
	r := &OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	req := noAllocationRetirement(t, r, r.OperationID, "oss", "")
	proof, err := w.RetireMountOperation(req)
	require.ErrorContains(t, err, "full")
	require.Nil(t, proof)
	result, err := w.QueryMountOperation(&MountOperationQuery{r.OperationID, req.RequestFingerprint})
	require.NoError(t, err)
	require.Equal(t, "absent", result.State)
}

func TestMountOperationNoAllocationMalformedPhysicalProofIsRejected(t *testing.T) {
	r := &OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	fp, err := MountRequestFingerprint(r)
	require.NoError(t, err)
	for _, mutate := range []func(*MountOperationResult){
		func(p *MountOperationResult) { p.PhysicalGeneration = strings.Repeat("c", 64) },
		func(p *MountOperationResult) { p.MountPoint = "/replacement" },
		func(p *MountOperationResult) { p.RequestFingerprint = strings.Repeat("d", 64) },
		func(p *MountOperationResult) { p.OperationID = strings.Repeat("e", 64) },
		func(p *MountOperationResult) { p.Kind = "nydus" },
	} {
		proof := MountOperationResult{OperationID: r.OperationID, RequestFingerprint: fp, Kind: "oss", State: "not_allocated"}
		mutate(&proof)
		_, err := QueryOriginalMountOperation(&noAllocationService{client: noAllocationClient(t, proof)}, r, r.OperationID, "oss", true)
		require.Error(t, err)
	}
}

func TestMountOperationNoAllocationConcurrentLateRequestsCannotCrossFence(t *testing.T) {
	w, _, cfg := nativeNoAllocationWorker(t)
	r := &OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	req := noAllocationRetirement(t, r, r.OperationID, "oss", "")
	proof, err := w.RetireMountOperation(req)
	require.NoError(t, err)
	var requests sync.WaitGroup
	results := make(chan error, 16)
	for i := 0; i < 8; i++ {
		requests.Add(2)
		go func() { defer requests.Done(); _, err := w.MountOSS(r); results <- err }()
		go func() { defer requests.Done(); _, err := w.RetireMountOperation(req); results <- err }()
	}
	requests.Wait()
	close(results)
	failed := 0
	for err := range results {
		if err != nil {
			failed++
		}
	}
	require.GreaterOrEqual(t, failed, 8, "every late mount must be refused")
	confirmed, err := w.QueryMountOperation(&MountOperationQuery{r.OperationID, req.RequestFingerprint})
	require.NoError(t, err)
	require.Equal(t, proof, confirmed)
	entries, err := filepath.Glob(filepath.Join(cfg.Root, "allocations", "*"))
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestMountOperationNoAllocationRetirementWithoutMatchingReadbackIsRejected(t *testing.T) {
	r := &OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
	fp, err := MountRequestFingerprint(r)
	require.NoError(t, err)
	proof := MountOperationResult{OperationID: r.OperationID, RequestFingerprint: fp, Kind: "oss", State: "not_allocated"}
	calls := 0
	client := &HttpClient{clt: &http.Client{Transport: mountOperationTestTransport(func(request *http.Request) (*http.Response, error) {
		calls++
		result := proof
		if request.URL.Path == "/mount_operation_query" {
			result.State = "intent"
		}
		raw, err := json.Marshal(result)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	_, err = RetireOriginalMountOperation(&noAllocationService{client: client}, r, r.OperationID, "oss")
	require.Error(t, err, "the cleanup consumer needs a separate persisted completion observation")
	require.Equal(t, 2, calls)
}
