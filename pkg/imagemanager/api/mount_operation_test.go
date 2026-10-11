// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestMountOperationMissingJournalStopsBeforeDaemonAllocation(t *testing.T) {
	mgr := newMockManager()
	calls := 0
	mgr.createDaemonFunc = func(*distillfs.DaemonCreateOpt) error { calls++; return nil }
	w := mustNewHttpWorker(t, mgr)
	var req OSSMountRequest
	require.NoError(t, json.Unmarshal([]byte(`{"operation_id":"`+strings.Repeat("a", 64)+`","endpoint":"https://objects.example","bucket":"original","object":"root.erofs"}`), &req))
	_, err := w.MountOSS(&req)
	require.Error(t, err)
	require.Zero(t, calls, "a durable caller operation must exist before allocating its daemon")
}

func mountOperationFixture(t *testing.T) (*HttpWorker, *OCIMountRequest, *mountOperationRecord) {
	t.Helper()
	w, route := routingRetentionWorker(t)
	request := &OCIMountRequest{OperationID: strings.Repeat("c", 64), RequirePhysicalGeneration: true, ImageURL: route.ImageURL}
	fingerprint, err := MountRequestFingerprint(request)
	require.NoError(t, err)
	record := &mountOperationRecord{OperationID: request.OperationID, RequestFingerprint: fingerprint, Kind: "oci", Phase: "bound", ImageURL: route.ImageURL, NydusImageURL: route.NydusImageURL, DaemonID: generateNydusID(route.NydusImageURL), PhysicalGeneration: strings.Repeat("a", 64), MountPoint: route.MountPoint}
	return w, request, record
}

func seedMountOperation(t *testing.T, w *HttpWorker, binding *mountOperationRecord) {
	t.Helper()
	intent := *binding
	intent.Phase, intent.PhysicalGeneration, intent.DaemonID, intent.MountPoint, intent.NydusImageURL = "intent", "", "", "", ""
	_, fresh, err := w.mountStore.beginMountOperation(&intent)
	require.NoError(t, err)
	require.True(t, fresh)
	require.NoError(t, w.mountStore.publishMountBinding(binding))
}

func completeMountOperationSource(t *testing.T, w *HttpWorker, record *mountOperationRecord) {
	t.Helper()
	route := &MountRecord{ImageURL: record.ImageURL, MountType: "nydus", NydusImageURL: record.NydusImageURL, MountPoint: record.MountPoint, PhysicalGeneration: record.PhysicalGeneration}
	require.NoError(t, w.mountStore.Put(route.ImageURL, route))
	require.NoError(t, w.mountStore.DeleteIfRecord(route.ImageURL, route))
}

func reopenMountOperationWorker(t *testing.T, w *HttpWorker) {
	t.Helper()
	path := w.mountStore.db.Path()
	require.NoError(t, w.mountStore.Close())
	var err error
	w.mountStore, err = OpenMountStore(path)
	require.NoError(t, err)
}

func TestMountOperationLostReplyReopensOriginalBindingWithoutRedispatch(t *testing.T) {
	w, request, record := mountOperationFixture(t)
	dispatches := 0
	_, err := w.executeMountOperation(request.OperationID, "oci", request.ImageURL, "", request, func(bind mountBinding) (*MountInfo, error) {
		dispatches++
		require.NoError(t, bind(record.DaemonID, record.NydusImageURL, record.PhysicalGeneration, record.MountPoint))
		return nil, errors.New("success reply was lost")
	})
	require.Error(t, err)
	reopenMountOperationWorker(t, w)
	query := &MountOperationQuery{record.OperationID, record.RequestFingerprint}
	result, err := w.QueryMountOperation(query)
	require.NoError(t, err)
	require.Equal(t, "unresolved", result.State, "missing physical readback cannot invent ready or not-started")
	require.Equal(t, record.PhysicalGeneration, result.PhysicalGeneration)
	completeMountOperationSource(t, w, record)
	replacement := &MountRecord{ImageURL: record.ImageURL, MountType: "nydus", NydusImageURL: record.NydusImageURL, MountPoint: record.MountPoint, PhysicalGeneration: strings.Repeat("b", 64)}
	require.NoError(t, w.mountStore.Put(record.ImageURL, replacement))
	lookups := 0
	w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	result, err = w.QueryMountOperation(query)
	require.NoError(t, err)
	require.Equal(t, "released", result.State)
	response, err := w.MountOCI(request)
	require.NoError(t, err)
	require.True(t, response.Released)
	require.Equal(t, record.PhysicalGeneration, response.PhysicalGeneration)
	require.Equal(t, 1, dispatches)
	require.Zero(t, lookups, "old completion must precede any replacement lookup")
	current, err := w.mountStore.Get(record.ImageURL)
	require.NoError(t, err)
	require.Equal(t, replacement, current)
}

func TestMountOperationConfirmationFailureKeepsQueryableOriginalBinding(t *testing.T) {
	w, request, record := mountOperationFixture(t)
	path := w.mountStore.db.Path()
	_, err := w.executeMountOperation(request.OperationID, "oci", request.ImageURL, "", request, func(bind mountBinding) (*MountInfo, error) {
		require.NoError(t, bind(record.DaemonID, record.NydusImageURL, record.PhysicalGeneration, record.MountPoint))
		require.NoError(t, w.mountStore.Close()) // Producer succeeded; confirmation cannot be written.
		return &MountInfo{MountPoint: record.MountPoint, PhysicalGeneration: record.PhysicalGeneration}, nil
	})
	require.Error(t, err)
	w.mountStore, err = OpenMountStore(path)
	require.NoError(t, err)
	query := &MountOperationQuery{record.OperationID, record.RequestFingerprint}
	stored, err := w.mountStore.getMountOperation(query)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Equal(t, "bound", stored.Phase)
	completeMountOperationSource(t, w, record)
	result, err := w.QueryMountOperation(query)
	require.NoError(t, err)
	require.Equal(t, "released", result.State)
	require.Equal(t, record.PhysicalGeneration, result.PhysicalGeneration)
}

func TestMountOperationSharedJournalCapacityStopsBeforeDispatch(t *testing.T) {
	w, request, _ := mountOperationFixture(t)
	require.NoError(t, w.mountStore.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(mountOperationsBucket)
		for i := 0; i < mountJournalLimit-1; i++ {
			if err := bucket.Put([]byte(fmt.Sprintf("controlled-capacity-%d", i)), []byte("capacity fixture")); err != nil {
				return err
			}
		}
		return nil
	}))
	dispatches := 0
	_, err := w.executeMountOperation(request.OperationID, "oci", request.ImageURL, "", request, func(mountBinding) (*MountInfo, error) { dispatches++; return nil, nil })
	require.ErrorContains(t, err, "journal is full")
	require.Zero(t, dispatches)
}

func TestMountOperationIntentReopenNeverBlindlyDispatches(t *testing.T) {
	w, request, record := mountOperationFixture(t)
	dispatches := 0
	for attempt := 0; attempt < 2; attempt++ {
		_, err := w.executeMountOperation(request.OperationID, "oci", request.ImageURL, "", request, func(mountBinding) (*MountInfo, error) {
			dispatches++
			return nil, errors.New("dispatch outcome unknown")
		})
		require.Error(t, err)
		if attempt == 0 {
			reopenMountOperationWorker(t, w)
		}
	}
	require.Equal(t, 1, dispatches)
	result, err := w.QueryMountOperation(&MountOperationQuery{record.OperationID, record.RequestFingerprint})
	require.NoError(t, err)
	require.Equal(t, "intent", result.State)
	require.Empty(t, result.PhysicalGeneration)
}

func TestMountOperationAbsenceQueryHasNoRegistrationOrPhysicalEffects(t *testing.T) {
	w, _, record := mountOperationFixture(t)
	lookups := 0
	w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	result, err := w.QueryMountOperation(&MountOperationQuery{record.OperationID, record.RequestFingerprint})
	require.NoError(t, err)
	require.Equal(t, "absent", result.State)
	require.Empty(t, result.PhysicalGeneration)
	require.Zero(t, lookups)
	require.NoError(t, w.mountStore.db.View(func(tx *bolt.Tx) error { require.Zero(t, tx.Bucket(mountOperationsBucket).Stats().KeyN); return nil }))
}

func TestMountOperationChangedCredentialsCannotReuseOriginalRequest(t *testing.T) {
	w, _, _ := mountOperationFixture(t)
	request := &OSSMountRequest{OperationID: strings.Repeat("d", 64), Endpoint: "https://objects.example", Bucket: "original", Object: "root.erofs", AccessKeyID: "controlled-test-key", AccessKeySecret: "controlled-test-secret"}
	dispatches := 0
	_, err := w.executeMountOperation(request.OperationID, "oss", "", "", request, func(mountBinding) (*MountInfo, error) { dispatches++; return nil, errors.New("unknown") })
	require.Error(t, err)
	request.AccessKeySecret = "different-controlled-secret"
	_, err = w.executeMountOperation(request.OperationID, "oss", "", "", request, func(mountBinding) (*MountInfo, error) { dispatches++; return nil, nil })
	require.ErrorContains(t, err, "request changed")
	require.Equal(t, 1, dispatches)
	require.NoError(t, w.mountStore.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(mountOperationsBucket).Get([]byte(request.OperationID))
		require.NotContains(t, string(raw), "controlled-test-key")
		require.NotContains(t, string(raw), "controlled-test-secret")
		return nil
	}))
}

func TestMountOperationKnownBindingCannotChangeOrRegress(t *testing.T) {
	w, _, record := mountOperationFixture(t)
	seedMountOperation(t, w, record)
	query := &MountOperationQuery{record.OperationID, record.RequestFingerprint}
	require.NoError(t, w.mountStore.confirmMountOperation(query, record.PhysicalGeneration, record.MountPoint))
	replacement := *record
	replacement.PhysicalGeneration = strings.Repeat("b", 64)
	require.Error(t, w.mountStore.publishMountBinding(&replacement))
	require.NoError(t, w.mountStore.publishMountBinding(record))
	require.Error(t, w.mountStore.confirmMountOperation(query, replacement.PhysicalGeneration, replacement.MountPoint))
	got, err := w.mountStore.getMountOperation(query)
	require.NoError(t, err)
	require.Equal(t, "ready", got.Phase)
	require.Equal(t, record.PhysicalGeneration, got.PhysicalGeneration)
}

func TestMountOperationCorruptionAndAmbiguousFieldsStopBeforeBackend(t *testing.T) {
	for _, mode := range []string{"checksum", "duplicate", "case", "missing", "trailing", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			w, _, record := mountOperationFixture(t)
			seedMountOperation(t, w, record)
			require.NoError(t, w.mountStore.db.Update(func(tx *bolt.Tx) error {
				bucket := tx.Bucket(mountOperationsBucket)
				raw := bytes.Clone(bucket.Get([]byte(record.OperationID)))
				switch mode {
				case "checksum":
					raw = bytes.Replace(raw, []byte(record.MountPoint), []byte("/changed"), 1)
				case "duplicate":
					raw = bytes.Replace(raw, []byte(`"phase":`), []byte(`"phase":"ready","phase":`), 1)
				case "case":
					raw = bytes.Replace(raw, []byte(`"phase":`), []byte(`"Phase":`), 1)
				case "missing":
					raw = bytes.Replace(raw, []byte(`"phase":"bound",`), nil, 1)
				case "trailing":
					raw = append(raw, []byte(` {}`)...)
				case "oversized":
					raw = append(raw, bytes.Repeat([]byte(" "), mountRecordLimit)...)
				}
				return bucket.Put([]byte(record.OperationID), raw)
			}))
			lookups := 0
			w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
			_, err := w.QueryMountOperation(&MountOperationQuery{record.OperationID, record.RequestFingerprint})
			require.Error(t, err)
			require.Zero(t, lookups)
		})
	}
}

func TestMountOperationIndependentQueryDuringDispatchAndDuplicateSerialization(t *testing.T) {
	w, request, record := mountOperationFixture(t)
	entered, finish := make(chan struct{}), make(chan struct{})
	var dispatches atomic.Int32
	var wg sync.WaitGroup
	dispatch := func(bind mountBinding) (*MountInfo, error) {
		dispatches.Add(1)
		close(entered)
		<-finish
		if err := bind(record.DaemonID, record.NydusImageURL, record.PhysicalGeneration, record.MountPoint); err != nil {
			return nil, err
		}
		return &MountInfo{MountPoint: record.MountPoint, PhysicalGeneration: record.PhysicalGeneration}, nil
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = w.executeMountOperation(request.OperationID, "oci", request.ImageURL, "", request, dispatch)
	}()
	<-entered
	queryDone := make(chan *MountOperationResult, 1)
	go func() {
		result, _ := w.QueryMountOperation(&MountOperationQuery{record.OperationID, record.RequestFingerprint})
		queryDone <- result
	}()
	select {
	case result := <-queryDone:
		require.NotNil(t, result)
		require.Equal(t, "intent", result.State)
	case <-time.After(time.Second):
		close(finish)
		wg.Wait()
		t.Fatal("independent query waited for producer dispatch")
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = w.executeMountOperation(request.OperationID, "oci", request.ImageURL, "", request, dispatch)
	}()
	close(finish)
	wg.Wait()
	require.Equal(t, int32(1), dispatches.Load())
	require.Empty(t, w.operationLocks)
}

func TestMountOperationQueryEndpointRejectsAmbiguityAndReplaysOriginal(t *testing.T) {
	w, _, record := mountOperationFixture(t)
	seedMountOperation(t, w, record)
	completeMountOperationSource(t, w, record)
	query := &MountOperationQuery{record.OperationID, record.RequestFingerprint}
	raw, err := json.Marshal(query)
	require.NoError(t, err)
	for _, input := range [][]byte{bytes.Replace(raw, []byte(`"operation_id":`), []byte(`"operation_id":"invalid","operation_id":`), 1), append(bytes.Clone(raw), []byte(` {}`)...)} {
		recorder := httptest.NewRecorder()
		w.prepareHttp().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mount_operation_query", bytes.NewReader(input)))
		require.Equal(t, http.StatusBadRequest, recorder.Code)
	}
	recorder := httptest.NewRecorder()
	w.prepareHttp().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mount_operation_query", bytes.NewReader(raw)))
	require.Equal(t, http.StatusOK, recorder.Code)
	var result MountOperationResult
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &result))
	require.Equal(t, record.OperationID, result.OperationID)
	require.Equal(t, "released", result.State)
}

func TestMountOperationAmbiguousDispatchRequestStopsBeforeRegistration(t *testing.T) {
	for _, mode := range []string{"duplicate", "case", "trailing", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			w, _, _ := mountOperationFixture(t)
			calls := 0
			w.mgr.(*mockManager).createDaemonFunc = func(*distillfs.DaemonCreateOpt) error { calls++; return nil }
			body := `{"operation_id":"` + strings.Repeat("a", 64) + `","endpoint":"https://objects.example","bucket":"original","object":"root.erofs"}`
			switch mode {
			case "duplicate":
				body = strings.Replace(body, `"operation_id":`, `"operation_id":"`+strings.Repeat("b", 64)+`","operation_id":`, 1)
			case "case":
				body = strings.Replace(body, `"operation_id":`, `"Operation_ID":`, 1)
			case "trailing":
				body += ` {}`
			case "oversized":
				body += strings.Repeat(" ", mountRecordLimit)
			}
			recorder := httptest.NewRecorder()
			w.prepareHttp().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/oss_mount", strings.NewReader(body)))
			require.Equal(t, http.StatusBadRequest, recorder.Code)
			require.Zero(t, calls)
			require.NoError(t, w.mountStore.db.View(func(tx *bolt.Tx) error { require.Zero(t, tx.Bucket(mountOperationsBucket).Stats().KeyN); return nil }))
		})
	}
}

type mountOperationTestTransport func(*http.Request) (*http.Response, error)

func (f mountOperationTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMountOperationClientRejectsChangedOrAmbiguousReply(t *testing.T) {
	query := &MountOperationQuery{strings.Repeat("c", 64), strings.Repeat("d", 64)}
	for _, body := range []string{
		`{"operation_id":"` + strings.Repeat("a", 64) + `","request_fingerprint":"` + query.RequestFingerprint + `","state":"absent"}`,
		`{"operation_id":"` + query.OperationID + `","request_fingerprint":"` + query.RequestFingerprint + `","state":"absent","state":"ready"}`,
		`{"operation_id":"` + query.OperationID + `","request_fingerprint":"` + query.RequestFingerprint + `","state":"ready"}`,
	} {
		client := &HttpClient{clt: &http.Client{Transport: mountOperationTestTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}}
		_, err := client.QueryMountOperation(query)
		require.Error(t, err)
	}
}

func TestMountOperationInvalidIdentityStopsBeforeDaemonAllocation(t *testing.T) {
	mgr := newMockManager()
	calls := 0
	mgr.createDaemonFunc = func(*distillfs.DaemonCreateOpt) error { calls++; return nil }
	w := mustNewHttpWorker(t, mgr)
	var req OSSMountRequest
	require.NoError(t, json.Unmarshal([]byte(`{"operation_id":"invalid","endpoint":"https://objects.example","bucket":"original","object":"root.erofs"}`), &req))
	_, err := w.MountOSS(&req)
	require.Error(t, err)
	require.Zero(t, calls, "invalid operation identity cannot dispatch a mount")
}

func TestMountOperationJournalWriteFailureStopsBeforeDaemonAllocation(t *testing.T) {
	w, _, _ := mountOperationFixture(t)
	mgr := w.mgr.(*mockManager)
	calls := 0
	mgr.createDaemonFunc = func(*distillfs.DaemonCreateOpt) error { calls++; return nil }
	require.NoError(t, w.mountStore.Close())
	_, err := w.MountOSS(&OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "https://objects.example", Bucket: "original", Object: "root.erofs"})
	require.Error(t, err)
	require.Zero(t, calls)
}

func TestMountOperationOCIRequiresOwnershipWithoutLegacyFallback(t *testing.T) {
	w := mustNewHttpWorker(t, newMockManager())
	require.NotPanics(t, func() {
		_, err := w.MountOCI(&OCIMountRequest{OperationID: strings.Repeat("a", 64), ImageURL: "registry.example/original:tag"})
		require.ErrorContains(t, err, "requires physical ownership")
	})
}

func TestMountOperationWrongQueryAndChangedStorageKeyStopBeforeBackend(t *testing.T) {
	w, _, record := mountOperationFixture(t)
	seedMountOperation(t, w, record)
	lookups := 0
	w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	_, err := w.QueryMountOperation(&MountOperationQuery{record.OperationID, strings.Repeat("b", 64)})
	require.Error(t, err)
	_, err = w.QueryMountOperation(&MountOperationQuery{record.OperationID, "invalid"})
	require.Error(t, err)
	otherID := strings.Repeat("e", 64)
	require.NoError(t, w.mountStore.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(mountOperationsBucket)
		return bucket.Put([]byte(otherID), bucket.Get([]byte(record.OperationID)))
	}))
	_, err = w.QueryMountOperation(&MountOperationQuery{otherID, record.RequestFingerprint})
	require.Error(t, err)
	require.Zero(t, lookups)
}
