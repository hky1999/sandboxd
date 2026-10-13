// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
)

// Kept separate from legacy Service: managed callers must require this
// capability, rather than silently using a service without durable queries.
type MountOperationService interface {
	QueryMountOperation(*MountOperationQuery) (*MountOperationResult, error)
}

var _ MountOperationService = (*HttpWorker)(nil)
var _ MountOperationService = (*HttpClient)(nil)

type mountOperationBinding struct {
	owner   distillfs.PreparationOwner
	publish func(daemonID, nydusURL, generation, target string) error
}

type mountBinding = *mountOperationBinding

func (b *mountOperationBinding) Bind(daemonID, nydusURL, generation, target string) error {
	return b.publish(daemonID, nydusURL, generation, target)
}

func decodeMountDispatch(body io.Reader, request any) error {
	raw, err := io.ReadAll(io.LimitReader(body, mountRecordLimit+1))
	if err != nil || len(raw) > mountRecordLimit {
		return fmt.Errorf("mount request exceeds byte limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueMountJSONValue(d, 0); err != nil {
		return fmt.Errorf("mount request is ambiguous")
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("mount request contains trailing data")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return fmt.Errorf("mount request is invalid")
	}
	var allowed []string
	switch request.(type) {
	case *OSSMountRequest:
		allowed = []string{"operation_id", "physical_generation", "mount_point", "endpoint", "bucket", "object", "access_key_id", "access_key_secret"}
	case *NydusMountRequest:
		allowed = []string{"operation_id", "physical_generation", "image_url", "mount_point"}
	case *OCIMountRequest:
		allowed = []string{"operation_id", "physical_generation", "require_physical_generation", "image_url"}
	default:
		return fmt.Errorf("unsupported mount request")
	}
	if err := exactMountJSONFields(fields, allowed...); err != nil {
		return err
	}
	if rawID, exists := fields["operation_id"]; exists {
		var id string
		if err := json.Unmarshal(rawID, &id); err != nil || !validMountGeneration(id) {
			return fmt.Errorf("mount operation identity is invalid")
		}
	}
	return json.Unmarshal(raw, request)
}

func nativeMountBinding(bind mountBinding, daemonID, nydusURL string) func(string, string) error {
	if bind == nil {
		return nil
	}
	return func(generation, target string) error { return bind.Bind(daemonID, nydusURL, generation, target) }
}

func (w *HttpWorker) prepareDaemonForMount(opts *distillfs.DaemonCreateOpt, bind mountBinding) error {
	if bind == nil {
		return w.mgr.CreateDaemon(opts)
	}
	manager, ok := w.mgr.(distillfs.PreparationManager)
	if !ok {
		return fmt.Errorf("managed mount requires durable pre-allocation ownership")
	}
	nydusURL := ""
	if opts.SourceType == "nydus" {
		nydusURL = opts.ImageURL
	}
	return manager.PrepareDaemon(opts, bind.owner, nativeMountBinding(bind, opts.ID, nydusURL))
}

// An independent lookup only reads the original preparation. It never aborts
// an active producer, allocates directories, or adopts the source's current
// generation. Absence still means unknown, including for legacy producers.
func (w *HttpWorker) findOriginalPreparation(r *mountOperationRecord) (*mountOperationRecord, error) {
	manager, ok := w.mgr.(distillfs.PreparationManager)
	if !ok {
		return nil, nil
	}
	p, err := manager.FindPreparation(distillfs.PreparationOwner{OperationID: r.OperationID, RequestFingerprint: r.RequestFingerprint})
	if err != nil || p == nil {
		return nil, err
	}
	bound := *r
	bound.Phase, bound.DaemonID = "bound", p.DaemonID
	bound.PhysicalGeneration, bound.MountPoint = p.Generation, p.Target
	if p.SourceType == "nydus" {
		bound.NydusImageURL = p.ImageURL
	}
	if err := validateMountOperation(&bound); err != nil {
		return nil, err
	}
	return &bound, nil
}

func (w *HttpWorker) acquireMountOperationLock(id string) func() {
	w.operationLocksMu.Lock()
	if w.operationLocks == nil {
		w.operationLocks = make(map[string]*mountRouteLock)
	}
	entry := w.operationLocks[id]
	if entry == nil {
		entry = &mountRouteLock{}
		w.operationLocks[id] = entry
	}
	entry.refs++
	w.operationLocksMu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		w.operationLocksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(w.operationLocks, id)
		}
		w.operationLocksMu.Unlock()
	}
}

func (w *HttpWorker) executeMountOperation(id, kind, imageURL, expected string, request any, mount func(mountBinding) (*MountInfo, error)) (*MountInfo, error) {
	if !validMountGeneration(id) {
		return nil, fmt.Errorf("mount operation identity is invalid")
	}
	if w.mountStore == nil {
		return nil, fmt.Errorf("mount operation requires its persistent journal")
	}
	if expected != "" && !validMountGeneration(expected) {
		return nil, fmt.Errorf("original mount selector is invalid")
	}
	fingerprint, err := MountRequestFingerprint(request)
	if err != nil {
		return nil, err
	}
	unlock := w.acquireMountOperationLock(id)
	defer unlock()
	intent := &mountOperationRecord{OperationID: id, RequestFingerprint: fingerprint, Kind: kind, Phase: "intent", ImageURL: imageURL}
	if _, ok := w.mgr.(distillfs.PreparationRetirementManager); ok {
		intent.PreparationProtocol = 1
	}
	r, fresh, err := w.mountStore.beginMountOperation(intent)
	if err != nil {
		return nil, err
	}
	if !fresh {
		if expected != "" && r.PhysicalGeneration != expected {
			return nil, fmt.Errorf("original mount selector changed")
		}
		return w.recoverBoundMountOperation(r)
	}
	bind := func(daemonID, nydusURL, generation, target string) error {
		if expected != "" && expected != generation {
			return fmt.Errorf("original mount selector changed")
		}
		binding := *intent
		binding.Phase, binding.DaemonID, binding.NydusImageURL = "bound", daemonID, nydusURL
		binding.PhysicalGeneration, binding.MountPoint = generation, target
		return w.mountStore.publishMountBinding(&binding)
	}
	info, err := mount(&mountOperationBinding{owner: distillfs.PreparationOwner{OperationID: id, RequestFingerprint: fingerprint}, publish: bind})
	if err != nil {
		return nil, err
	} // Preserve intent/binding; no blind retry.
	if info == nil {
		return nil, fmt.Errorf("original mount reply is missing")
	}
	query := &MountOperationQuery{id, fingerprint}
	if !info.Released && !info.ReleasePending {
		if err := w.mountStore.confirmMountOperation(query, info.PhysicalGeneration, info.MountPoint); err != nil {
			return nil, err
		}
	}
	return info, nil
}

// This query never dispatches, reconstructs a route, or changes references. A
// bound result can be inspected even if the success confirmation was not saved.
func (w *HttpWorker) QueryMountOperation(query *MountOperationQuery) (*MountOperationResult, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if w.mountStore == nil {
		return nil, fmt.Errorf("mount operation requires its persistent journal")
	}
	r, err := w.mountStore.getMountOperation(query)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return &MountOperationResult{OperationID: query.OperationID, RequestFingerprint: query.RequestFingerprint, State: "absent"}, nil
	}
	return w.inspectMountOperation(r)
}

func (w *HttpWorker) inspectMountOperation(r *mountOperationRecord) (*MountOperationResult, error) {
	result := &MountOperationResult{OperationID: r.OperationID, RequestFingerprint: r.RequestFingerprint, Kind: r.Kind, State: "unresolved", PhysicalGeneration: r.PhysicalGeneration, MountPoint: r.MountPoint}
	if r.Phase == "not_allocated" {
		result.State = "not_allocated"
		return result, nil
	}
	if r.Phase == "intent" {
		bound, err := w.findOriginalPreparation(r)
		if err != nil {
			return nil, err
		}
		if bound == nil {
			result.State = "intent"
			return result, nil
		}
		return w.inspectMountOperation(bound)
	}
	if r.Kind == "oci" {
		completed, err := w.mountStore.Completed(r.ImageURL, r.PhysicalGeneration)
		if err != nil {
			return nil, err
		}
		if completed != nil {
			if completed.MountPoint != r.MountPoint || completed.NydusImageURL != r.NydusImageURL {
				return nil, fmt.Errorf("original mount completion binding changed")
			}
			result.State = "released"
			return result, nil
		}
	}
	if w.mgr == nil {
		return result, nil
	}
	d := w.mgr.GetDaemon(r.DaemonID)
	if d == nil {
		return result, nil
	}
	var phase string
	var err error
	if r.RetirementRequested {
		phase, err = d.InspectPhysicalGenerationForRetirement(r.PhysicalGeneration)
	} else {
		phase, err = d.InspectPhysicalGeneration(r.PhysicalGeneration)
	}
	if err != nil {
		return result, nil
	}
	if d.MountPoint() != r.MountPoint {
		return nil, fmt.Errorf("original mount target changed")
	}
	switch phase {
	case "running":
		result.State = "ready"
	case "releasing", "not_started":
		result.State = "release_pending"
	case "released":
		result.State = "released"
	}
	return result, nil
}

// Replays bind to the journal's original backend even if a tag now resolves
// elsewhere. Only Mount, not the independent query, may rebuild a missing route.
func (w *HttpWorker) recoverBoundMountOperation(r *mountOperationRecord) (*MountInfo, error) {
	if r.Phase == "not_allocated" {
		return nil, fmt.Errorf("original mount operation is durably closed without allocation")
	}
	if r.Phase == "intent" {
		bound, err := w.findOriginalPreparation(r)
		if err != nil {
			return nil, err
		}
		if bound == nil {
			return nil, fmt.Errorf("original mount dispatch is unresolved")
		}
		// Only the explicit retry publishes the recovered original binding;
		// the independent query remains read-only.
		if err := w.mountStore.publishMountBinding(bound); err != nil {
			return nil, err
		}
		r = bound
	}
	if r.Kind == "oci" {
		unlock := w.acquireMountRouteLock(r.ImageURL)
		defer unlock()
		result, err := w.inspectMountOperation(r)
		if err != nil {
			return nil, err
		}
		if result.State == "released" {
			return &MountInfo{MountPoint: r.MountPoint, PhysicalGeneration: r.PhysicalGeneration, Released: true}, nil
		}
		if result.State != "ready" && result.State != "release_pending" {
			return nil, fmt.Errorf("original mount result is unresolved")
		}
		if !r.RetirementRequested {
			if err := w.recordMountGeneration(r.ImageURL, "nydus", r.NydusImageURL, r.MountPoint, r.PhysicalGeneration); err != nil {
				return nil, err
			}
		}
	}
	info, err := w.recoverDaemonMountForRetirement(r.DaemonID, r.PhysicalGeneration, r.Kind == "oss", r.RetirementRequested)
	if err != nil {
		return nil, err
	}
	if info.MountPoint != r.MountPoint {
		return nil, fmt.Errorf("original mount target changed")
	}
	if !info.Released && !info.ReleasePending {
		if err := w.mountStore.confirmMountOperation(&MountOperationQuery{r.OperationID, r.RequestFingerprint}, info.PhysicalGeneration, info.MountPoint); err != nil {
			return nil, err
		}
	}
	return info, nil
}

func (w *HttpWorker) serveMountOperationQuery(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer request.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(request.Body, 1025))
	if err != nil || len(raw) > 1024 {
		http.Error(writer, "mount operation query exceeds byte limit", http.StatusBadRequest)
		return
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueMountJSONValue(d, 0); err != nil {
		http.Error(writer, "ambiguous mount operation query", http.StatusBadRequest)
		return
	}
	if _, err := d.Token(); err != io.EOF {
		http.Error(writer, "trailing mount operation query", http.StatusBadRequest)
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 2 {
		http.Error(writer, "invalid mount operation query", http.StatusBadRequest)
		return
	}
	if err := exactMountJSONFields(fields, "operation_id", "request_fingerprint"); err != nil {
		http.Error(writer, "invalid mount operation query", http.StatusBadRequest)
		return
	}
	var query MountOperationQuery
	if err := json.Unmarshal(raw, &query); err != nil {
		http.Error(writer, "invalid mount operation query", http.StatusBadRequest)
		return
	}
	result, err := w.QueryMountOperation(&query)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusConflict)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(result)
}

func (c *HttpClient) QueryMountOperation(query *MountOperationQuery) (*MountOperationResult, error) {
	if query == nil || !validMountGeneration(query.OperationID) || !validMountGeneration(query.RequestFingerprint) {
		return nil, fmt.Errorf("original mount query identity is required")
	}
	raw, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	resp, err := c.clt.Post("http://unix/mount_operation_query", "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("mount operation query failed: %w", err)
	}
	return readMountOperationReply(resp, query)
}

func readMountOperationReply(resp *http.Response, query *MountOperationQuery) (*MountOperationResult, error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mount operation query failed with status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, mountRecordLimit+1))
	if err != nil || len(data) > mountRecordLimit {
		return nil, fmt.Errorf("mount operation query reply exceeds byte limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueMountJSONValue(d, 0); err != nil {
		return nil, fmt.Errorf("mount operation query reply is ambiguous")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("mount operation query reply contains trailing data")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 6 {
		return nil, fmt.Errorf("mount operation query reply fields are incomplete")
	}
	if err := exactMountJSONFields(fields, "operation_id", "request_fingerprint", "kind", "state", "physical_generation", "mount_point"); err != nil {
		return nil, err
	}
	var result MountOperationResult
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&result); err != nil {
		return nil, fmt.Errorf("mount operation query reply is invalid")
	}
	if result.OperationID != query.OperationID || result.RequestFingerprint != query.RequestFingerprint {
		return nil, fmt.Errorf("mount operation query reply identity changed")
	}
	if result.State != "absent" && result.State != "intent" && result.State != "unresolved" && result.State != "ready" && result.State != "release_pending" && result.State != "released" && result.State != "not_allocated" {
		return nil, fmt.Errorf("mount operation query reply state is invalid")
	}
	if result.State == "ready" || result.State == "release_pending" || result.State == "released" || result.State == "unresolved" {
		if !validMountGeneration(result.PhysicalGeneration) || !filepath.IsAbs(result.MountPoint) || filepath.Clean(result.MountPoint) != result.MountPoint {
			return nil, fmt.Errorf("mount operation query reply binding is missing")
		}
	}
	if result.State == "absent" {
		if result.Kind != "" || result.PhysicalGeneration != "" || result.MountPoint != "" {
			return nil, fmt.Errorf("absent mount operation reply contains physical claims")
		}
	} else {
		if result.Kind != "oss" && result.Kind != "nydus" && result.Kind != "oci" {
			return nil, fmt.Errorf("mount operation query reply kind is invalid")
		}
		if (result.State == "intent" || result.State == "not_allocated") && (result.PhysicalGeneration != "" || result.MountPoint != "") {
			return nil, fmt.Errorf("unbound mount operation reply contains physical claims")
		}
	}
	return &result, nil
}
