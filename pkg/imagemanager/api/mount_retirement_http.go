// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

var _ MountOperationRetirementService = (*HttpWorker)(nil)
var _ MountOperationRetirementService = (*HttpClient)(nil)

func (w *HttpWorker) serveMountOperationRetirement(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer request.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(request.Body, mountRecordLimit+1))
	if err != nil || len(raw) > mountRecordLimit {
		http.Error(writer, "mount retirement exceeds byte limit", http.StatusBadRequest)
		return
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueMountJSONValue(d, 0); err != nil {
		http.Error(writer, "ambiguous mount retirement", http.StatusBadRequest)
		return
	}
	if _, err := d.Token(); err != io.EOF {
		http.Error(writer, "trailing mount retirement", http.StatusBadRequest)
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 4 {
		http.Error(writer, "invalid mount retirement fields", http.StatusBadRequest)
		return
	}
	if err := exactMountJSONFields(fields, "operation_id", "request_fingerprint", "kind", "image_url"); err != nil {
		http.Error(writer, "invalid mount retirement fields", http.StatusBadRequest)
		return
	}
	var req MountOperationRetirement
	if err := json.Unmarshal(raw, &req); err != nil || validateMountRetirement(&req) != nil {
		http.Error(writer, "invalid mount retirement", http.StatusBadRequest)
		return
	}
	result, err := w.RetireMountOperation(&req)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusConflict)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(result)
}

func (c *HttpClient) RetireMountOperation(req *MountOperationRetirement) (*MountOperationResult, error) {
	if err := validateMountRetirement(req); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.clt.Post("http://unix/mount_operation_retire", "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("mount operation retirement failed: %w", err)
	}
	result, err := readMountOperationReply(resp, &MountOperationQuery{OperationID: req.OperationID, RequestFingerprint: req.RequestFingerprint})
	if err != nil {
		return nil, err
	}
	if result.Kind != req.Kind {
		return nil, fmt.Errorf("mount operation retirement reply kind changed")
	}
	return result, nil
}
