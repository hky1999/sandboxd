// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/protobuf/proto"
)

// These digests detect damaged or accidentally changed daemon-owned records.
// They are not signatures, immutable OCI identities, or mount retirement proof.
func fsSourceFingerprint(id string, state sandboxFSState) (string, error) {
	// Optional empty source lists have one representation across clone/reopen.
	if len(state.S3) == 0 {
		state.S3 = nil
	}
	if len(state.OCI) == 0 {
		state.OCI = nil
	}
	encoded, err := json.Marshal(struct {
		Domain     string
		SandboxID  string
		Generation string
		Rootfs     []byte
		S3         []*runtime.S3Config
		OCI        []string
	}{"akernel-filesystem-source-v3", id, state.Generation, state.Rootfs, state.S3, state.OCI})
	if err != nil {
		return "", fmt.Errorf("encode filesystem source fingerprint")
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func fsJournalIntegrity(j storedSandboxFSStates) (string, error) {
	j.IntegritySHA256 = ""
	encoded, err := json.Marshal(j)
	if err != nil {
		return "", fmt.Errorf("encode filesystem journal integrity")
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func validateFSSources(s sandboxFSState) error {
	var root runtime.RootfsConfig
	if err := proto.Unmarshal(s.Rootfs, &root); err != nil || len(root.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("invalid filesystem root source")
	}
	switch source := root.Source.(type) {
	case *runtime.RootfsConfig_Path:
		if root.Type != runtime.RootfsSrcType_LOCAL || strings.TrimSpace(source.Path) == "" {
			return fmt.Errorf("invalid local filesystem source")
		}
	case *runtime.RootfsConfig_ImageUrl:
		if root.Type != runtime.RootfsSrcType_IMAGE || strings.TrimSpace(source.ImageUrl) == "" {
			return fmt.Errorf("invalid image filesystem source")
		}
	case *runtime.RootfsConfig_S3Config:
		if root.Type != runtime.RootfsSrcType_S3 || !validFSS3Source(source.S3Config) {
			return fmt.Errorf("invalid S3 filesystem source")
		}
	default:
		return fmt.Errorf("missing filesystem root source")
	}
	for _, source := range s.S3 {
		if !validFSS3Source(source) {
			return fmt.Errorf("invalid S3 filesystem mount source")
		}
	}
	for _, source := range s.OCI {
		if strings.TrimSpace(source) == "" {
			return fmt.Errorf("invalid OCI filesystem mount source")
		}
	}
	return nil
}

func validFSS3Source(s *runtime.S3Config) bool {
	return s != nil && len(s.ProtoReflect().GetUnknown()) == 0 && strings.TrimSpace(s.Endpoint) != "" && strings.TrimSpace(s.Bucket) != "" && strings.TrimSpace(s.Object) != ""
}

func validateFSJournal(j storedSandboxFSStates) error {
	if j.SchemaVersion != fsJournalSchema {
		return fmt.Errorf("unsupported filesystem ownership schema")
	}
	if j.Items == nil || len(j.Items)+len(j.Completed) > fsJournalLimit {
		return fmt.Errorf("invalid filesystem ownership inventory")
	}
	for id, state := range j.Items {
		if id == "" || strings.ContainsRune(id, 0) || strings.ContainsRune(state.Generation, 0) {
			return fmt.Errorf("invalid filesystem owner identity")
		}
		if err := validateFSSources(state); err != nil {
			return err
		}
		fingerprint, err := fsSourceFingerprint(id, state)
		if err != nil {
			return err
		}
		if state.SourceFingerprint != fingerprint {
			return fmt.Errorf("filesystem original source fingerprint changed")
		}
		if len(state.S3) != len(state.S3Phases) || len(state.OCI) != len(state.OCIPhases) {
			return fmt.Errorf("incomplete filesystem ownership stages")
		}
		if err := validateFSMountBindings(state); err != nil {
			return err
		}
		phases := append([]fsLeasePhase{state.RootfsPhase}, state.S3Phases...)
		phases = append(phases, state.OCIPhases...)
		for _, phase := range phases {
			switch phase {
			case fsReserved, fsAcquiring, fsAcquired, fsReleasePending, fsReleased:
			default:
				return fmt.Errorf("invalid filesystem ownership stage")
			}
		}
	}
	for key, r := range j.Completed {
		fingerprint, err := hex.DecodeString(r.SourceFingerprint)
		if err != nil || len(fingerprint) != sha256.Size || r.SandboxID == "" || strings.ContainsRune(r.SandboxID, 0) || strings.ContainsRune(r.Generation, 0) || key != fsCompletionKey(r.SandboxID, r.Generation) {
			return fmt.Errorf("invalid filesystem completion")
		}
		if active, exists := j.Items[r.SandboxID]; exists && active.Generation == r.Generation {
			return fmt.Errorf("filesystem generation is both active and completed")
		}
	}
	return nil
}

func validateFSMountBindings(s sandboxFSState) error {
	if len(s.S3) != len(s.S3MountGenerations) || len(s.OCI) != len(s.OCIMountGenerations) {
		return fmt.Errorf("incomplete original filesystem mount bindings")
	}
	var root runtime.RootfsConfig
	if err := proto.Unmarshal(s.Rootfs, &root); err != nil {
		return err
	}
	validate := func(g string, phase fsLeasePhase, remote bool) error {
		if g != "" && (!remote || !validFSPhysicalGeneration(g) || phase == fsReserved) {
			return fmt.Errorf("invalid original filesystem mount generation")
		}
		if s.Generation != "" && remote && (phase == fsAcquired || phase == fsReleasePending) && g == "" {
			return fmt.Errorf("original filesystem mount generation is missing")
		}
		return nil
	}
	if err := validate(s.RootfsMountGeneration, s.RootfsPhase, root.Type != runtime.RootfsSrcType_LOCAL); err != nil {
		return err
	}
	for i, g := range s.S3MountGenerations {
		if err := validate(g, s.S3Phases[i], true); err != nil {
			return err
		}
	}
	for i, g := range s.OCIMountGenerations {
		if err := validate(g, s.OCIPhases[i], true); err != nil {
			return err
		}
	}
	return nil
}

func validateFSRecoveryBindings(s sandboxFSState) error {
	if err := validateFSMountBindings(s); err != nil {
		return err
	}
	if s.Generation == "" {
		return nil
	}
	var root runtime.RootfsConfig
	if err := proto.Unmarshal(s.Rootfs, &root); err != nil {
		return err
	}
	unknown := func(g string, phase fsLeasePhase) bool { return needsFSReference(phase) && g == "" }
	if root.Type != runtime.RootfsSrcType_LOCAL && unknown(s.RootfsMountGeneration, s.RootfsPhase) {
		return fmt.Errorf("original rootfs acquisition is unresolved")
	}
	for i, g := range s.S3MountGenerations {
		if unknown(g, s.S3Phases[i]) {
			return fmt.Errorf("original S3 acquisition is unresolved")
		}
	}
	for i, g := range s.OCIMountGenerations {
		if unknown(g, s.OCIPhases[i]) {
			return fmt.Errorf("original image acquisition is unresolved")
		}
	}
	return nil
}

func decodeFSJournal(data []byte) (storedSandboxFSStates, error) {
	var j storedSandboxFSStates
	// Check duplicates before encoding/json can silently pick the last value.
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueFSJSONValue(decoder, 0); err != nil {
		return j, fmt.Errorf("invalid or ambiguous filesystem journal JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return j, fmt.Errorf("trailing filesystem journal data")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(data, &header); err != nil || header == nil {
		return j, fmt.Errorf("invalid filesystem journal envelope")
	}
	version := 0
	if raw, exists := header["schema_version"]; exists {
		if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &version) != nil {
			return j, fmt.Errorf("invalid filesystem journal schema")
		}
	}
	switch version {
	case 0:
		if err := exactFSJSONFields(header, "schema_version", "items"); err != nil {
			return j, err
		}
		// A legacy owner had ONLY these source fields. New ownership fields,
		// even empty ones, must never be downgraded to an acquired old owner.
		var old struct {
			SchemaVersion int `json:"schema_version,omitempty"`
			Items         map[string]struct {
				Rootfs []byte              `json:"rootfs,omitempty"`
				S3     []*runtime.S3Config `json:"s3,omitempty"`
				OCI    []string            `json:"oci,omitempty"`
			} `json:"items"`
		}
		if err := decodeStrictFSJSON(data, &old); err != nil {
			return j, err
		}
		var rawItems map[string]json.RawMessage
		if json.Unmarshal(header["items"], &rawItems) != nil || rawItems == nil {
			return j, fmt.Errorf("missing legacy filesystem inventory")
		}
		j = storedSandboxFSStates{SchemaVersion: fsJournalSchema, Items: make(map[string]sandboxFSState), Completed: make(map[string]fsCompletion)}
		for id, item := range old.Items {
			var fields map[string]json.RawMessage
			if json.Unmarshal(rawItems[id], &fields) != nil || fields == nil {
				return j, fmt.Errorf("invalid legacy filesystem owner")
			}
			if err := exactFSJSONFields(fields, "rootfs", "s3", "oci"); err != nil {
				return j, err
			}
			if err := validateFSS3JSONFields(fields); err != nil {
				return j, err
			}
			state := sandboxFSState{Rootfs: item.Rootfs, S3: item.S3, OCI: item.OCI, RootfsPhase: fsAcquired, S3Phases: make([]fsLeasePhase, len(item.S3)), OCIPhases: make([]fsLeasePhase, len(item.OCI)), S3MountGenerations: make([]string, len(item.S3)), OCIMountGenerations: make([]string, len(item.OCI))}
			for i := range state.S3Phases {
				state.S3Phases[i] = fsAcquired
			}
			for i := range state.OCIPhases {
				state.OCIPhases[i] = fsAcquired
			}
			fingerprint, err := fsSourceFingerprint(id, state)
			if err != nil {
				return j, err
			}
			state.SourceFingerprint = fingerprint
			j.Items[id] = state
		}
	case 2:
		if err := exactFSJSONFields(header, "schema_version", "items", "completed"); err != nil {
			return j, err
		}
		if err := decodeStrictFSJSON(data, &j); err != nil {
			return j, err
		}
		if j.Items == nil || len(j.Items)+len(j.Completed) != 0 {
			return j, fmt.Errorf("nonempty schema 2 requires independent ownership migration")
		}
		j.SchemaVersion = fsJournalSchema
	case 3:
		if err := exactFSJSONFields(header, "schema_version", "items", "completed", "integrity_sha256"); err != nil {
			return j, err
		}
		if err := decodeStrictFSJSON(data, &j); err != nil {
			return j, err
		}
		if j.Items == nil || len(j.Items)+len(j.Completed) != 0 {
			return j, fmt.Errorf("nonempty schema 3 requires independent physical ownership migration")
		}
		integrity, err := fsJournalIntegrity(j)
		if err != nil || j.IntegritySHA256 != integrity {
			return j, fmt.Errorf("filesystem journal integrity changed")
		}
		j.SchemaVersion = fsJournalSchema
	case fsJournalSchema:
		if err := exactFSJSONFields(header, "schema_version", "items", "completed", "integrity_sha256"); err != nil {
			return j, err
		}
		if err := decodeStrictFSJSON(data, &j); err != nil {
			return j, err
		}
		if err := validateFSJSONOwnerFields(header); err != nil {
			return j, err
		}
		integrity, err := fsJournalIntegrity(j)
		if err != nil {
			return j, err
		}
		if j.IntegritySHA256 != integrity {
			return j, fmt.Errorf("filesystem journal integrity changed")
		}
	default:
		return j, fmt.Errorf("unsupported filesystem ownership schema")
	}
	if err := validateFSJournal(j); err != nil {
		return j, err
	}
	return j, nil
}

func decodeStrictFSJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid filesystem journal fields")
	}
	return nil
}

func exactFSJSONFields(fields map[string]json.RawMessage, allowed ...string) error {
	known := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		known[key] = true
	}
	for key := range fields {
		if !known[key] {
			return fmt.Errorf("unknown filesystem journal field")
		}
	}
	return nil
}

func validateFSJSONOwnerFields(header map[string]json.RawMessage) error {
	for _, section := range []string{"items", "completed"} {
		raw, exists := header[section]
		if !exists {
			continue
		}
		var items map[string]json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return fmt.Errorf("invalid filesystem journal section")
		}
		for _, rawItem := range items {
			var fields map[string]json.RawMessage
			if json.Unmarshal(rawItem, &fields) != nil || fields == nil {
				return fmt.Errorf("invalid filesystem journal entry")
			}
			allowed := []string{"sandbox_id", "generation", "source_fingerprint"}
			if section == "items" {
				allowed = []string{"generation", "source_fingerprint", "rootfs", "s3", "oci", "rootfs_phase", "s3_phases", "oci_phases", "rootfs_mount_generation", "s3_mount_generations", "oci_mount_generations"}
			}
			if err := exactFSJSONFields(fields, allowed...); err != nil {
				return err
			}
			if section == "items" {
				if err := validateFSS3JSONFields(fields); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateFSS3JSONFields(fields map[string]json.RawMessage) error {
	raw, exists := fields["s3"]
	if !exists {
		return nil
	}
	var sources []map[string]json.RawMessage
	if json.Unmarshal(raw, &sources) != nil {
		return fmt.Errorf("invalid filesystem S3 source list")
	}
	for _, source := range sources {
		if source == nil {
			return fmt.Errorf("missing filesystem S3 source")
		}
		if err := exactFSJSONFields(source, "endpoint", "bucket", "object", "access_key_id", "access_key_secret"); err != nil {
			return err
		}
	}
	return nil
}

func uniqueFSJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("filesystem JSON depth exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate filesystem JSON key")
			}
			seen[key] = true
			if err := uniqueFSJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueFSJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid filesystem JSON container")
	}
	_, err = decoder.Token()
	return err
}
