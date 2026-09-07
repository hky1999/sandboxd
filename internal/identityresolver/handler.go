// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0
package identityresolver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
	"unicode"
	"unicode/utf8"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc"
)

const InstanceLabel = "akernel.scheduler/instance-id"
const RuntimeLabel = "akernel.scheduler/runtime-id"
const GenerationLabel = "akernel.scheduler/resource-generation"
const maxInstanceIDBytes = 256

type Client interface {
	List(context.Context, *runtime.ListSandboxesRequest, ...grpc.CallOption) (*runtime.ListSandboxesResponse, error)
	Stats(context.Context, *runtime.StatsRequest, ...grpc.CallOption) (*runtime.StatsResponse, error)
}
type Identity struct {
	Instance           string `json:"instance"`
	SandboxID          string `json:"sandbox_id"`
	RuntimeID          string `json:"runtime_id"`
	ResourceGeneration string `json:"resource_generation"`
}
type Handler struct {
	client        Client
	authorization string
	slots         chan struct{}
}

func New(client Client, token string) (*Handler, error) {
	if client == nil || len(token) < 32 {
		return nil, fmt.Errorf("resolver requires a client and a token of at least 32 bytes")
	}
	return &Handler{client: client, authorization: "Bearer " + token, slots: make(chan struct{}, 64)}, nil
}

// selector names the sandbox a lookup targets: either its assigned IPv4 or its
// trusted instance label. Exactly one field is set.
type selector struct {
	ip       string
	instance string
}

// parseSelector demands exactly one selector parameter with exactly one
// nonempty value, and rejects unknown parameters so typos cannot silently
// degrade the lookup.
func parseSelector(query url.Values) (selector, string) {
	selectors := 0
	for name, values := range query {
		switch name {
		case "ip", "instance_id":
			selectors++
			if len(values) != 1 {
				return selector{}, "duplicate " + name + " values"
			}
			if values[0] == "" {
				return selector{}, name + " must not be empty"
			}
		default:
			return selector{}, "unknown query parameter " + name
		}
	}
	if selectors != 1 {
		return selector{}, "query must contain exactly one of ip or instance_id"
	}
	if raw := query.Get("instance_id"); raw != "" {
		if len(raw) > maxInstanceIDBytes || !utf8.ValidString(raw) {
			return selector{}, "instance_id must be valid UTF-8 and at most 256 bytes"
		}
		for _, r := range raw {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				return selector{}, "instance_id must not contain whitespace or control characters"
			}
		}
		return selector{instance: raw}, ""
	}
	ip := net.ParseIP(query.Get("ip"))
	if ip == nil || ip.To4() == nil {
		return selector{}, "invalid IPv4 address"
	}
	return selector{ip: ip.String()}, ""
}
func (s selector) matches(status *runtime.SandboxStatus) bool {
	if status == nil || status.State != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		return false
	}
	if s.instance != "" {
		// A RUNNING sandbox can be identified by its trusted label even
		// when no address has been published.
		return status.Labels[InstanceLabel] == s.instance
	}
	return status.Ip == s.ip
}

// selectIncarnation resolves the unique RUNNING match to its complete
// identity, together with the raw bytes of its persisted birth-evidence label
// so /resources can compare that label across both List snapshots. /resolve
// ignores the birth bytes entirely.
func selectIncarnation(list *runtime.ListSandboxesResponse, sel selector) (Identity, string, bool) {
	var identity Identity
	var birth string
	count := 0
	if list == nil {
		return identity, birth, false
	}
	for _, status := range list.Sandboxes {
		if !sel.matches(status) {
			continue
		}
		count++
		identity = Identity{Instance: status.Labels[InstanceLabel], SandboxID: status.ID, RuntimeID: status.Labels[RuntimeLabel], ResourceGeneration: status.Labels[GenerationLabel]}
		birth = status.Labels[birthResourcesLabel]
	}
	return identity, birth, count == 1 && identity.Instance != "" && identity.SandboxID != "" && identity.RuntimeID != "" && identity.ResourceGeneration != ""
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(h.authorization)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.URL.Path != "/resolve" && r.URL.Path != "/resources" {
		http.NotFound(w, r)
		return
	}
	resources := r.URL.Path == "/resources"
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil {
		http.Error(w, "malformed query encoding", 400)
		return
	}
	sel, reason := parseSelector(query)
	if reason != "" {
		http.Error(w, reason, 400)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "resolver busy", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	list, err := h.client.List(ctx, &runtime.ListSandboxesRequest{})
	if err != nil {
		http.Error(w, "sandbox identity unavailable", 503)
		return
	}
	identity, birth, ok := selectIncarnation(list, sel)
	if !ok {
		http.Error(w, "no unique complete running identity", 409)
		return
	}
	// The sample window brackets the physical Stats RPC only: it bounds the
	// live reading's staleness and is unrelated to the birth observation.
	sampleStartedUnixMs := time.Now().UnixMilli()
	stats, err := h.client.Stats(ctx, &runtime.StatsRequest{ID: identity.SandboxID})
	sampleFinishedUnixMs := time.Now().UnixMilli()
	if err != nil || stats == nil || stats.ResourceGeneration != identity.ResourceGeneration {
		http.Error(w, "physical identity changed or unavailable", 503)
		return
	}
	// Recheck lifecycle and selector ownership after physical Stats. This is a
	// fresh observation, not a lease: callers must still fence later actions by
	// generation.
	list, err = h.client.List(ctx, &runtime.ListSandboxesRequest{})
	if err != nil {
		http.Error(w, "sandbox identity unavailable", 503)
		return
	}
	current, currentBirth, ok := selectIncarnation(list, sel)
	if !ok || current != identity {
		http.Error(w, "identity changed during lookup", 409)
		return
	}
	if resources {
		serveResources(w, identity, birth, currentBirth, stats, sampleStartedUnixMs, sampleFinishedUnixMs)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(identity)
}
