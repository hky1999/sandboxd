// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
)

// TestListenMetricsBindConflictFailsSynchronously: an occupied port must
// surface its bind error from listenMetrics itself — before any scanning
// starts — with no reliance on a background goroutine racing os.Exit.
func TestListenMetricsBindConflictFailsSynchronously(t *testing.T) {
	occ, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occ.Close()
	ln, err := listenMetrics(occ.Addr().String())
	if err == nil {
		ln.Close()
		t.Fatal("bind conflict must fail synchronously")
	}
}

// TestListenMetricsServesMetrics: a successful bind actually serves the
// Prometheus endpoint.
func TestListenMetricsServesMetrics(t *testing.T) {
	ln, err := listenMetrics("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
}

// TestMetricsHandlerPurePrometheus: /metrics must serve ONLY Prometheus
// text format under the registered content type — no JSON tail appended
// after the samples (the old expvar-style appendix), no per-artifact
// label cardinality.
func TestMetricsHandlerPurePrometheus(t *testing.T) {
	t.Cleanup(func() { roundGauges.Store(nil) })
	res := checkpointpublish.RoundResult{
		Pending: 2, UnpublishedBytes: 4096, OldestPendingAge: time.Minute,
		Published: []string{"a"},
		Phases: []checkpointpublish.ArtifactPhases{{
			ID: "m", QueueWait: 5 * time.Second, SealToReady: 9 * time.Second,
		}},
	}
	roundGauges.Store(&res)
	rec := httptest.NewRecorder()
	metricsHandler(rec, httptest.NewRequest("GET", "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("content-type = %q, want the Prometheus text registration", ct)
	}
	body := rec.Body.String()
	samples := 0
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A JSON fragment (object opening or "key": value) is residue from
		// the removed expvar appendix and must never appear.
		if strings.HasPrefix(line, "{") || strings.Contains(line, "\":") {
			t.Fatalf("non-Prometheus line (JSON residue): %q", line)
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed sample line (want name[labels] value): %q", line)
		}
		if !strings.HasPrefix(fields[0], "publishd_") {
			t.Fatalf("unexpected metric name in %q", line)
		}
		samples++
	}
	if samples < 9 {
		t.Fatalf("only %d samples, want all 9 series", samples)
	}
	if !strings.Contains(body, "publishd_publish_wall_seconds") {
		t.Fatal("publish-wall exemplar series missing")
	}
	if strings.Contains(body, `id="`) {
		t.Fatal("per-artifact labels leaked into /metrics")
	}
	// Before the first round the handler still answers with the correct
	// content type and an empty (not JSON) body.
	roundGauges.Store(nil)
	rec2 := httptest.NewRecorder()
	metricsHandler(rec2, httptest.NewRequest("GET", "/metrics", nil))
	if ct := rec2.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("pre-round content-type = %q", ct)
	}
	if strings.TrimSpace(rec2.Body.String()) != "" {
		t.Fatalf("pre-round body not empty: %q", rec2.Body.String())
	}
}

func TestParseBytes(t *testing.T) {
	good := map[string]int64{
		"1": 1, "512": 512, "1K": 1 << 10, "512m": 512 << 20,
		"20G": 20 << 30, "1T": 1 << 40, "+8G": 8 << 30, "1024K": 1 << 20,
	}
	for in, want := range good {
		got, err := parseBytes(in)
		if err != nil || got != want {
			t.Fatalf("parseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	bad := []string{"", " ", "K", "G", "-1", "-1G", "1x", "1G ", " 1G", "1.5G", "abc", "99999999999999999999999", "1e9", "0x10", "1KB", "--", "+", "-", "1T1"}
	for _, in := range bad {
		if got, err := parseBytes(in); err == nil {
			t.Fatalf("parseBytes(%q) = %d; want error", in, got)
		}
	}
}
