package identityresolver

import (
	"encoding/json"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/protobuf/proto"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// birthLabel renders a schema-1 birth evidence label for the fixture identity,
// with an optional mutation for negative cases.
func birthLabel(mutate func(map[string]any)) string {
	evidence := map[string]any{
		"schema_version":      1,
		"sandbox_id":          "sandbox",
		"resource_generation": "generation",
		"phase":               "start",
		"observed_at_unix_ms": time.Now().Add(-time.Minute).UnixMilli(),
		"cpu_quota_usec":      100000,
		"cpu_period_usec":     100000,
		"memory_limit_bytes":  2147483648,
	}
	if mutate != nil {
		mutate(evidence)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func birthStatus() *runtime.SandboxStatus {
	status := runningStatus()
	status.Labels[birthResourcesLabel] = birthLabel(nil)
	// None of the fields below may ever reach a /resources or /resolve body.
	status.Command = []string{"secret-command", "--secret-argument"}
	status.Envs = []*runtime.KeyValue{{Key: "SECRET_ENV", Value: "secret-value"}}
	status.Message = "secret-state-message"
	status.Stdout = "/secret/stdout-path"
	status.MetricLabels = map[string]string{"secret-metric": "secret-dimension"}
	return status
}

// grownStats carries live limits that grew past the birth evidence: 4GiB and
// 200ms quota against the 2GiB and 100ms prepared at birth.
func grownStats() *runtime.StatsResponse {
	return &runtime.StatsResponse{
		ResourceGeneration:  "generation",
		CpuUsageNs:          123456789,
		MemoryUsageBytes:    1073741824,
		MemoryLimitBytes:    4294967296,
		MemoryMaxUsageBytes: 3221225472,
		CpuQuotaUsec:        200000,
		CpuPeriodUsec:       100000,
		CpuLimitsKnown:      true,
		CpuPressureKnown:    true,
		CpuPeriods:          555,
		CpuThrottledPeriods: 6,
		CpuThrottledNs:      987654321,
		MemoryPressureKnown: true,
		MemoryHighEvents:    7,
		MemoryOomEvents:     8,
		MemoryOomKillEvents: 9,
		ElasticPolicy:       "SECRET-elastic-policy",
	}
}

func TestResourcesReturnsValidatedBirthAndLiveSample(t *testing.T) {
	for _, lookup := range []string{"ip", "instance"} {
		t.Run(lookup, func(t *testing.T) {
			status := birthStatus()
			if lookup == "instance" {
				status.Ip = ""
			}
			first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{status}}
			second := proto.Clone(first).(*runtime.ListSandboxesResponse)
			client := &fakeClient{first: first, second: second, stats: grownStats()}
			token := strings.Repeat("x", 32)
			handler, err := New(client, token)
			if err != nil {
				t.Fatal(err)
			}
			query := "/resources?ip=10.88.0.1"
			if lookup == "instance" {
				query = "/resources?instance_id=instance"
			}
			req := httptest.NewRequest("GET", query, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			beforeUnixMs := time.Now().UnixMilli()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			afterUnixMs := time.Now().UnixMilli()
			if response.Code != 200 {
				t.Fatalf("invalid response %d %s", response.Code, response.Body.String())
			}
			var report resourceReport
			if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.SchemaVersion != 1 || report.Identity != (Identity{Instance: "instance", SandboxID: "sandbox", RuntimeID: "runtime", ResourceGeneration: "generation"}) {
				t.Fatalf("invalid report header %+v", report)
			}
			// The birth block keeps the original prepared limits even though
			// the live sample has since grown past them.
			if report.Birth.SchemaVersion != 1 || report.Birth.SandboxID != "sandbox" || report.Birth.ResourceGeneration != "generation" || report.Birth.Phase != "start" || report.Birth.ObservedAtUnixMs <= 0 || report.Birth.CpuQuotaUsec != 100000 || report.Birth.CpuPeriodUsec != 100000 || report.Birth.MemoryLimitBytes != 2147483648 {
				t.Fatalf("invalid birth evidence %+v", report.Birth)
			}
			if report.Current.MemoryPeakKnown {
				t.Fatal("unproven kernel memory peak reported known")
			}
			if report.Current.MemoryLimitBytes != 4294967296 || report.Current.MemoryLimitBytes == report.Birth.MemoryLimitBytes || report.Current.CpuQuotaUsec != 200000 || report.Current.CpuQuotaUsec == report.Birth.CpuQuotaUsec {
				t.Fatalf("grown live sample not reported: %+v", report)
			}
			if report.SampleStartedUnixMs < beforeUnixMs || report.SampleFinishedUnixMs > afterUnixMs || report.SampleStartedUnixMs > report.SampleFinishedUnixMs || report.SampleStartedUnixMs <= report.Birth.ObservedAtUnixMs {
				t.Fatalf("sample window does not bracket the stats call: %d %d", report.SampleStartedUnixMs, report.SampleFinishedUnixMs)
			}
			if report.Current.CpuUsageNs != 123456789 || report.Current.MemoryUsageBytes != 1073741824 || report.Current.MemoryMaxUsageBytes != 3221225472 || report.Current.CpuPeriodUsec != 100000 || !report.Current.CpuLimitsKnown || !report.Current.CpuPressureKnown || report.Current.CpuPeriods != 555 || report.Current.CpuThrottledPeriods != 6 || report.Current.CpuThrottledNs != 987654321 || !report.Current.MemoryPressureKnown || report.Current.MemoryHighEvents != 7 || report.Current.MemoryOomEvents != 8 || report.Current.MemoryOomKillEvents != 9 {
				t.Fatalf("allowlisted stats not copied: %+v", report)
			}
			for _, leak := range []string{"secret-command", "SECRET_ENV", "secret-value", "secret-state-message", "/secret/stdout-path", "secret-metric", "SECRET-elastic-policy", "elastic", "akernel.scheduler", "birth-resources"} {
				if strings.Contains(response.Body.String(), leak) {
					t.Fatalf("leaked %s in %s", leak, response.Body.String())
				}
			}
			if client.calls != 2 || client.statsCalls != 1 {
				t.Fatalf("unexpected backend calls %d %d", client.calls, client.statsCalls)
			}
		})
	}
}

func TestResourcesAcceptsRestorePhaseBirth(t *testing.T) {
	status := birthStatus()
	status.Labels[birthResourcesLabel] = birthLabel(func(evidence map[string]any) { evidence["phase"] = "restore" })
	first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{status}}
	second := proto.Clone(first).(*runtime.ListSandboxesResponse)
	client := &fakeClient{first: first, second: second, stats: grownStats()}
	token := strings.Repeat("x", 32)
	handler, err := New(client, token)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/resources?ip=10.88.0.1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	var report resourceReport
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &report) != nil || report.Birth.Phase != "restore" {
		t.Fatalf("invalid response %d %s", response.Code, response.Body.String())
	}
}

func TestResourcesRejectsBadBirthEvidence(t *testing.T) {
	badBirths := []struct {
		name   string
		label  string
		absent bool
	}{
		{name: "absent", absent: true},
		{name: "empty", label: ""},
		{name: "not-json", label: `{"schema_version":1,`},
		{name: "json-array", label: `[]`},
		{name: "unknown-field", label: birthLabel(func(evidence map[string]any) { evidence["cpu_total_usec"] = 1 })},
		{name: "trailing-object", label: birthLabel(nil) + `{"extra":1}`},
		{name: "schema-2", label: birthLabel(func(evidence map[string]any) { evidence["schema_version"] = 2 })},
		{name: "phase-restart", label: birthLabel(func(evidence map[string]any) { evidence["phase"] = "restart" })},
		{name: "zero-timestamp", label: birthLabel(func(evidence map[string]any) { evidence["observed_at_unix_ms"] = 0 })},
		{name: "negative-timestamp", label: birthLabel(func(evidence map[string]any) { evidence["observed_at_unix_ms"] = -1 })},
		{name: "future-timestamp", label: birthLabel(func(evidence map[string]any) { evidence["observed_at_unix_ms"] = time.Now().Add(time.Hour).UnixMilli() })},
		{name: "unlimited-quota", label: birthLabel(func(evidence map[string]any) { evidence["cpu_quota_usec"] = -1 })},
		{name: "zero-quota", label: birthLabel(func(evidence map[string]any) { evidence["cpu_quota_usec"] = 0 })},
		{name: "zero-period", label: birthLabel(func(evidence map[string]any) { evidence["cpu_period_usec"] = 0 })},
		{name: "zero-memory", label: birthLabel(func(evidence map[string]any) { evidence["memory_limit_bytes"] = 0 })},
		{name: "wrong-sandbox", label: birthLabel(func(evidence map[string]any) { evidence["sandbox_id"] = "other" })},
		{name: "wrong-generation", label: birthLabel(func(evidence map[string]any) { evidence["resource_generation"] = "other" })},
		{name: "oversized", label: strings.Repeat(" ", maxBirthResourceEvidenceBytes+1) + birthLabel(nil)},
	}
	for _, bad := range badBirths {
		t.Run(bad.name, func(t *testing.T) {
			status := birthStatus()
			if bad.absent {
				delete(status.Labels, birthResourcesLabel)
			} else {
				status.Labels[birthResourcesLabel] = bad.label
			}
			first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{status}}
			second := proto.Clone(first).(*runtime.ListSandboxesResponse)
			client := &fakeClient{first: first, second: second, stats: grownStats()}
			token := strings.Repeat("x", 32)
			handler, err := New(client, token)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/resources?ip=10.88.0.1", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != 409 || response.Body.String() != "birth resource evidence missing, malformed, or changed\n" {
				t.Fatalf("expected generic 409, got %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestResourcesRejectsChangedBirthAndIdentityAcrossSnapshots(t *testing.T) {
	for _, mode := range []string{"rewritten", "removed", "replaced-sandbox", "exited-second", "wrong-stats-generation"} {
		t.Run(mode, func(t *testing.T) {
			status := birthStatus()
			first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{status}}
			second := proto.Clone(first).(*runtime.ListSandboxesResponse)
			client := &fakeClient{first: first, second: second, stats: grownStats()}
			switch mode {
			case "rewritten":
				second.Sandboxes[0].Labels[birthResourcesLabel] = birthLabel(func(evidence map[string]any) { evidence["memory_limit_bytes"] = 4294967296 })
			case "removed":
				delete(second.Sandboxes[0].Labels, birthResourcesLabel)
			case "replaced-sandbox":
				second.Sandboxes[0].ID = "replacement"
			case "exited-second":
				second.Sandboxes[0].State = runtime.SandboxState_SANDBOX_STATE_EXITED
			case "wrong-stats-generation":
				client.stats.ResourceGeneration = "replacement"
			}
			token := strings.Repeat("x", 32)
			handler, err := New(client, token)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/resources?ip=10.88.0.1", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			code, body := 409, "birth resource evidence missing, malformed, or changed\n"
			if mode == "replaced-sandbox" || mode == "exited-second" {
				body = "identity changed during lookup\n"
			}
			if mode == "wrong-stats-generation" {
				code, body = 503, "physical identity changed or unavailable\n"
			}
			if response.Code != code || response.Body.String() != body {
				t.Fatalf("expected %d %q, got %d %s", code, body, response.Code, response.Body.String())
			}
		})
	}
}

func TestResolveUnchangedWithAndWithoutBirthEvidence(t *testing.T) {
	for _, mode := range []string{"valid-birth", "no-birth"} {
		t.Run(mode, func(t *testing.T) {
			status := runningStatus()
			if mode == "valid-birth" {
				status.Labels[birthResourcesLabel] = birthLabel(nil)
			}
			first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{status}}
			second := proto.Clone(first).(*runtime.ListSandboxesResponse)
			client := &fakeClient{first: first, second: second, stats: &runtime.StatsResponse{ResourceGeneration: "generation"}}
			token := strings.Repeat("x", 32)
			handler, err := New(client, token)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/resolve?ip=10.88.0.1", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			encoded, err := json.Marshal(Identity{Instance: "instance", SandboxID: "sandbox", RuntimeID: "runtime", ResourceGeneration: "generation"})
			if err != nil {
				t.Fatal(err)
			}
			if response.Code != 200 || response.Body.String() != string(encoded)+"\n" {
				t.Fatalf("resolve response changed: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestResourcesSharesResolverGuards(t *testing.T) {
	requests := []struct {
		query      string
		method     string
		authorized bool
		code       int
	}{
		{query: "/resources", method: "GET", authorized: true, code: 400},
		{query: "/resources?ip=10.88.0.1&instance_id=instance", method: "GET", authorized: true, code: 400},
		{query: "/resources?ips=10.88.0.1", method: "GET", authorized: true, code: 400},
		{query: "/resource?ip=10.88.0.1", method: "GET", authorized: true, code: 404},
		{query: "/resources?ip=10.88.0.1", method: "POST", authorized: true, code: 405},
		{query: "/resources?ip=10.88.0.1", method: "GET", authorized: false, code: 401},
	}
	for _, request := range requests {
		t.Run(request.method+" "+request.query, func(t *testing.T) {
			first := &runtime.ListSandboxesResponse{Sandboxes: []*runtime.SandboxStatus{birthStatus()}}
			client := &fakeClient{first: first, second: proto.Clone(first).(*runtime.ListSandboxesResponse), stats: grownStats()}
			token := strings.Repeat("x", 32)
			handler, err := New(client, token)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(request.method, request.query, nil)
			if request.authorized {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != request.code {
				t.Fatalf("expected %d, got %d for %s", request.code, response.Code, request.query)
			}
			if client.calls != 0 || client.statsCalls != 0 {
				t.Fatalf("rejected request %s reached daemon", request.query)
			}
		})
	}
}
