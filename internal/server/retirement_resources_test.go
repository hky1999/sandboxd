// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// retirementCgroups is a bounded fake cgroup manager: deterministic stats, an
// optional failure, a synchronous hook so a test can move sandbox metadata
// while a capture's Stats read is in flight, and recycle recording so a test
// can prove what was already durable when the daemon released the cgroup.
type retirementCgroups struct {
	stats     cgroupmanager.Stats
	fail      bool
	onStats   func()
	onRecycle func()
	recycled  []string
}

func (c *retirementCgroups) ReadMemoryLimit(string) (int64, error) { return 0, nil }

func (*retirementCgroups) Allocate() (string, error)  { return "/sandbox/lease", nil }
func (*retirementCgroups) ShutDown() error            { return nil }
func (*retirementCgroups) SupportsMemoryShrink() bool { return false }

func (*retirementCgroups) Prepare(string, *runtime.LinuxSandboxResources) error {
	return nil
}

func (*retirementCgroups) CgroupIdentity(string) (cgroupmanager.CgroupIdentity, error) {
	return cgroupmanager.CgroupIdentity{}, errors.New("retirement fake has no cgroup identity")
}

func (*retirementCgroups) ReadFreeze(string) (cgroupmanager.FreezeState, error) {
	return cgroupmanager.FreezeState{}, errors.New("retirement fake has no freeze support")
}

func (*retirementCgroups) WriteFreeze(string, bool) error {
	return errors.New("retirement fake has no freeze support")
}

func (*retirementCgroups) WriteMemoryLimits(string, uint64, uint64) error {
	return errors.New("retirement fake has no ordered memory writes")
}

func (c *retirementCgroups) Stats(string) (cgroupmanager.Stats, error) {
	if c.onStats != nil {
		c.onStats()
	}
	if c.fail {
		return cgroupmanager.Stats{}, errors.New("stats unavailable")
	}
	return c.stats, nil
}

func (c *retirementCgroups) Recycle(path string) error {
	c.recycled = append(c.recycled, path)
	if c.onRecycle != nil {
		c.onRecycle()
	}
	return nil
}

// retirementObservingDeleteHandler proves ordering around the runtime
// handler: the before-record must already be durable when Delete begins, and
// the handler's cleanup — unlike the daemon's resource release — leaves the
// cgroup alive, so it bumps the fake cumulative counters the after-record
// must observe. afterDelete is a bounded test hook (never a production fault
// hook) for post-delete fault injection.
type retirementObservingDeleteHandler struct {
	*svc.FakeRuntimeHandler
	calls       int
	evidenceDir string
	observed    []string
	cgroups     *retirementCgroups
	afterDelete func() error
	afterErr    error
}

func (h *retirementObservingDeleteHandler) Delete(_ context.Context, _ string) error {
	h.calls++
	if entries, err := os.ReadDir(h.evidenceDir); err == nil {
		for _, entry := range entries {
			h.observed = append(h.observed, entry.Name())
		}
	}
	if h.cgroups != nil {
		h.cgroups.stats.CPUUsageNanos += 1000
		h.cgroups.stats.MemoryMaxUsageBytes += 4096
	}
	if h.afterDelete != nil {
		h.afterErr = h.afterDelete()
	}
	return nil
}

// flakyDeleteHandler fails the first physical delete so a retry must add new
// observations under a fresh attempt ID instead of replacing the first.
type flakyDeleteHandler struct {
	*svc.FakeRuntimeHandler
	calls int
}

func (h *flakyDeleteHandler) Delete(_ context.Context, _ string) error {
	h.calls++
	if h.calls == 1 {
		return errors.New("runtime delete failed")
	}
	return nil
}

// storeRetirementSandbox mirrors storeSandboxForDelete for a committed
// scheduler-managed incarnation: bundle, spec, cgroup fact, generation and
// trusted identity labels, plus any extra labels (typically birth evidence).
func storeRetirementSandbox(t *testing.T, s *sandboxService, id, generation string, extraLabels map[string]string) {
	t.Helper()
	bundleDir := filepath.Join(s.config.RootDir, "containers", id)
	require.NoError(t, os.MkdirAll(bundleDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`),
		0600,
	))
	labels := map[string]string{
		resourceGenerationLabel:  generation,
		schedulerInstanceIDLabel: "instance-" + id,
		schedulerRuntimeIDLabel:  "runtime-" + id,
	}
	for name, value := range extraLabels {
		labels[name] = value
	}
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID: id, RuntimeHandler: "runsc", Labels: labels,
		ResourceFacts: map[string]string{config.ResourceNameCgroup: "/sandbox/lease"},
	}))
}

func retirementBirthLabel(t *testing.T, id, generation string) string {
	t.Helper()
	raw, err := json.Marshal(birthResourceEvidence{
		SchemaVersion:      birthResourceEvidenceSchemaVersion,
		SandboxID:          id,
		ResourceGeneration: generation,
		Phase:              "start",
		ObservedAtUnixMs:   time.Now().UnixMilli(),
		CpuQuotaUsec:       50000,
		CpuPeriodUsec:      100000,
		MemoryLimitBytes:   512 * 1024 * 1024,
	})
	require.NoError(t, err)
	return string(raw)
}

func retirementEvidencePrefix(id, generation string) string {
	key, _ := json.Marshal([2]string{id, generation})
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:]) + "."
}

// readRetirementEvidence loads every durable evidence record for one sandbox
// generation, decoding under the same strict schema rules the writer emits.
// Records are located and correlated by their contents — phase, attempt and
// record IDs — never by filesystem or UUID ordering.
func readRetirementEvidence(t *testing.T, s *sandboxService, id, generation string) []retirementResourceRecord {
	t.Helper()
	dir := s.retirementResourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		require.ErrorIs(t, err, os.ErrNotExist)
		return nil
	}
	prefix := retirementEvidencePrefix(id, generation)
	var records []retirementResourceRecord
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		var record retirementResourceRecord
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		require.NoError(t, decoder.Decode(&record))
		require.Equal(t, io.EOF, decoder.Decode(new(any)), "record must be exactly one JSON object")
		require.Equal(t, id, record.SandboxID)
		require.Equal(t, generation, record.ResourceGeneration)
		records = append(records, record)
	}
	return records
}

func readRetirementEvidenceBytes(t *testing.T, s *sandboxService, id, generation string) []byte {
	t.Helper()
	prefix := retirementEvidencePrefix(id, generation)
	entries, err := os.ReadDir(s.retirementResourceDir())
	require.NoError(t, err)
	var raw []byte
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".json") {
			data, err := os.ReadFile(filepath.Join(s.retirementResourceDir(), name))
			require.NoError(t, err)
			raw = append(raw, data...)
		}
	}
	return raw
}

// recordsByPhase groups one generation's records by their observation phase.
func recordsByPhase(records []retirementResourceRecord) map[string]retirementResourceRecord {
	byPhase := make(map[string]retirementResourceRecord)
	for _, record := range records {
		byPhase[record.Phase] = record
	}
	return byPhase
}

// A successful matching-generation delete leaves two correlated records: the
// before-record durable before the handler runs, the after-record — observing
// the post-handler cumulative counters — durable before the cgroup is
// recycled, both under exact artifact ownership and one attempt ID.
func TestPreDeleteCapturePersistsSampleAndBirthBeforeHandler(t *testing.T) {
	handler := &retirementObservingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	cgroups := &retirementCgroups{stats: cgroupmanager.Stats{
		CPUUsageNanos: 123000, CPUUsageKnown: true,
		CPUQuotaUsec: 50000, CPUPeriodUsec: 100000, CPULimitsKnown: true,
		CPUPressureKnown: true, CPUPeriods: 25, CPUThrottledPeriods: 4, CPUThrottledNanos: 123000,
		MemoryUsageBytes: 4096, MemoryUsageKnown: true,
		MemoryLimitBytes: 512 * 1024 * 1024, MemoryLimitKnown: true,
		MemoryMaxUsageBytes: 8192, MemoryPeakKnown: true,
		MemoryPressureKnown: true, MemoryHighEvents: 9, MemoryOOMEvents: 2, MemoryOOMKillEvents: 1,
	}}
	s.cgroupMgr = cgroups
	handler.evidenceDir = s.retirementResourceDir()
	handler.cgroups = cgroups
	recycledEvidence := -1
	cgroups.onRecycle = func() {
		if entries, err := os.ReadDir(s.retirementResourceDir()); err == nil {
			recycledEvidence = len(entries)
		}
	}
	const id = "retire-evidence"
	storeRetirementSandbox(t, s, id, "generation-1", map[string]string{
		birthResourcesLabel:   retirementBirthLabel(t, id, "generation-1"),
		elasticResourcesLabel: `{"version":1,"LEAK-POLICY":"secret"}`,
	})

	response, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-1"})
	require.NoError(t, err)
	require.Equal(t, "generation-1", response.RetiredGeneration)
	require.Equal(t, 1, handler.calls)

	records := readRetirementEvidence(t, s, id, "generation-1")
	require.Len(t, records, 2)
	byPhase := recordsByPhase(records)
	require.Len(t, byPhase, 2)
	before := byPhase[retirementResourcePhaseBeforeDelete]
	after := byPhase[retirementResourcePhaseAfterDelete]

	// Exactly the before-record was durable when the handler began, and both
	// records were durable before the daemon recycled the cgroup.
	require.Len(t, handler.observed, 1)
	require.Equal(t, retirementEvidencePrefix(id, "generation-1")+before.RecordID+".json", handler.observed[0])
	require.False(t, strings.HasPrefix(handler.observed[0], "."), "temp artifacts must not survive publication")
	require.Equal(t, 2, recycledEvidence)
	require.Equal(t, []string{"/sandbox/lease"}, cgroups.recycled)

	// Exact ownership: 0700 directory, only 0600 record files.
	info, err := os.Stat(s.retirementResourceDir())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	entries, err := os.ReadDir(s.retirementResourceDir())
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasPrefix(entry.Name(), "."), "no temp names may remain")
		info, err := os.Stat(filepath.Join(s.retirementResourceDir(), entry.Name()))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}

	// One attempt, two observations, two unique record IDs.
	require.NotEmpty(t, before.DeleteAttemptID)
	require.Equal(t, before.DeleteAttemptID, after.DeleteAttemptID)
	require.NotEqual(t, before.RecordID, after.RecordID)
	for _, record := range []retirementResourceRecord{before, after} {
		require.Equal(t, retirementResourceRecordSchema, record.SchemaVersion)
		require.Equal(t, id, record.SandboxID)
		require.Equal(t, "generation-1", record.ResourceGeneration)
		require.Equal(t, "instance-retire-evidence", record.InstanceID)
		require.Equal(t, "runtime-retire-evidence", record.RuntimeID)
		require.True(t, record.IdentityComplete)
		require.True(t, record.MetadataCommitted)
		require.False(t, record.PhysicalDeletionConfirmed)
		require.Greater(t, record.SampleStartedUnixMs, int64(0))
		require.GreaterOrEqual(t, record.SampleFinishedUnixMs, record.SampleStartedUnixMs)
		require.LessOrEqual(t, record.SampleFinishedUnixMs, time.Now().UnixMilli())
		require.Equal(t, retirementBirthStatusOk, record.BirthStatus)
		require.NotNil(t, record.Birth)
		require.Equal(t, "start", record.Birth.Phase)
		require.Equal(t, int64(50000), record.Birth.CpuQuotaUsec)
		require.Equal(t, uint64(100000), record.Birth.CpuPeriodUsec)
		require.Equal(t, uint64(512*1024*1024), record.Birth.MemoryLimitBytes)
		require.Equal(t, retirementSampleStatusOk, record.SampleStatus)
		require.NotNil(t, record.Sample)
		require.True(t, record.Sample.CpuUsageKnown)
		require.True(t, record.Sample.MemoryUsageKnown)
		require.True(t, record.Sample.MemoryLimitKnown)
		require.True(t, record.Sample.MemoryPeakKnown)
		require.True(t, record.Sample.CpuLimitsKnown)
		require.True(t, record.Sample.CpuPressureKnown)
		require.Equal(t, uint64(25), record.Sample.CpuPeriods)
		require.Equal(t, uint64(4), record.Sample.CpuThrottledPeriods)
		require.Equal(t, uint64(123000), record.Sample.CpuThrottledNs)
		require.True(t, record.Sample.MemoryPressureKnown)
		require.Equal(t, uint64(9), record.Sample.MemoryHighEvents)
		require.Equal(t, uint64(2), record.Sample.MemoryOomEvents)
		require.Equal(t, uint64(1), record.Sample.MemoryOomKillEvents)
		require.Equal(t, int64(50000), record.Sample.CpuQuotaUsec)
		require.Equal(t, uint64(100000), record.Sample.CpuPeriodUsec)
		require.Equal(t, uint64(4096), record.Sample.MemoryUsageBytes)
		require.Equal(t, uint64(512*1024*1024), record.Sample.MemoryLimitBytes)
	}

	// The samples bracket the handler: the after-record observes the
	// cumulative counters the handler itself bumped.
	require.Equal(t, uint64(123000), before.Sample.CpuUsageNs)
	require.Equal(t, uint64(124000), after.Sample.CpuUsageNs)
	require.Equal(t, uint64(8192), before.Sample.MemoryMaxUsageBytes)
	require.Equal(t, uint64(8192+4096), after.Sample.MemoryMaxUsageBytes)

	// The allowlist never carries the elastic policy or any raw label value.
	raw := readRetirementEvidenceBytes(t, s, id, "generation-1")
	require.NotContains(t, string(raw), "LEAK-POLICY")
	require.NotContains(t, string(raw), elasticResourcesLabel)
}

// Legacy Delete on a sandbox that happens to carry a generation label is
// captured around the handler too, with unknown source-validity flags
// forwarded as false rather than inferred from the nonzero numbers.
func TestLegacyDeleteOnGeneratedSandboxStillCapturesEvidence(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	s.cgroupMgr = &retirementCgroups{stats: cgroupmanager.Stats{
		CPUUsageNanos: 777000, MemoryUsageBytes: 2048,
		MemoryMaxUsageBytes: 4096, CPUQuotaUsec: 100000, CPUPeriodUsec: 100000,
	}}
	const id = "retire-legacy"
	storeRetirementSandbox(t, s, id, "generation-legacy", nil)

	_, err := s.Delete(context.Background(), &runtime.DeleteRequest{ID: id, Timeout: 30})
	require.NoError(t, err)
	require.Equal(t, 1, handler.calls)

	records := readRetirementEvidence(t, s, id, "generation-legacy")
	require.Len(t, records, 2)
	for _, record := range records {
		require.Equal(t, retirementSampleStatusOk, record.SampleStatus)
		require.NotNil(t, record.Sample)
		require.Equal(t, uint64(777000), record.Sample.CpuUsageNs)
		require.False(t, record.Sample.CpuUsageKnown)
		require.False(t, record.Sample.MemoryUsageKnown)
		require.False(t, record.Sample.MemoryLimitKnown)
		require.False(t, record.Sample.MemoryPeakKnown)
		require.False(t, record.Sample.CpuLimitsKnown)
		require.Equal(t, uint64(4096), record.Sample.MemoryMaxUsageBytes)
		require.Equal(t, retirementBirthStatusMissing, record.BirthStatus)
		require.Nil(t, record.Birth)
	}
	require.Equal(t, records[0].DeleteAttemptID, records[1].DeleteAttemptID)
}

// Sandboxes without a generation label keep the unconditional legacy path:
// no evidence directory, no behavior change.
func TestDeleteWithoutGenerationLabelKeepsLegacyBehavior(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "retire-ungenerated"
	storeSandboxForDelete(t, s, id)

	_, err := s.Delete(context.Background(), &runtime.DeleteRequest{ID: id, Timeout: 30})
	require.NoError(t, err)
	require.Equal(t, 1, handler.calls)
	require.NoDirExists(t, s.retirementResourceDir())
}

// A failed physical delete emits only the before-record; the retry runs under
// a fresh attempt ID and emits before+after, preserving every prior record.
func TestRetirementEvidenceRetryAfterFailedHandlerPreservesBothObservations(t *testing.T) {
	handler := &flakyDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	s.cgroupMgr = &retirementCgroups{stats: cgroupmanager.Stats{CPUUsageNanos: 42, CPUUsageKnown: true}}
	const id = "retire-retry"
	storeRetirementSandbox(t, s, id, "generation-retry", nil)

	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-retry"}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.Error(t, err)
	require.Equal(t, 1, handler.calls)
	first := readRetirementEvidence(t, s, id, "generation-retry")
	require.Len(t, first, 1)
	require.Equal(t, retirementResourcePhaseBeforeDelete, first[0].Phase)
	require.Equal(t, retirementSampleStatusOk, first[0].SampleStatus)
	firstAttempt, firstRecord := first[0].DeleteAttemptID, first[0].RecordID

	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, 2, handler.calls)
	records := readRetirementEvidence(t, s, id, "generation-retry")
	require.Len(t, records, 3)

	attempts := make(map[string][]string)
	recordIDs := make(map[string]bool)
	for _, record := range records {
		attempts[record.DeleteAttemptID] = append(attempts[record.DeleteAttemptID], record.Phase)
		recordIDs[record.RecordID] = true
	}
	require.Len(t, recordIDs, 3, "every observation keeps its own record file")
	require.Len(t, attempts, 2)
	require.Equal(t, []string{retirementResourcePhaseBeforeDelete}, attempts[firstAttempt],
		"the failed attempt must keep exactly its before observation")
	retryAttempt := ""
	for attempt := range attempts {
		if attempt != firstAttempt {
			retryAttempt = attempt
		}
	}
	require.ElementsMatch(t, []string{
		retirementResourcePhaseBeforeDelete, retirementResourcePhaseAfterDelete,
	}, attempts[retryAttempt])
	require.True(t, recordIDs[firstRecord], "the original observation must survive the retry")

	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err) // completed receipt replay
	require.Equal(t, 2, handler.calls)
	require.Len(t, readRetirementEvidence(t, s, id, "generation-retry"), 3)
}

// A failed Stats read is honest absence: sample null, status unavailable. A
// post-handler failure still lets the cleanup proceed to a completed receipt
// while the before-record keeps its good sample.
func TestUnavailableStatsRecordsNullSampleAndStillCleansUp(t *testing.T) {
	handler := &retirementObservingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	cgroups := &retirementCgroups{stats: cgroupmanager.Stats{
		CPUUsageNanos: 555000, CPUUsageKnown: true, MemoryPeakKnown: true, MemoryMaxUsageBytes: 4096,
	}}
	s.cgroupMgr = cgroups
	handler.cgroups = cgroups
	handler.afterDelete = func() error { cgroups.fail = true; return nil }
	const id = "retire-stats-down"
	storeRetirementSandbox(t, s, id, "generation-stats", map[string]string{
		birthResourcesLabel: retirementBirthLabel(t, id, "generation-stats"),
	})

	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-stats"})
	require.NoError(t, err)
	require.Equal(t, 1, handler.calls)

	records := readRetirementEvidence(t, s, id, "generation-stats")
	require.Len(t, records, 2)
	before := recordsByPhase(records)[retirementResourcePhaseBeforeDelete]
	after := recordsByPhase(records)[retirementResourcePhaseAfterDelete]
	require.Equal(t, retirementSampleStatusOk, before.SampleStatus)
	require.NotNil(t, before.Sample)
	require.Equal(t, uint64(555000), before.Sample.CpuUsageNs)
	require.True(t, before.Sample.CpuUsageKnown)
	require.Equal(t, retirementSampleStatusUnavailable, after.SampleStatus)
	require.Nil(t, after.Sample)
	require.Equal(t, before.DeleteAttemptID, after.DeleteAttemptID)
	require.Equal(t, retirementBirthStatusOk, before.BirthStatus)
	require.Equal(t, retirementBirthStatusOk, after.BirthStatus)

	receipt, err := s.readRetirement(id, "generation-stats")
	require.NoError(t, err)
	require.True(t, receipt.Complete)
	require.Equal(t, []string{"/sandbox/lease"}, cgroups.recycled)
	_, err = s.sandboxManager.Get(id)
	require.ErrorIs(t, err, errord.ErrNotFound)
}

// A stale expected generation is refused before any capture or deletion.
func TestStaleGenerationProducesNoCaptureOrDeletion(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	s.cgroupMgr = &retirementCgroups{}
	const id = "retire-stale"
	storeRetirementSandbox(t, s, id, "generation-1", nil)

	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "stale"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.calls)
	require.NoDirExists(t, s.retirementResourceDir())
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err)
}

// If the metadata identity moves while a capture's Stats read is in flight,
// the delete is refused rather than archiving a mixed observation.
func TestSnapshotIdentityMutationDuringStatsRefusesDeletion(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "retire-moving"
	cgroups := &retirementCgroups{}
	cgroups.onStats = func() {
		require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{resourceGenerationLabel: "generation-2"}))
	}
	s.cgroupMgr = cgroups
	storeRetirementSandbox(t, s, id, "generation-1", nil)

	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-1"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.calls)
	require.Empty(t, readRetirementEvidence(t, s, id, "generation-1"))
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, "generation-2", current.Metadata.Labels[resourceGenerationLabel])
}

// A completed receipt replays without new evidence, and never touches a
// replacement incarnation now owning the ID.
func TestCompletedReceiptReplayAddsNoRecordsAndSparesReplacement(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	s.cgroupMgr = &retirementCgroups{}
	const id = "retire-replay"
	storeRetirementSandbox(t, s, id, "generation-1", nil)

	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-1"}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, 1, handler.calls)
	require.Len(t, readRetirementEvidence(t, s, id, "generation-1"), 2)

	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, 1, handler.calls)
	require.Len(t, readRetirementEvidence(t, s, id, "generation-1"), 2)

	storeRetirementSandbox(t, s, id, "generation-2", nil)
	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err) // the old-generation receipt cannot touch the replacement
	require.Equal(t, 1, handler.calls)
	require.Len(t, readRetirementEvidence(t, s, id, "generation-1"), 2)
	require.Empty(t, readRetirementEvidence(t, s, id, "generation-2"))
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, "generation-2", current.Metadata.Labels[resourceGenerationLabel])
}

// Bad birth labels are recorded by explicit category with no raw label text
// leaked into the artifact; nil metadata is an error, never a panic.
func TestRetirementBirthCategoriesAndNilMetadata(t *testing.T) {
	foreignBirth, err := json.Marshal(map[string]any{
		"schema_version": 1, "sandbox_id": "retire-birth",
		"resource_generation": "generation-other", "phase": "start",
		"observed_at_unix_ms": time.Now().UnixMilli(),
		"cpu_quota_usec":      50000, "cpu_period_usec": 100000,
		"memory_limit_bytes": 512 * 1024 * 1024,
	})
	require.NoError(t, err)
	badBirthLabels := []struct{ name, label string }{
		{"malformed", `{"schema_version":1, LEAK-MALFORMED`},
		{"oversize", `{"schema_version":1,"note":"LEAK-OVERSIZE","pad":"` + strings.Repeat("x", 5000) + `"}`},
		{"unknown field", `{"schema_version":1,"sandbox_id":"retire-birth","LEAK-UNKNOWN":1}`},
		{"foreign generation", string(foreignBirth)},
	}
	for _, bad := range badBirthLabels {
		t.Run(bad.name, func(t *testing.T) {
			handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			s.cgroupMgr = &retirementCgroups{}
			const id = "retire-birth"
			storeRetirementSandbox(t, s, id, "generation-1", map[string]string{birthResourcesLabel: bad.label})

			_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-1"})
			require.NoError(t, err)
			records := readRetirementEvidence(t, s, id, "generation-1")
			require.Len(t, records, 2)
			for _, record := range records {
				require.Equal(t, retirementBirthStatusInvalid, record.BirthStatus)
				require.Nil(t, record.Birth)
			}
			require.NotContains(t, string(readRetirementEvidenceBytes(t, s, id, "generation-1")), "LEAK-")
		})
	}

	t.Run("nil metadata refuses rather than panics", func(t *testing.T) {
		s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
		require.Error(t, s.captureRetirementResources("retire-birth", "generation-1",
			"attempt", retirementResourcePhaseBeforeDelete, nil))
		require.NoDirExists(t, s.retirementResourceDir())
	})

	t.Run("uncommitted snapshot cannot replace committed metadata", func(t *testing.T) {
		s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
		s.cgroupMgr = &retirementCgroups{}
		const id = "retire-birth"
		storeRetirementSandbox(t, s, id, "generation-1", map[string]string{
			birthResourcesLabel: retirementBirthLabel(t, id, "generation-1"),
		})
		intent := &runtime.SandboxMetadata{
			ID: id, RuntimeHandler: "runsc",
			Labels: map[string]string{
				resourceGenerationLabel:  "generation-1",
				schedulerInstanceIDLabel: "instance-" + id,
				schedulerRuntimeIDLabel:  "runtime-" + id,
				birthResourcesLabel:      retirementBirthLabel(t, id, "generation-1"),
			},
			PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
		}
		require.Error(t, s.captureRetirementResources(id, "generation-1",
			"attempt", retirementResourcePhaseBeforeDelete, intent))
		records := readRetirementEvidence(t, s, id, "generation-1")
		require.Empty(t, records)
	})
}

// Untrusted identity labels collapse to empty with identity_complete false,
// and their unvetted text never reaches the artifact. The control-character
// case is built through rune(0) so the test source itself can never hold a
// literal NUL byte.
func TestRetirementIdentityLabelsAreAllowlisted(t *testing.T) {
	untrustedLabels := []struct {
		name         string
		instance     string
		runtimeID    string
		wantInstance string
		wantRuntime  string
	}{
		{"whitespace instance", "instance with space", "runtime-ok", "", "runtime-ok"},
		{"control runtime", "instance-ok", "runtime" + string(rune(0)) + "id", "instance-ok", ""},
		{"oversize instance", strings.Repeat("i", 300), "runtime-ok", "", "runtime-ok"},
		{"missing runtime", "instance-ok", "", "instance-ok", ""},
	}
	for _, untrusted := range untrustedLabels {
		t.Run(untrusted.name, func(t *testing.T) {
			handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			s.cgroupMgr = &retirementCgroups{}
			const id = "retire-identity"
			bundleDir := filepath.Join(s.config.RootDir, "containers", id)
			require.NoError(t, os.MkdirAll(bundleDir, 0755))
			require.NoError(t, os.WriteFile(
				filepath.Join(bundleDir, config.SandboxSpecFile),
				[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`),
				0600,
			))
			labels := map[string]string{resourceGenerationLabel: "generation-identity"}
			if untrusted.instance != "" {
				labels[schedulerInstanceIDLabel] = untrusted.instance
			}
			if untrusted.runtimeID != "" {
				labels[schedulerRuntimeIDLabel] = untrusted.runtimeID
			}
			require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
				ID:             id,
				RuntimeHandler: "runsc",
				Labels:         labels,
				ResourceFacts:  map[string]string{config.ResourceNameCgroup: "/sandbox/lease"},
			}))

			_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-identity"})
			require.NoError(t, err)
			records := readRetirementEvidence(t, s, id, "generation-identity")
			require.Len(t, records, 2)
			raw := string(readRetirementEvidenceBytes(t, s, id, "generation-identity"))
			for _, record := range records {
				require.False(t, record.IdentityComplete)
				require.Equal(t, untrusted.wantInstance, record.InstanceID)
				require.Equal(t, untrusted.wantRuntime, record.RuntimeID)
			}
			if untrusted.wantInstance == "" && untrusted.instance != "" {
				require.NotContains(t, raw, untrusted.instance)
			}
			if untrusted.wantRuntime == "" && untrusted.runtimeID != "" {
				require.NotContains(t, raw, untrusted.runtimeID)
			}
		})
	}
}

// An unusable artifact directory before the handler prevents the physical
// delete — no pending receipt, no handler call, metadata intact for the
// retry once it clears.
func TestRetirementEvidenceDirectoryFailurePreventsHandlerDelete(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	s.cgroupMgr = &retirementCgroups{}
	const id = "retire-blocked"
	storeRetirementSandbox(t, s, id, "generation-blocked", nil)
	require.NoError(t, os.WriteFile(s.retirementResourceDir(), []byte("not a directory"), 0600))

	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-blocked"}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.Error(t, err)
	require.Zero(t, handler.calls)
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.NoDirExists(t, filepath.Join(s.config.RootDir, "scheduler-retirements"))

	require.NoError(t, os.Remove(s.retirementResourceDir()))
	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, 1, handler.calls)
	require.Len(t, readRetirementEvidence(t, s, id, "generation-blocked"), 2)
}

// An after-record persistence failure after a successful runtime delete must
// stop resource recycling and the completion receipt, leaving the recoverable
// unknown state; the retry under a fresh attempt ID completes it.
func TestAfterDeleteEvidenceFailureStopsResourceReleaseAndReceipt(t *testing.T) {
	handler := &retirementObservingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	cgroups := &retirementCgroups{stats: cgroupmanager.Stats{CPUUsageNanos: 42, CPUUsageKnown: true}}
	s.cgroupMgr = cgroups
	handler.cgroups = cgroups
	sabotaged := false
	handler.afterDelete = func() error {
		if sabotaged {
			return nil
		}
		sabotaged = true
		dir := s.retirementResourceDir()
		if err := os.Rename(dir, dir+".saved"); err != nil {
			return err
		}
		return os.WriteFile(dir, []byte("not a directory"), 0600)
	}
	const id = "retire-after-blocked"
	storeRetirementSandbox(t, s, id, "generation-after", nil)

	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation-after"}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.Error(t, err)
	require.NoError(t, handler.afterErr)
	require.Equal(t, 1, handler.calls)
	require.Empty(t, cgroups.recycled, "no resource may be recycled on uncertain journal state")
	receipt, err := s.readRetirement(id, "generation-after")
	require.NoError(t, err)
	require.False(t, receipt.Complete, "the completion receipt must not be written")
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err)

	// Clearing the obstacle exposes the failed attempt's before-record, and a
	// retry completes under a fresh attempt ID.
	require.NoError(t, os.Remove(s.retirementResourceDir()))
	require.NoError(t, os.Rename(s.retirementResourceDir()+".saved", s.retirementResourceDir()))
	preserved := readRetirementEvidence(t, s, id, "generation-after")
	require.Len(t, preserved, 1)
	require.Equal(t, retirementResourcePhaseBeforeDelete, preserved[0].Phase)
	require.Equal(t, retirementSampleStatusOk, preserved[0].SampleStatus)

	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, 2, handler.calls)
	records := readRetirementEvidence(t, s, id, "generation-after")
	require.Len(t, records, 3)
	attempts := make(map[string][]string)
	for _, record := range records {
		attempts[record.DeleteAttemptID] = append(attempts[record.DeleteAttemptID], record.Phase)
	}
	require.Len(t, attempts, 2)
	receipt, err = s.readRetirement(id, "generation-after")
	require.NoError(t, err)
	require.True(t, receipt.Complete)
	require.Equal(t, []string{"/sandbox/lease"}, cgroups.recycled)
}
