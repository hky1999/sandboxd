// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type realCloseMember struct {
	PID              int      `json:"pid"`
	StartTicks       uint64   `json:"start_ticks"`
	ExecutableSHA256 string   `json:"executable_sha256"`
	Cgroup           string   `json:"cgroup"`
	Command          []string `json:"command"`
	command          *exec.Cmd
	pidfd            int
	waited           bool
}

func readRealCloseMember(pid int) (realCloseMember, error) {
	root := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return realCloseMember{}, err
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return realCloseMember{}, errors.New("invalid original member stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return realCloseMember{}, errors.New("incomplete original member stat")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return realCloseMember{}, err
	}
	executable, err := os.ReadFile(filepath.Join(root, "exe"))
	if err != nil {
		return realCloseMember{}, err
	}
	digest := sha256.Sum256(executable)
	group, err := os.ReadFile(filepath.Join(root, "cgroup"))
	if err != nil {
		return realCloseMember{}, err
	}
	parts := strings.Split(strings.TrimSpace(string(group)), "::")
	if len(parts) != 2 || parts[0] != "0" {
		return realCloseMember{}, errors.New("original member cgroup is not known unified")
	}
	return realCloseMember{PID: pid, StartTicks: ticks, ExecutableSHA256: hex.EncodeToString(digest[:]), Cgroup: parts[1]}, nil
}

func realMemberResourceObservation(identity CgroupIdentity) map[string]any {
	result := map[string]any{"observed_at_utc": time.Now().UTC(), "original_cgroup": identity, "values": map[string]any{}, "scope": "Phase observation, not continuous sampling or a node-budget proof."}
	values := result["values"].(map[string]any)
	info, err := os.Stat(filepath.Join("/sys/fs/cgroup", identity.Path))
	var actual CgroupIdentity
	if err == nil {
		actual, err = cgroupIdentityFromInfo(identity.Path, info)
	}
	matched := err == nil && actual == identity
	result["original_identity_known"] = matched
	for _, name := range []string{"cpu.max", "cpu.stat", "memory.current", "memory.peak", "memory.high", "memory.max", "memory.events", "memory.pressure", "cgroup.events", "cgroup.freeze"} {
		var value any
		known := false
		if matched {
			data, readErr := os.ReadFile(filepath.Join("/sys/fs/cgroup", identity.Path, name))
			if readErr == nil {
				value, known = strings.TrimSpace(string(data)), true
			}
		}
		values[name] = map[string]any{"known": known, "value": value}
	}
	return result
}

func (p *realCloseMember) verify(t *testing.T) {
	t.Helper()
	actual, err := readRealCloseMember(p.PID)
	require.NoError(t, err)
	require.Equal(t, p.StartTicks, actual.StartTicks)
	require.Equal(t, p.ExecutableSHA256, actual.ExecutableSHA256)
	require.Equal(t, p.Cgroup, actual.Cgroup)
	polls := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	_, err = unix.Poll(polls, 0)
	require.NoError(t, err)
	require.Zero(t, polls[0].Revents, "original member must still be alive")
}

func (p *realCloseMember) confirmExit(t *testing.T) map[string]any {
	t.Helper()
	polls := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	_, err := unix.Poll(polls, 5000)
	require.NoError(t, err)
	require.NotZero(t, polls[0].Revents&unix.POLLIN, "original pidfd must independently confirm exit")
	err = p.command.Wait()
	p.waited = true
	var exited *exec.ExitError
	require.ErrorAs(t, err, &exited)
	return map[string]any{"original_process": p, "pidfd_exit_confirmed": true, "exit_code": p.command.ProcessState.ExitCode(), "exit_status": p.command.ProcessState.String()}
}

func startRealCloseMember(t *testing.T, path string) *realCloseMember {
	t.Helper()
	imageProgram, err := os.ReadFile("/usr/bin/sleep")
	require.NoError(t, err)
	digest := sha256.Sum256(imageProgram)
	command := exec.Command("/usr/bin/sleep", "120")
	require.NoError(t, command.Start())
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	require.NoError(t, err)
	before, err := readRealCloseMember(command.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(digest[:]), before.ExecutableSHA256)
	member := &before
	member.command, member.pidfd, member.Command = command, pidfd, command.Args
	// Cleanup only our directly created, pinned child after rechecking its
	// original executable and start time. No path-based group fallback.
	t.Cleanup(func() {
		defer unix.Close(pidfd)
		if member.waited {
			return
		}
		polls := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		_, err := unix.Poll(polls, 0)
		if err == nil && polls[0].Revents&unix.POLLIN != 0 {
			command.Wait()
			return
		}
		current, err := readRealCloseMember(member.PID)
		if err != nil || current.StartTicks != member.StartTicks || current.ExecutableSHA256 != member.ExecutableSHA256 {
			t.Errorf("original test child cannot be verified for cleanup: %v", err)
			return
		}
		if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil {
			t.Errorf("original test child cleanup failed: %v", err)
			return
		}
		_, err = unix.Poll(polls, 5000)
		if err == nil && polls[0].Revents&unix.POLLIN != 0 {
			command.Wait()
		} else {
			t.Errorf("original test child cleanup exit unconfirmed")
		}
	})
	require.NoError(t, os.WriteFile(filepath.Join("/sys/fs/cgroup", path, "cgroup.procs"), []byte(strconv.Itoa(member.PID)), 0600))
	member.Cgroup = path
	member.verify(t)
	return member
}

// Explicit owned BareMetal1 fixture. It exercises production directory-bound
// drain, real pidfds and real bbolt reopen with live neighbors. The OOM watcher
// is controlled; this is not a native sandbox, daemon restart or node budget.
func TestRealGenerationCloseWithMembersAndContinuation(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_CGROUP_MEMBER_CLOSE_INTEGRATION") != "1" {
		t.Skip("requires owned BareMetal1 real-member cgroup close fixture")
	}
	evidence := os.Getenv("CGROUP_CLOSE_EVIDENCE")
	require.True(t, filepath.IsAbs(evidence))
	var expected CgroupIdentity
	require.NoError(t, json.Unmarshal([]byte(os.Getenv("CGROUP_CLOSE_ROOT_IDENTITY")), &expected))
	info, err := os.Stat("/sys/fs/cgroup")
	require.NoError(t, err)
	root, err := cgroupIdentityFromInfo("/", info)
	require.NoError(t, err)
	require.Equal(t, expected.Device, root.Device)
	require.Equal(t, expected.Inode, root.Inode)
	require.NoError(t, os.MkdirAll(evidence, 0700))
	save := func(name string, value any) {
		data, err := json.MarshalIndent(value, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(evidence, name), append(data, '\n'), 0600))
	}
	parent := "/generation-member-fixture"
	require.NoError(t, os.Mkdir(filepath.Join("/sys/fs/cgroup", parent), 0755))
	observer, err := readRealCloseMember(os.Getpid())
	require.NoError(t, err)
	require.False(t, observer.Cgroup == parent || strings.HasPrefix(observer.Cgroup, parent+"/"))
	save("observer.json", observer)
	for _, scenario := range []string{"completed", "completion-save-failed", "continuation-save-failed"} {
		t.Run(scenario, func(t *testing.T) {
			peerPath, targetPath := parent+"/"+scenario+"-peer", parent+"/"+scenario+"-target"
			for _, path := range []string{peerPath, targetPath} {
				require.NoError(t, os.Mkdir(filepath.Join("/sys/fs/cgroup", path), 0755))
			}
			db := store.NewStoreImp(filepath.Join(evidence, scenario+".bbolt"))
			ops := &cgroupV2{mountpoint: "/sys/fs/cgroup"}
			makeManager := func(db store.DbStore) *CgroupManager {
				return &CgroupManager{rootName: parent, max: 2, cacheSize: 2, usingID: cmap.New[struct{}](), idleID: util.New(""), cgroups: cmap.New[struct{}](), gcQueue: util.New(""), gcWake: make(chan struct{}, 1), ops: ops, oom: newFakeOOMWatcher(), db: db}
			}
			m := makeManager(db)
			m.total = 2
			for _, path := range []string{targetPath, peerPath} {
				m.cgroups.Set(path, struct{}{})
				m.idleID.Push(path)
			}
			generation := "physical-members-" + scenario
			path, err := m.AllocateForGeneration(generation)
			require.NoError(t, err)
			require.Equal(t, targetPath, path)
			path, err = m.AllocateForGeneration(generation + "-peer")
			require.NoError(t, err)
			require.Equal(t, peerPath, path)
			target := startRealCloseMember(t, targetPath)
			peer := startRealCloseMember(t, peerPath)
			controls := func(path string) map[string]string {
				values := map[string]string{}
				for _, name := range []string{"cgroup.procs", "cgroup.events", "cgroup.freeze", "cgroup.type"} {
					data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", path, name))
					require.NoError(t, err)
					values[name] = string(data)
				}
				return values
			}
			peerBefore := controls(peerPath)
			request := GenerationCgroupCloseRequest{Path: targetPath, Generation: generation, OperationID: "member-close-" + scenario, Deadline: time.Now().Add(20 * time.Second).UTC()}
			original := m.leaseIdentities[targetPath]
			observations := []map[string]any{realMemberResourceObservation(original)}
			fault := &closeFaultStore{DbStore: db}
			m.db = fault
			if scenario == "completion-save-failed" {
				fault.failAt = 2
			}
			if scenario == "continuation-save-failed" {
				request.Deadline = time.Now().Add(-time.Minute).UTC()
				fault.failAt = 1
			}
			save(scenario+"-before.json", map[string]any{"observer": observer, "target": target, "peer": peer, "original": original, "request": request, "peer_controls": peerBefore, "pool_total": m.total, "logical_fixture_id": generation, "sandbox_id": nil, "cpu_memory_scope": "Whole container 0.5 CPU / 256 MiB; per-member limits and node budget not measured."})
			target.verify(t)
			peer.verify(t)
			require.Equal(t, strconv.Itoa(target.PID), strings.TrimSpace(controls(targetPath)["cgroup.procs"]), "no unowned member may enter the target")
			var proof *ClosedGenerationCgroup
			var continuation GenerationCgroupCloseRequest
			if scenario == "continuation-save-failed" {
				continuation = GenerationCgroupCloseRequest{Path: targetPath, Generation: generation, OperationID: "member-continuation", ExpectedRevision: 1, Deadline: time.Now().Add(20 * time.Second).UTC()}
				proof, err = m.ContinueCloseForGeneration(context.Background(), request, continuation)
				require.ErrorContains(t, err, "journal failure")
				require.Nil(t, proof)
				target.verify(t)
				peer.verify(t)
				require.True(t, m.usingID.Has(targetPath))
				require.Equal(t, 2, m.total)
				save(scenario+"-save-failure.json", map[string]any{"original_target_alive": true, "peer_alive": true, "pool_total": m.total, "signals_sent": false, "original_request": request, "continuation": continuation})
			} else {
				proof, err = m.CloseForGeneration(context.Background(), request)
				if scenario == "completion-save-failed" {
					require.ErrorContains(t, err, "journal failure")
					require.Nil(t, proof)
				} else {
					require.NoError(t, err)
					require.NotNil(t, proof.Directory)
					require.NoError(t, proof.Close())
				}
				save(scenario+"-target-exit.json", target.confirmExit(t))
			}
			peer.verify(t)
			observations = append(observations, realMemberResourceObservation(original))
			require.Equal(t, peerBefore, controls(peerPath))
			require.True(t, m.usingID.Has(targetPath))
			require.Equal(t, 2, m.total)
			require.Empty(t, m.idleID.List())
			pending, err := db.LoadRaw(config.CgroupBucket)
			require.NoError(t, err)
			save(scenario+"-before-reopen.json", json.RawMessage(pending))
			var state storedCgroupIDs
			require.NoError(t, json.Unmarshal(pending, &state))
			reopened := makeManager(db)
			reopened.total = len(state.Items)
			for _, active := range state.Items {
				reopened.usingID.Set(active, struct{}{})
				reopened.cgroups.Set(active, struct{}{})
			}
			require.NoError(t, reopened.restoreGenerationLeases(state))
			if scenario == "continuation-save-failed" {
				target.verify(t)
				peer.verify(t)
				proof, err = reopened.ContinueCloseForGeneration(context.Background(), request, continuation)
				require.NoError(t, err)
				require.NoError(t, proof.Close())
				save(scenario+"-target-exit.json", target.confirmExit(t))
			} else {
				proof, err = reopened.CloseForGeneration(context.Background(), request)
				require.NoError(t, err)
				require.Nil(t, proof.Directory)
				require.NotNil(t, proof.Parent)
				require.NoError(t, proof.Close())
			}
			peer.verify(t)
			require.Equal(t, peerBefore, controls(peerPath))
			require.True(t, reopened.usingID.Has(targetPath))
			require.Equal(t, 2, reopened.total)
			require.NoError(t, reopened.RecycleForGeneration(targetPath, generation))
			observations = append(observations, realMemberResourceObservation(original))
			require.Equal(t, 1, reopened.total)
			require.Empty(t, reopened.idleID.List())
			require.NoError(t, reopened.RecycleForGeneration(targetPath, generation))
			require.Equal(t, 1, reopened.total)
			peer.verify(t)
			peerRequest := GenerationCgroupCloseRequest{Path: peerPath, Generation: generation + "-peer", OperationID: "member-peer-cleanup-" + scenario, Deadline: time.Now().Add(20 * time.Second).UTC()}
			proof, err = reopened.CloseForGeneration(context.Background(), peerRequest)
			require.NoError(t, err)
			require.NoError(t, proof.Close())
			save(scenario+"-peer-exit.json", peer.confirmExit(t))
			require.NoError(t, reopened.RecycleForGeneration(peerPath, generation+"-peer"))
			require.Zero(t, reopened.total)
			require.Empty(t, reopened.usingID.Keys())
			require.Empty(t, reopened.idleID.List())
			settled, err := db.LoadRaw(config.CgroupBucket)
			require.NoError(t, err)
			save(scenario+"-settled.json", json.RawMessage(settled))
			save(scenario+"-resource-observations.json", observations)
			save(scenario+"-verdict.json", map[string]any{"original": original, "original_request": request, "continuation": continuation, "original_target_pidfd_exit": true, "peer_pidfd_exit_after_independent_cleanup": true, "peer_alive_and_controls_unchanged_during_target_retirement": true, "close_retained_lease": true, "separate_pool_settlement": true, "pool_total": 0, "using_count": 0, "idle_count": 0, "signals_sent": true, "native_runtime_tested": false, "daemon_restart_tested": false, "node_budget_tested": false, "source_scope": "Real process, cgroup v2, production directory close and original bbolt reopen; controlled OOM watcher."})
		})
	}
	require.NoError(t, os.Remove(filepath.Join("/sys/fs/cgroup", parent)))
	save("fixture-cleanup.json", map[string]any{"owned_parent_and_leaves_normally_removed": true, "force_used": false, "node_budget_tested": false})
}
