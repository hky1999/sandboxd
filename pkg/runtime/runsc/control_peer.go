// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type nativeServingProcess struct {
	birth              *nativeRuntimeBirth
	pidfd              int
	proc               *os.File
	executable         *os.File
	executableIdentity unix.Stat_t
}

func boundedPeerFile(ctx context.Context, dir *os.File, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("original control process input exceeds its limit or is unreadable")
	}
	return data, ctx.Err()
}

func verifyPeerScope(ctx context.Context, birth *nativeRuntimeBirth) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(boot) > 128 || strings.TrimSpace(string(boot)) != birth.Scope.BootID {
		return errors.New("original control process boot differs")
	}
	var namespace unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/pid", &namespace); err != nil || uint64(namespace.Dev) != birth.Scope.PIDNamespaceDevice || namespace.Ino != birth.Scope.PIDNamespaceInode {
		return errors.New("original control process observer namespace differs")
	}
	self, err := os.Open("/proc/self")
	if err != nil {
		return err
	}
	defer self.Close()
	data, err := boundedPeerFile(ctx, self, "stat", 65536)
	if err != nil {
		return err
	}
	_, err = peerStartTicks(data, os.Getpid())
	return err
}

func peerStartTicks(data []byte, pid int) (uint64, error) {
	text := string(data)
	first, last := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if first <= 0 || last <= first {
		return 0, errors.New("control process stat is malformed")
	}
	actual, err := strconv.Atoi(strings.TrimSpace(text[:first]))
	fields := strings.Fields(text[last+1:])
	if err != nil || actual != pid || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0, errors.New("original control process is absent, exited or belongs to another PID")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, errors.New("original control process start time is invalid")
	}
	return ticks, nil
}

func (p *nativeServingProcess) close() {
	if p.executable != nil {
		_ = p.executable.Close()
	}
	if p.proc != nil {
		_ = p.proc.Close()
	}
	if p.pidfd >= 0 {
		_ = unix.Close(p.pidfd)
		p.pidfd = -1
	}
}

func (p *nativeServingProcess) live(ctx context.Context) error {
	if p.pidfd < 0 || p.proc == nil || p.executable == nil {
		return errors.New("original serving process handle is unavailable")
	}
	if err := verifyPeerScope(ctx, p.birth); err != nil {
		return err
	}
	fds := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	_, err := unix.Poll(fds, 0)
	if err != nil {
		return err
	}
	if fds[0].Revents != 0 {
		return errors.New("original serving process handle is exited or invalid")
	}
	data, err := boundedPeerFile(ctx, p.proc, "stat", 65536)
	if err != nil {
		return err
	}
	start, err := peerStartTicks(data, p.birth.PID)
	if err != nil || start != p.birth.StartTicks {
		return errors.New("original serving process PID was reused or changed")
	}
	fd, err := unix.Openat(int(p.proc.Fd()), "exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var current unix.Stat_t
	err = unix.Fstat(fd, &current)
	_ = unix.Close(fd)
	if err != nil || !sameRuntimeInventoryStat(p.executableIdentity, current) {
		return errors.New("original serving executable changed")
	}
	for name, digest := range map[string]string{"cmdline": p.birth.ArgumentsSHA256, "cgroup": p.birth.CgroupSHA256} {
		data, err := boundedPeerFile(ctx, p.proc, name, 65536)
		if err != nil || len(data) == 0 {
			return errors.New("original serving process fingerprint is unreadable")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			return errors.New("original serving arguments or cgroup differs")
		}
	}
	return ctx.Err()
}

func openNativeServingProcess(ctx context.Context, birth *nativeRuntimeBirth, id, generation string) (*nativeServingProcess, error) {
	if birth == nil {
		return nil, errors.New("original serving process birth is missing")
	}
	if err := birth.validate(id, generation, "sentry", birth.PID); err != nil {
		return nil, err
	}
	if err := verifyPeerScope(ctx, birth); err != nil {
		return nil, err
	}
	p := &nativeServingProcess{birth: birth, pidfd: -1}
	complete := false
	defer func() {
		if !complete {
			p.close()
		}
	}()
	fd, err := unix.PidfdOpen(birth.PID, 0)
	if err != nil {
		return nil, fmt.Errorf("open original control process pidfd: %w", err)
	}
	p.pidfd = fd
	fd, err = unix.Open("/proc/"+strconv.Itoa(birth.PID), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	p.proc = os.NewFile(uintptr(fd), "original control proc directory")
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil || filesystem.Type != unix.PROC_SUPER_MAGIC {
		return nil, errors.New("original control process source is not procfs")
	}
	fd, err = unix.Openat(int(p.proc.Fd()), "exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	p.executable = os.NewFile(uintptr(fd), "original serving executable")
	if err := unix.Fstat(fd, &p.executableIdentity); err != nil || p.executableIdentity.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("original serving executable is not regular")
	}
	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	reader := io.LimitReader(p.executable, (256<<20)+1)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if total <= 0 || total > 256<<20 || hex.EncodeToString(hash.Sum(nil)) != birth.ExecutableSHA256 {
		return nil, errors.New("actual original serving executable SHA256 differs")
	}
	if err := p.live(ctx); err != nil {
		return nil, err
	}
	complete = true
	return p, nil
}

func (g *runtimeStateTransition) authenticate(ctx context.Context, conn controlRPC, state *containerState, args StartArgs) error {
	if args.ResourceGeneration == "" {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p, err := openNativeServingProcess(bounded, state.Sandbox.ProcessBirth, args.ID, args.ResourceGeneration)
	if err != nil {
		return err
	}
	g.serving = p
	rpc, ok := conn.(*rpcClient)
	if !ok {
		return errors.New("managed control transport has no kernel sender credential verification")
	}
	if err := rpc.requireSender(p.birth.PID, func() error { return p.live(ctx) }); err != nil {
		return err
	}
	var result any
	if err := callContext(bounded, rpc, "containerManager.Processes", &args.ID, &result); err != nil {
		return fmt.Errorf("original serving process readonly proof failed: %w", err)
	}
	if err := g.check(ctx); err != nil {
		return err
	}
	if g.client.controlPeerObserved != nil {
		rpc.mu.Lock()
		connectionPeer, err := unix.GetsockoptUcred(rpc.fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		sender, frames := rpc.verifiedSenderPID, rpc.verifiedFrames
		rpc.mu.Unlock()
		if err != nil {
			return err
		}
		g.client.controlPeerObserved(map[string]any{
			"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration,
			"serving_pid": p.birth.PID, "serving_start_ticks": p.birth.StartTicks,
			"executable_sha256": p.birth.ExecutableSHA256, "arguments_sha256": p.birth.ArgumentsSHA256, "cgroup_sha256": p.birth.CgroupSHA256,
			"observer_scope": p.birth.Scope, "connection_peer_pid": connectionPeer.Pid,
			"verified_kernel_sender_pid": sender, "verified_response_frames": frames,
			"read_only_method": "containerManager.Processes", "verified_before_tap_open": true,
		})
	}
	return nil
}
