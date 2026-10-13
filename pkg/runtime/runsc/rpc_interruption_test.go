// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func interruptionTestPair(t *testing.T) (*rpcClient, *rpcClient) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	client, server := &rpcClient{fd: pair[0]}, &rpcClient{fd: pair[1]}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func TestRPCInterruptedReceivePreservesRequestAndSender(t *testing.T) {
	client, server := interruptionTestPair(t)
	require.NoError(t, client.requireSender(os.Getpid(), func() error { return nil }))
	receives, sends := 0, 0
	client.recvmsg = func(fd int, data, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
		receives++
		if receives == 1 || receives == 3 {
			return -1, 0, 0, nil, unix.EINTR
		}
		return unix.Recvmsg(fd, data, oob, flags)
	}
	client.sendmsgN = func(fd int, data, oob []byte, to unix.Sockaddr, flags int) (int, error) {
		sends++
		return unix.SendmsgN(fd, data, oob, to, flags)
	}
	done := make(chan error, 1)
	go func() {
		var request clientCall
		files, err := server.unmarshal(&request)
		closeAll(files)
		if err == nil && request.Method != contMgrSetNetworkArgs {
			err = errors.New("different mutation received")
		}
		if err == nil {
			err = server.marshal(&callResult{Success: true, Result: []int{7}}, nil)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var result []int
	err := callContext(ctx, client, contMgrSetNetworkArgs, new(string), &result)
	if err != nil {
		_ = client.Interrupt()
		_ = server.Interrupt()
	}
	serverErr := <-done
	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.Equal(t, []int{7}, result)
	require.Equal(t, 1, sends, "an interrupted reply must never replay the mutation")
	require.GreaterOrEqual(t, receives, 4)
	require.Equal(t, os.Getpid(), client.verifiedSenderPID)
	require.GreaterOrEqual(t, client.verifiedFrames, uint64(2))
}

func TestRPCInterruptedPartialSendTransfersDescriptorOnce(t *testing.T) {
	client, server := interruptionTestPair(t)
	file, err := os.CreateTemp(t.TempDir(), "original-descriptor")
	require.NoError(t, err)
	defer file.Close()
	_, err = file.WriteString("original payload")
	require.NoError(t, err)
	calls, successfulRights := 0, 0
	client.sendmsgN = func(fd int, data, oob []byte, to unix.Sockaddr, flags int) (int, error) {
		calls++
		if calls == 1 || calls == 3 {
			return -1, unix.EINTR
		}
		if calls == 2 {
			data = data[:1]
		}
		n, err := unix.SendmsgN(fd, data, oob, to, flags)
		if err == nil && n > 0 && len(oob) > 0 {
			successfulRights++
		}
		return n, err
	}
	done := make(chan error, 1)
	go func() {
		var request clientCall
		files, err := server.unmarshal(&request)
		defer closeAll(files)
		if err == nil && (request.Method != contMgrRestore || len(files) != 1) {
			err = errors.New("request or descriptor count changed")
		}
		if err == nil {
			data := make([]byte, 16)
			n, readErr := files[0].ReadAt(data, 0)
			if string(data[:n]) != "original payload" {
				err = errors.New("descriptor payload changed")
			} else if readErr != nil && n != len("original payload") {
				err = readErr
			}
		}
		if err == nil {
			err = server.marshal(&callResult{Success: true}, nil)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = callContext(ctx, client, contMgrRestore, &filePayload{Files: []*os.File{file}}, nil)
	if err != nil {
		_ = client.Interrupt()
		_ = server.Interrupt()
	}
	serverErr := <-done
	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.Equal(t, 4, calls)
	require.Equal(t, 1, successfulRights)
}

func TestRPCInterruptedReceiveStillHonorsCancellation(t *testing.T) {
	client, server := interruptionTestPair(t)
	first := true
	client.recvmsg = func(fd int, data, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
		if first {
			first = false
			return -1, 0, 0, nil, unix.EINTR
		}
		return unix.Recvmsg(fd, data, oob, flags)
	}
	done := make(chan error, 1)
	go func() {
		var request clientCall
		files, err := server.unmarshal(&request)
		closeAll(files)
		done <- err // Deliberately withhold the reply on the original connection.
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := callContext(ctx, client, contMgrSetNetworkArgs, new(string), nil)
	require.NoError(t, <-done)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
}

func TestRPCReceiveFailureDoesNotRetryOrReplay(t *testing.T) {
	client, _ := interruptionTestPair(t)
	receives, sends := 0, 0
	client.recvmsg = func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error) {
		receives++
		return -1, 0, 0, nil, unix.ECONNRESET
	}
	client.sendmsgN = func(fd int, data, oob []byte, to unix.Sockaddr, flags int) (int, error) {
		sends++
		return unix.SendmsgN(fd, data, oob, to, flags)
	}
	require.ErrorIs(t, client.Call(contMgrRestore, new(string), new(json.RawMessage)), unix.ECONNRESET)
	require.Equal(t, 1, receives)
	require.Equal(t, 1, sends)
}
