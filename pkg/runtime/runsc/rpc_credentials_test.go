// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNativeRPCTransportAcceptsKernelSenderCredentials(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	client, server := &rpcClient{fd: pair[0]}, &rpcClient{fd: pair[1]}
	defer client.Close()
	defer server.Close()
	require.NoError(t, unix.SetsockoptInt(client.fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1))
	done := make(chan error, 1)
	go func() {
		var request clientCall
		files, err := server.unmarshal(&request)
		closeAll(files)
		if err == nil {
			err = server.marshal(&callResult{Success: true, Result: []any{}}, nil)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var result json.RawMessage
	require.NoError(t, callContext(ctx, client, "containerManager.Processes", new(string), &result))
	require.NoError(t, <-done)
	require.JSONEq(t, "[]", string(result))
}

// This helper is an ordinary test process, not a runtime or a sandbox. It
// inherits a socket whose SO_PEERCRED still names its parent initializer.
func TestNativeCredentialReplyHelper(t *testing.T) {
	mode := os.Getenv("NATIVE_CREDENTIAL_REPLY_HELPER")
	if mode == "" {
		t.Skip("subprocess helper only")
	}
	server := &rpcClient{fd: 3}
	defer server.Close()
	if mode == "tail" {
		ready := os.NewFile(4, "parent response gate")
		defer ready.Close()
		var signal [1]byte
		_, err := ready.Read(signal[:])
		require.NoError(t, err)
		_, err = unix.SendmsgN(3, []byte(`"success":true,"result":[]}`), nil, nil, 0)
		require.NoError(t, err)
	} else {
		var request clientCall
		files, err := server.unmarshal(&request)
		closeAll(files)
		require.NoError(t, err)
		require.Equal(t, "containerManager.Processes", request.Method)
		require.NoError(t, server.marshal(&callResult{Success: true, Result: []any{}}, nil))
	}
	// Remain alive until the parent has checked the original pidfd and closes.
	var signal [1]byte
	n, err := unix.Read(3, signal[:])
	if err != nil {
		require.ErrorIs(t, err, unix.ECONNRESET)
	} else {
		require.Zero(t, n, "the parent must not send a mutable request after this proof")
	}
}

func credentialHelper(t *testing.T, mode string, serverFD int, gate *os.File) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe, "-test.run=^TestNativeCredentialReplyHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "NATIVE_CREDENTIAL_REPLY_HELPER="+mode)
	output := new(bytes.Buffer)
	cmd.Stdout, cmd.Stderr = output, output
	fd := os.NewFile(uintptr(serverFD), "inherited original test socket")
	cmd.ExtraFiles = []*os.File{fd}
	if gate != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, gate)
	}
	require.NoError(t, cmd.Start())
	require.NoError(t, fd.Close())
	return cmd
}

func TestNativeCredentialsIdentifyInheritedSocketSenderInsteadOfInitializer(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	client := &rpcClient{fd: pair[0]}
	defer client.Close()
	parent, err := unix.GetsockoptUcred(client.fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	require.NoError(t, err)
	require.EqualValues(t, os.Getpid(), parent.Pid)
	cmd := credentialHelper(t, "whole", pair[1], nil)
	defer func() { _ = client.Close(); require.NoError(t, cmd.Wait()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, client.requireSender(cmd.Process.Pid, func() error { return nil }))
	var result json.RawMessage
	require.NoError(t, callContext(ctx, client, "containerManager.Processes", new(string), &result))
	require.JSONEq(t, "[]", string(result))
}

func TestNativeCredentialsRejectWrongProcessBeforeMutableRequests(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	client := &rpcClient{fd: pair[0]}
	defer client.Close()
	cmd := credentialHelper(t, "whole", pair[1], nil)
	defer func() { _ = client.Close(); require.NoError(t, cmd.Wait()) }()
	require.NoError(t, client.requireSender(os.Getpid(), func() error { return nil }))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var result json.RawMessage
	err = callContext(ctx, client, "containerManager.Processes", new(string), &result)
	require.ErrorContains(t, err, "not from the original serving process")
	require.Empty(t, result)
}

func TestNativeCredentialsRejectDifferentProcessInResponseTail(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	client := &rpcClient{fd: pair[0]}
	defer client.Close()
	serverFD, err := unix.Dup(pair[1])
	require.NoError(t, err)
	server := &rpcClient{fd: serverFD}
	defer server.Close()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer reader.Close()
	defer writer.Close()
	cmd := credentialHelper(t, "tail", pair[1], reader)
	defer func() { _ = client.Close(); _ = server.Close(); _ = writer.Close(); require.NoError(t, cmd.Wait()) }()
	done := make(chan error, 1)
	go func() {
		var request clientCall
		files, err := server.unmarshal(&request)
		closeAll(files)
		if err == nil {
			_, err = unix.SendmsgN(server.fd, []byte("{"), nil, nil, 0)
		}
		if err == nil {
			_, err = writer.Write([]byte("send"))
		}
		done <- err
	}()
	require.NoError(t, client.requireSender(os.Getpid(), func() error { return nil }))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var result json.RawMessage
	err = callContext(ctx, client, "containerManager.Processes", new(string), &result)
	require.ErrorContains(t, err, "not from the original serving process")
	require.NoError(t, <-done)
}
