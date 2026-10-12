// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestKernelReadShutdownLosesReplyAfterCompleteRequest(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	client, server := &rpcClient{fd: pair[0]}, &rpcClient{fd: pair[1]}
	defer client.Close()
	defer server.Close()
	client.afterRequestSent = func(method string, fd int) error {
		require.Equal(t, contMgrRestore, method)
		return unix.Shutdown(fd, unix.SHUT_RD)
	}
	done := make(chan error, 1)
	go func() {
		var request clientCall
		files, err := server.unmarshal(&request)
		closeAll(files)
		if err == nil && request.Method != contMgrRestore {
			err = errors.New("wrong request received")
		}
		if err == nil {
			err = server.marshal(&callResult{Success: true}, nil)
			if errors.Is(err, unix.EPIPE) {
				err = nil // The actual kernel refused delivery to the shut reader.
			}
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.ErrorIs(t, callContext(ctx, client, contMgrRestore, new(string), nil), io.EOF)
	require.NoError(t, <-done)
}
