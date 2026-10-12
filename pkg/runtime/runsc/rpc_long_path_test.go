// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestControlRPCConnectsOriginalSocketInLongPrivateDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), strings.Repeat("socket-directory-", 8))
	require.NoError(t, os.Mkdir(directory, 0700))
	root, err := os.Open(directory)
	require.NoError(t, err)
	defer root.Close()
	listener, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(listener)
	name := "original.sock"
	require.NoError(t, unix.Bind(listener, &unix.SockaddrUnix{Name: fmt.Sprintf("/proc/self/fd/%d/%s", root.Fd(), name)}))
	require.NoError(t, unix.Listen(listener, 1))
	path := filepath.Join(directory, name)
	require.GreaterOrEqual(t, len(path), len(unix.RawSockaddrUnix{}.Path))
	client, err := connectRPC(path)
	require.NoError(t, err)
	defer client.Close()
	peer, err := unix.GetsockoptUcred(client.fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	require.NoError(t, err)
	require.EqualValues(t, os.Getpid(), peer.Pid)
}

func TestControlRPCLongPathRejectsSymlinkAndNonSocketEndpoint(t *testing.T) {
	directory := filepath.Join(t.TempDir(), strings.Repeat("socket-directory-", 8))
	require.NoError(t, os.Mkdir(directory, 0700))
	regular := filepath.Join(directory, "regular")
	require.NoError(t, os.WriteFile(regular, nil, 0600))
	_, err := connectRPC(regular)
	require.ErrorContains(t, err, "not the original directory's socket")
	link := filepath.Join(directory, "alias")
	require.NoError(t, os.Symlink(regular, link))
	_, err = connectRPC(link)
	require.ErrorContains(t, err, "not the original directory's socket")
}
