// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

const maxFiles = 128

type remoteError struct {
	Message string
}

func (r remoteError) Error() string {
	return r.Message
}

type filePayload struct {
	Files []*os.File `json:"-"`
}

func (f *filePayload) filePayload() []*os.File {
	return f.Files
}

func (f *filePayload) setFilePayload(fs []*os.File) {
	f.Files = fs
}

type filePayloader interface {
	filePayload() []*os.File
	setFilePayload([]*os.File)
}

type clientCall struct {
	Method string `json:"method"`
	Arg    any    `json:"arg"`
}

type callResult struct {
	Success bool   `json:"success"`
	Err     string `json:"err"`
	Result  any    `json:"result"`
}

type rpcClient struct {
	mu                sync.Mutex
	fd                int
	expectedSenderPID int
	verifySender      func() error
	verifiedSenderPID int
	verifiedFrames    uint64
	// Private fault boundary for isolated tests. Normal transports leave it nil.
	afterRequestSent func(string, int) error
}

func (c *rpcClient) requireSender(pid int, verify func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if pid <= 0 || verify == nil {
		return fmt.Errorf("original control sender proof is incomplete")
	}
	if err := unix.SetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return err
	}
	c.expectedSenderPID, c.verifySender = pid, verify
	return nil
}

func connectRPC(path string) (*rpcClient, error) {
	address := path
	var directory *os.File
	var originalDirectory, originalSocket unix.Stat_t
	if len(path) >= len(unix.RawSockaddrUnix{}.Path) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("long control socket path is not an exact absolute path")
		}
		var err error
		directory, originalDirectory, err = openRuntimeIdentityDirectory(filepath.Dir(path))
		if err != nil {
			return nil, fmt.Errorf("open original long control socket directory: %w", err)
		}
		defer directory.Close()
		if err := unix.Fstatat(int(directory.Fd()), filepath.Base(path), &originalSocket, unix.AT_SYMLINK_NOFOLLOW); err != nil || originalSocket.Mode&unix.S_IFMT != unix.S_IFSOCK {
			return nil, fmt.Errorf("long control endpoint is not the original directory's socket")
		}
		if err := verifyRuntimeIdentityDirectory(filepath.Dir(path), originalDirectory); err != nil {
			return nil, err
		}
		address = fmt.Sprintf("/proc/self/fd/%d/%s", directory.Fd(), filepath.Base(path))
		if len(address) >= len(unix.RawSockaddrUnix{}.Path) {
			return nil, fmt.Errorf("control socket basename exceeds the Unix address limit")
		}
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: address}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if directory != nil {
		var current unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Dev != originalSocket.Dev || current.Ino != originalSocket.Ino || current.Mode != originalSocket.Mode {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("long control socket changed while connecting")
		}
		if err := verifyRuntimeIdentityDirectory(filepath.Dir(path), originalDirectory); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	}
	return &rpcClient{fd: fd}, nil
}

func (c *rpcClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

// Interrupt unblocks an in-flight Call without waiting for Call's serialization
// mutex. The caller still owns Close, which releases the descriptor after the
// blocked syscall has returned.
func (c *rpcClient) Interrupt() error {
	if c.fd < 0 {
		return nil
	}
	err := unix.Shutdown(c.fd, unix.SHUT_RDWR)
	if err == unix.ENOTCONN || err == unix.EINVAL {
		return nil
	}
	return err
}

func (c *rpcClient) Call(method string, arg any, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var files []*os.File
	if fp, ok := arg.(filePayloader); ok {
		files = fp.filePayload()
		if len(files) > maxFiles {
			return fmt.Errorf("too many file descriptors: %d > %d", len(files), maxFiles)
		}
	}

	if err := c.marshal(&clientCall{Method: method, Arg: arg}, files); err != nil {
		return err
	}
	if c.afterRequestSent != nil {
		if err := c.afterRequestSent(method, c.fd); err != nil {
			return err
		}
	}

	callR := callResult{Result: result}
	newFiles, err := c.unmarshal(&callR)
	if err != nil {
		return fmt.Errorf("urpc method %q failed: %w", method, err)
	}
	if fp, ok := result.(filePayloader); ok {
		fp.setFilePayload(newFiles)
	} else {
		closeAll(newFiles)
	}
	if !callR.Success {
		return remoteError{Message: callR.Err}
	}
	return nil
}

func (c *rpcClient) marshal(v any, files []*os.File) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	var oob []byte
	if len(files) > 0 {
		fds := make([]int, 0, len(files))
		for _, f := range files {
			fds = append(fds, int(f.Fd()))
		}
		oob = unix.UnixRights(fds...)
	}

	n, err := unix.SendmsgN(c.fd, data, oob, nil, 0)
	runtime.KeepAlive(files)
	if err != nil {
		return err
	}
	for n < len(data) {
		written, err := unix.SendmsgN(c.fd, data[n:], nil, nil, 0)
		if err != nil {
			return err
		}
		if written == 0 {
			return fmt.Errorf("short urpc write: wrote %d of %d bytes", n, len(data))
		}
		n += written
	}
	return nil
}

func (c *rpcClient) unmarshal(v any) ([]*os.File, error) {
	firstByte := make([]byte, 1)
	n, files, err := c.receiveFrame(firstByte)
	if err != nil {
		return nil, err
	}
	reader := &rpcReplyReader{client: c, received: n}
	decoder := json.NewDecoder(io.MultiReader(bytes.NewReader(firstByte[:n]), reader))
	decoder.UseNumber()
	if err := decoder.Decode(v); err != nil {
		closeAll(files)
		return nil, err
	}
	return files, nil
}

// Credentials are received on every stream read. Checking just the first byte
// would let a different process append the rest of an inherited connection.
func (c *rpcClient) receiveFrame(data []byte) (int, []*os.File, error) {
	oob := make([]byte, unix.CmsgSpace(maxFiles*4)+unix.CmsgSpace(unix.SizeofUcred))
	n, oobn, flags, _, err := unix.Recvmsg(c.fd, data, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return 0, nil, err
	}
	if n == 0 {
		return 0, nil, io.EOF
	}
	files, credentials, err := parseControlData(oob[:oobn])
	if err == nil && flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		err = fmt.Errorf("control response ancillary data was truncated")
	}
	if err == nil && c.expectedSenderPID != 0 {
		if credentials == nil || int(credentials.Pid) != c.expectedSenderPID {
			err = fmt.Errorf("control response is not from the original serving process")
		} else {
			err = c.verifySender()
			if err == nil {
				c.verifiedSenderPID = int(credentials.Pid)
				c.verifiedFrames++
			}
		}
	}
	if err != nil {
		closeAll(files)
		return 0, nil, err
	}
	return n, files, nil
}

type rpcReplyReader struct {
	client   *rpcClient
	received int
}

func (r *rpcReplyReader) Read(data []byte) (int, error) {
	if r.received >= runtimeStateBytes {
		return 0, fmt.Errorf("control response exceeds its byte limit")
	}
	if len(data) > runtimeStateBytes-r.received {
		data = data[:runtimeStateBytes-r.received]
	}
	n, files, err := r.client.receiveFrame(data)
	if len(files) != 0 {
		closeAll(files)
		return 0, fmt.Errorf("control response donated descriptors after its first byte")
	}
	r.received += n
	return n, err
}

type fdReader struct {
	fd int
}

func (r fdReader) Read(p []byte) (int, error) {
	n, err := unix.Read(r.fd, p)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}

func parseFiles(oob []byte) ([]*os.File, error) {
	files, _, err := parseControlData(oob)
	return files, err
}

func parseControlData(oob []byte) ([]*os.File, *unix.Ucred, error) {
	if len(oob) == 0 {
		return nil, nil, nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, nil, err
	}
	var files []*os.File
	var credentials *unix.Ucred
	var invalid error
	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SCM_CREDENTIALS {
			var err error
			if credentials != nil {
				invalid = fmt.Errorf("duplicate control sender credentials")
				continue
			}
			credentials, err = unix.ParseUnixCredentials(&msg)
			if err != nil {
				invalid = err
			}
			continue
		}
		fds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			invalid = err
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "runsc-urpc-fd"))
		}
	}
	if invalid != nil {
		closeAll(files)
		return nil, nil, invalid
	}
	return files, credentials, nil
}

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
