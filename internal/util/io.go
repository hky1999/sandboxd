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

package util

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Os returns the singleton instance of IoUtil.
// It is thread-safe.

var ioUtil IoUtil
var ioUtilOnce sync.Once

func Os() IoUtil {
	ioUtilOnce.Do(func() {
		if os.Getenv("TEST_UT") == "true" {
			ioUtil = &MockIoUtil{
				SuccessMap: map[string]bool{
					"success": true,
				},
			}
		} else {
			ioUtil = &EmbedIoUtil{}
		}
	})
	return ioUtil
}

type IoUtil interface {
	WriteFile(filename string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
}

type EmbedIoUtil struct{}

func (e *EmbedIoUtil) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return AtomicWriteFile(filename, data, perm)
}

func AtomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(filename), ".tmp-"+filepath.Base(filename))
	if err != nil {
		return err
	}
	// Remove abandoned temporary files on failures before publication.
	defer os.Remove(f.Name())
	if err := os.Chmod(f.Name(), perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filename); err != nil {
		return err
	}
	// A successful rename alone does not make its directory entry durable.
	// An error here means publication may have happened; callers must retain
	// the operation as unresolved rather than assuming the old file remains.
	return SyncDirectory(filepath.Dir(filename))
}

// SyncDirectory persists directory entries, propagating unsupported/error cases.
func SyncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return errors.Join(err, f.Close())
	}
	if !info.IsDir() {
		return errors.Join(errors.New("sync target is not a directory"), f.Close())
	}
	return errors.Join(f.Sync(), f.Close())
}

func (e *EmbedIoUtil) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (e *EmbedIoUtil) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

type MockIoUtil struct {
	SuccessMap map[string]bool
}

func (m *MockIoUtil) WriteFile(filename string, data []byte, perm os.FileMode) error {
	if m.SuccessMap == nil {
		return os.ErrNotExist
	}
	for key, success := range m.SuccessMap {
		if strings.Contains(string(data), key) && success {
			return nil
		}
	}
	return errors.New("mock error")
}

func (m *MockIoUtil) MkdirAll(path string, perm os.FileMode) error {
	return nil
}

func (m *MockIoUtil) Stat(name string) (os.FileInfo, error) {
	return nil, nil
}
