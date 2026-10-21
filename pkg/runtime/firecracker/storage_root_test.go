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

package firecracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/stretchr/testify/require"
)

func TestSelectFirecrackerPrivateStorageRoot(t *testing.T) {
	tests := []struct {
		name     string
		override string
		want     string
		wantErr  bool
	}{
		{name: "legacy hidden child", want: "/shared/filestore/.firecracker"},
		{name: "explicit legacy", override: "/shared/filestore/.firecracker", want: "/shared/filestore/.firecracker"},
		{name: "separate local storage", override: "/local/fc", want: "/local/fc"},
		{name: "clean explicit path", override: "/local/fc/../private", want: "/local/private"},
		{name: "same name prefix is separate", override: "/shared/filestore-other", want: "/shared/filestore-other"},
		{name: "relative", override: "local/fc", wantErr: true},
		{name: "whitespace is not default", override: "  ", wantErr: true},
		{name: "root", override: "/", wantErr: true},
		{name: "root after cleaning", override: "/local/..", wantErr: true},
		{name: "embedded NUL", override: "/local/\x00fc", wantErr: true},
		{name: "global filestore", override: "/shared/filestore", wantErr: true},
		{name: "global ancestor", override: "/shared", wantErr: true},
		{name: "unmanaged child of global", override: "/shared/filestore/not-a-volume", wantErr: true},
		{name: "sandbox root", override: "/state/containers", wantErr: true},
		{name: "sandbox child", override: "/state/containers/private", wantErr: true},
		{name: "sandbox ancestor", override: "/state", wantErr: true},
		{name: "runtime root", override: "/runtime/fc", wantErr: true},
		{name: "runtime child", override: "/runtime/fc/private", wantErr: true},
		{name: "runtime ancestor", override: "/runtime", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, err := selectFirecrackerPrivateStorageRoot("/shared/filestore", test.override, "/state/containers", "/runtime/fc")
			if test.wantErr {
				require.Error(t, err)
				require.Empty(t, root)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, root)
		})
	}
}

func TestValidateFirecrackerPrivateStorageLocation(t *testing.T) {
	t.Run("absent sandbox root", func(t *testing.T) {
		require.NoError(t, validateFirecrackerPrivateStorageLocation(filepath.Join(t.TempDir(), "missing"), "/local/fc"))
	})
	tests := []struct {
		name    string
		stateID string
		overlay string
		shared  string
		corrupt bool
		missing bool
		wantErr bool
	}{
		{name: "matching disk", stateID: "sbox-storage", overlay: "matching"},
		{name: "matching virtio-fs", stateID: "sbox-storage", overlay: "matching", shared: "matching"},
		{name: "different disk root", stateID: "sbox-storage", overlay: "/old/overlay.ext4", wantErr: true},
		{name: "different virtio-fs root", stateID: "sbox-storage", overlay: "matching", shared: "/old/shared", wantErr: true},
		{name: "different sandbox identity", stateID: "sbox-other", overlay: "matching", wantErr: true},
		{name: "corrupt identity", corrupt: true, wantErr: true},
		{name: "non-FC sandbox", missing: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sandboxes := t.TempDir()
			storage := filepath.Join(t.TempDir(), "private")
			stateDir := filepath.Join(sandboxes, "sbox-storage", firecrackerArtifactsDir)
			require.NoError(t, os.MkdirAll(stateDir, 0700))
			if !test.missing {
				overlay := test.overlay
				if overlay == "matching" {
					overlay = filepath.Join(storage, "sbox-storage", "overlay.ext4")
				}
				state := firecrackerPersistedState{ID: test.stateID, OverlayPath: overlay}
				if test.shared != "" {
					shared := test.shared
					if shared == "matching" {
						shared = filepath.Join(storage, "sbox-storage", firecrackerVirtioFSSharedDir)
					}
					state.VirtioFS = &firecrackerVirtioFSState{SharedDir: shared}
				}
				body, err := json.Marshal(state)
				require.NoError(t, err)
				if test.corrupt {
					body = []byte("{invalid")
				}
				require.NoError(t, os.WriteFile(filepath.Join(stateDir, firecrackerStateFilename), body, 0600))
			}
			err := validateFirecrackerPrivateStorageLocation(sandboxes, storage)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			_, statErr := os.Stat(storage)
			require.True(t, os.IsNotExist(statErr), "validation must not create or migrate storage")
		})
	}
}

func TestFirecrackerStorageDirConfiguration(t *testing.T) {
	var value config.FirecrackerConfig
	require.NoError(t, json.Unmarshal([]byte(`{"storageDir":"/local/fc"}`), &value))
	require.Equal(t, "/local/fc", value.StorageDir)
	field, found := reflect.TypeOf(value).FieldByName("StorageDir")
	require.True(t, found)
	require.Equal(t, "storage_dir", field.Tag.Get("toml"))
}
