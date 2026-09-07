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

package checkpointpublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrStateLayoutBusy = errors.New("publication state layout initialization is busy")

// StateLayout describes an explicitly initialized publication-state location.
// All consumers keep using StatePath; no per-process path override is needed.
type StateLayout struct {
	CheckpointRoot string `json:"checkpoint_root"`
	StateDirectory string `json:"state_directory"`
	Link           string `json:"link"`
}

type stateLayoutOwner struct {
	Version int    `json:"version"`
	Root    string `json:"root"`
}

// Publish states always end in .json; keep ownership outside that namespace.
const stateLayoutOwnerName = ".layout-owner"

// InitStateLayout configures a fresh checkpoint root without moving or replacing
// existing publication state. Both input directories must already exist.
func InitStateLayout(ctx context.Context, checkpointRoot, stateBase string) (*StateLayout, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := canonicalLayoutDirectory(checkpointRoot)
	if err != nil {
		return nil, err
	}
	base, err := canonicalLayoutDirectory(stateBase)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, base)
	if err != nil {
		return nil, err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return nil, errors.New("publication state base must be outside checkpoint root")
	}
	key := sha256.Sum256([]byte(root))
	target := filepath.Join(base, hex.EncodeToString(key[:]))
	layout := &StateLayout{CheckpointRoot: root, StateDirectory: target, Link: filepath.Join(root, StateDirName)}
	lock, err := os.OpenFile(target+".init.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrStateLayoutBusy
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	linked, err := layout.linked()
	if err != nil {
		return nil, err
	}
	want := stateLayoutOwner{Version: 1, Root: root}
	info, err := os.Lstat(target)
	switch {
	case err == nil:
		if !info.IsDir() {
			return nil, fmt.Errorf("state layout target is not a directory: %s", target)
		}
		raw, err := os.ReadFile(filepath.Join(target, stateLayoutOwnerName))
		if err != nil {
			return nil, fmt.Errorf("read state layout owner: %w", err)
		}
		var owner stateLayoutOwner
		if err := json.Unmarshal(raw, &owner); err != nil || owner != want {
			return nil, fmt.Errorf("state layout owner does not match checkpoint root: %s", target)
		}
		if !linked {
			entries, err := os.ReadDir(target)
			if err != nil {
				return nil, err
			}
			if len(entries) != 1 || entries[0].Name() != stateLayoutOwnerName {
				return nil, fmt.Errorf("state directory has existing data but no matching .publish link: %s", target)
			}
		}
	case os.IsNotExist(err):
		if linked {
			return nil, errors.New("configured publication state target disappeared")
		}
		if err := prepareStateLayoutTarget(base, target, want); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	// Also sync on retry: an earlier attempt may have stopped after rename.
	if err := syncStateLayoutDirectory(base); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !linked {
		if err := os.Symlink(target, layout.Link); err != nil {
			// A publisher may have created .publish, or another initializer using
			// a different state base may have won. Never replace either outcome.
			ok, checkErr := layout.linked()
			if checkErr != nil {
				return nil, checkErr
			}
			if !ok {
				return nil, fmt.Errorf("create publication state link: %w", err)
			}
		}
	}
	// Once visible, finish the durability operation even if ctx was cancelled.
	if err := syncStateLayoutDirectory(root); err != nil {
		return nil, err
	}
	return layout, nil
}

func canonicalLayoutDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.New("state layout directory must be specified")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", canonical)
	}
	return canonical, nil
}

func (layout *StateLayout) linked() (bool, error) {
	info, err := os.Lstat(layout.Link)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, fmt.Errorf("refuse existing publication state directory: %s", layout.Link)
	}
	resolved, err := filepath.EvalSymlinks(layout.Link)
	if err != nil {
		return false, fmt.Errorf("resolve existing publication state link: %w", err)
	}
	if resolved != layout.StateDirectory {
		return false, fmt.Errorf("publication state link points to a different directory: %s", resolved)
	}
	return true, nil
}

func prepareStateLayoutTarget(base, target string, owner stateLayoutOwner) error {
	stage, err := os.MkdirTemp(base, ".state-layout-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()
	raw, err := json.Marshal(owner)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(stage, stateLayoutOwnerName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(raw, '\n'))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := syncStateLayoutDirectory(stage); err != nil {
		return err
	}
	// Do not overwrite even an empty target created by a noncooperating actor.
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("commit publication state directory: %w", err)
	}
	committed = true
	return nil
}

func syncStateLayoutDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
