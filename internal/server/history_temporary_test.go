// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0
package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHistoryTemporaryOrphansRemovedAcrossRestartWithoutChangingAuthority(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		t.Run(fmt.Sprintf("fenced-%v", fenced), func(t *testing.T) {
			s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			r := testHistoryRequest(t, 7)
			_, err := s.StartOperation(context.Background(), r)
			require.NoError(t, err)
			if fenced {
				_, err = s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary()})
				require.NoError(t, err)
			}
			index := filepath.Join(s.config.RootDir, "scheduler-start-operations.index")
			fence := filepath.Join(s.config.RootDir, "scheduler-start-operations.history")
			before, err := os.ReadFile(index)
			require.NoError(t, err)
			var authority []byte
			if fenced {
				authority, err = os.ReadFile(fence)
				require.NoError(t, err)
			}
			for number := 0; number < 260; number++ {
				body := []byte("unpublished partial history bytes")
				if number%2 == 0 {
					body = nil
				}
				require.NoError(t, os.WriteFile(filepath.Join(s.config.RootDir, fmt.Sprintf(".history-%d", number)), body, 0600))
			}
			foreign := filepath.Join(s.config.RootDir, ".history-unrelated")
			require.NoError(t, os.WriteFile(foreign, []byte("unrelated"), 0600))
			for _, name := range []string{".history-001", ".history-4294967296"} {
				require.NoError(t, os.WriteFile(filepath.Join(s.config.RootDir, name), []byte("unrelated numeric name"), 0600))
			}
			s.closeStartOperationJournal()
			reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			reopened.config.RootDir = s.config.RootDir
			query := startOperationQuery(r)
			query.HistoryIdentity = r.HistoryIdentity
			_, err = reopened.GetStartOperation(context.Background(), query)
			require.NoError(t, err)
			for number := 0; number < 260; number++ {
				_, err = os.Lstat(filepath.Join(s.config.RootDir, fmt.Sprintf(".history-%d", number)))
				require.ErrorIs(t, err, os.ErrNotExist)
			}
			after, err := os.ReadFile(index)
			require.NoError(t, err)
			require.Equal(t, before, after)
			if fenced {
				after, err = os.ReadFile(fence)
				require.NoError(t, err)
				require.Equal(t, authority, after)
			}
			body, err := os.ReadFile(foreign)
			require.NoError(t, err)
			require.Equal(t, "unrelated", string(body))
			for _, name := range []string{".history-001", ".history-4294967296"} {
				body, err = os.ReadFile(filepath.Join(s.config.RootDir, name))
				require.NoError(t, err)
				require.Equal(t, "unrelated numeric name", string(body))
			}
		})
	}
}

func TestHistoryTemporaryUnsafeFileAndMissingAuthorityRemainUntouched(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public-mode", "setuid", "setgid", "sticky", "oversize", "missing-authority", "corrupt-authority"} {
		t.Run(kind, func(t *testing.T) {
			s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			_, err := s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary()})
			require.NoError(t, err)
			path := filepath.Join(s.config.RootDir, ".history-123")
			outside := filepath.Join(t.TempDir(), "preserved")
			require.NoError(t, os.WriteFile(outside, []byte("must remain"), 0600))
			switch kind {
			case "symlink":
				require.NoError(t, os.Symlink(outside, path))
			case "hardlink":
				require.NoError(t, os.Link(outside, path))
			case "public-mode":
				require.NoError(t, os.WriteFile(path, []byte("unpublished"), 0644))
			case "setuid", "setgid", "sticky":
				require.NoError(t, os.WriteFile(path, []byte("unpublished"), 0600))
				special := map[string]os.FileMode{"setuid": os.ModeSetuid, "setgid": os.ModeSetgid, "sticky": os.ModeSticky}[kind]
				require.NoError(t, os.Chmod(path, 0600|special))
			case "oversize":
				file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
				require.NoError(t, err)
				require.NoError(t, file.Truncate(historyStateLimit+1))
				require.NoError(t, file.Close())
			default:
				require.NoError(t, os.WriteFile(path, []byte("unpublished"), 0600))
			}
			fence := filepath.Join(s.config.RootDir, "scheduler-start-operations.history")
			if kind == "missing-authority" {
				require.NoError(t, os.Remove(fence))
			} else if kind == "corrupt-authority" {
				require.NoError(t, os.WriteFile(fence, []byte("broken"), 0600))
			}
			before, err := os.Lstat(path)
			require.NoError(t, err)
			s.closeStartOperationJournal()
			reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			reopened.config.RootDir = s.config.RootDir
			_, err = reopened.StartOperation(context.Background(), testHistoryRequest(t, 21))
			require.Equal(t, codes.Unavailable, status.Code(err))
			after, err := os.Lstat(path)
			require.NoError(t, err)
			require.True(t, os.SameFile(before, after))
			body, err := os.ReadFile(outside)
			require.NoError(t, err)
			require.Equal(t, "must remain", string(body))
		})
	}
}

func TestHistoryTemporaryCleanupRejectsReplacedParentOrLock(t *testing.T) {
	for _, replaced := range []string{"parent", "lock"} {
		t.Run(replaced, func(t *testing.T) {
			s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			r := testHistoryRequest(t, 7)
			_, err := s.StartOperation(context.Background(), r)
			require.NoError(t, err)
			_, err = s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary()})
			require.NoError(t, err)
			root := s.config.RootDir
			if replaced == "parent" {
				original := root + "-original"
				require.NoError(t, os.Rename(root, original))
				t.Cleanup(func() { require.NoError(t, os.RemoveAll(original)) })
				require.NoError(t, os.Mkdir(root, 0755))
				for _, name := range []string{"scheduler-start-operations", "scheduler-start-operations.index", "scheduler-start-operations.history"} {
					require.NoError(t, os.Rename(filepath.Join(original, name), filepath.Join(root, name)))
				}
			} else {
				lock := filepath.Join(root, "scheduler-start-operations/.lock")
				require.NoError(t, os.Rename(lock, lock+"-original"))
				require.NoError(t, os.WriteFile(lock, nil, 0600))
			}
			path := filepath.Join(root, ".history-123")
			require.NoError(t, os.WriteFile(path, []byte("must remain"), 0600))
			query := startOperationQuery(r)
			query.HistoryIdentity = r.HistoryIdentity
			_, err = s.GetStartOperation(context.Background(), query)
			require.Equal(t, codes.Unavailable, status.Code(err))
			body, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "must remain", string(body))
		})
	}
}

func TestHistoryTemporaryCleanupDoesNotRecreateMissingExistingLock(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := testHistoryRequest(t, 7)
	_, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	_, err = s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary()})
	require.NoError(t, err)
	s.closeStartOperationJournal()
	lock := filepath.Join(s.config.RootDir, "scheduler-start-operations/.lock")
	require.NoError(t, os.Remove(lock))
	path := filepath.Join(s.config.RootDir, ".history-123")
	require.NoError(t, os.WriteFile(path, []byte("must remain"), 0600))
	reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	reopened.config.RootDir = s.config.RootDir
	query := startOperationQuery(r)
	query.HistoryIdentity = r.HistoryIdentity
	_, err = reopened.GetStartOperation(context.Background(), query)
	require.Equal(t, codes.Unavailable, status.Code(err))
	_, err = os.Lstat(lock)
	require.ErrorIs(t, err, os.ErrNotExist)
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "must remain", string(body))
}
