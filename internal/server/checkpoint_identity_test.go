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

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func describeIdentityFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := []byte("sealed runtime state")
	sum := sha256.Sum256(content)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "checkpoint.img"), content, 0600))
	manifest, err := json.Marshal(map[string]any{
		"version": 2, "runtime": "runsc",
		"digests": map[string]string{"checkpoint.img": hex.EncodeToString(sum[:])},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0600))
	return dir
}

func TestDescribeCheckpointArtifactsUsesAdmissionRootWithoutWriting(t *testing.T) {
	dir := describeIdentityFixture(t)
	manifestPath := filepath.Join(dir, "manifest.json")
	before, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	beforeStat, err := os.Stat(dir)
	require.NoError(t, err)
	binding, err := checkpointroot.Bind(dir)
	require.NoError(t, err)
	response, err := (&sandboxService{}).DescribeCheckpointArtifacts(context.Background(),
		&runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: dir + "/."})
	require.NoError(t, err)
	require.Equal(t, dir, response.GetCheckpointDir())
	require.Equal(t, binding.RootDigest, response.GetExpectedRootDigest())
	require.Len(t, response.GetExpectedRootDigest(), checkpointroot.DigestHexLen)
	after, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
	afterStat, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, beforeStat.ModTime(), afterStat.ModTime())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2, "query must not create a lease, journal, or publication marker")
}

func TestDescribeCheckpointArtifactsBindsExactManifestView(t *testing.T) {
	dir := describeIdentityFixture(t)
	service := &sandboxService{}
	request := &runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: dir}
	first, err := service.DescribeCheckpointArtifacts(context.Background(), request)
	require.NoError(t, err)
	path := filepath.Join(dir, "manifest.json")
	manifest, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(manifest, '\n'), 0600))
	second, err := service.DescribeCheckpointArtifacts(context.Background(), request)
	require.NoError(t, err)
	require.NotEqual(t, first.GetExpectedRootDigest(), second.GetExpectedRootDigest(),
		"the root binds the exact sealed manifest bytes, not a Rust reconstruction")
}

func TestDescribeCheckpointArtifactsDoesNotValidatePayloadBytes(t *testing.T) {
	dir := describeIdentityFixture(t)
	service := &sandboxService{}
	request := &runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: dir}
	first, err := service.DescribeCheckpointArtifacts(context.Background(), request)
	require.NoError(t, err)
	// Corruption is deliberately NOT detected by metadata discovery. Runtime
	// restore must verify the actual opened payload; this RPC must not prefetch
	// gigabytes of guest memory merely to supply an admission pin.
	file, err := os.OpenFile(filepath.Join(dir, "checkpoint.img"), os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = file.WriteAt([]byte("CORRUPTED"), 0)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	second, err := service.DescribeCheckpointArtifacts(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, first.GetExpectedRootDigest(), second.GetExpectedRootDigest())
}

func TestDescribeCheckpointArtifactsRejectsInvalidDirectories(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func(*testing.T) *runtime.DescribeCheckpointArtifactsRequest
		code    codes.Code
	}{
		{"nil", func(*testing.T) *runtime.DescribeCheckpointArtifactsRequest { return nil }, codes.InvalidArgument},
		{"empty", func(*testing.T) *runtime.DescribeCheckpointArtifactsRequest {
			return &runtime.DescribeCheckpointArtifactsRequest{}
		}, codes.InvalidArgument},
		{"relative", func(*testing.T) *runtime.DescribeCheckpointArtifactsRequest {
			return &runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: "relative"}
		}, codes.InvalidArgument},
		{"root", func(*testing.T) *runtime.DescribeCheckpointArtifactsRequest {
			return &runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: "/"}
		}, codes.InvalidArgument},
		{"empty_directory", func(t *testing.T) *runtime.DescribeCheckpointArtifactsRequest {
			return &runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: t.TempDir()}
		}, codes.FailedPrecondition},
		{"symlink_ancestor", func(t *testing.T) *runtime.DescribeCheckpointArtifactsRequest {
			dir := describeIdentityFixture(t)
			parent := t.TempDir()
			require.NoError(t, os.Symlink(filepath.Dir(dir), filepath.Join(parent, "link")))
			return &runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: filepath.Join(parent, "link", filepath.Base(dir))}
		}, codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := (&sandboxService{}).DescribeCheckpointArtifacts(context.Background(), tc.request(t))
			require.Nil(t, response)
			require.Equal(t, tc.code, status.Code(err), "%v", err)
		})
	}
}

func TestDescribeCheckpointArtifactsRejectsUnsealedAndUncoveredArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*testing.T, string)
	}{
		{"missing_seal", func(t *testing.T, dir string) { require.NoError(t, os.Remove(filepath.Join(dir, "manifest.json"))) }},
		{"malformed_seal", func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{"), 0600))
		}},
		{"incomplete_seal", func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0600))
		}},
		{"uncovered_file", func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "extra"), []byte("unbound"), 0600))
		}},
		{"oversized_seal", func(t *testing.T, dir string) {
			file, err := os.OpenFile(filepath.Join(dir, "manifest.json"), os.O_WRONLY, 0)
			require.NoError(t, err)
			require.NoError(t, file.Truncate(checkpointroot.MaxManifestBytes+1))
			require.NoError(t, file.Close())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := describeIdentityFixture(t)
			tc.alter(t, dir)
			response, err := (&sandboxService{}).DescribeCheckpointArtifacts(context.Background(),
				&runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: dir})
			require.Nil(t, response)
			require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
		})
	}
}

func TestDescribeCheckpointArtifactsHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response, err := (&sandboxService{}).DescribeCheckpointArtifacts(ctx, nil)
	require.Nil(t, response)
	require.Equal(t, codes.Canceled, status.Code(err))
}

func TestDescribeCheckpointArtifactsWireContract(t *testing.T) {
	dir := describeIdentityFixture(t)
	expected, err := checkpointroot.Bind(dir)
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		service runtime.SandboxServiceServer
		code    codes.Code
	}{
		{"implemented", &sandboxService{}, codes.OK},
		{"old_server", &runtime.UnimplementedSandboxServiceServer{}, codes.Unimplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener := bufconn.Listen(1 << 20)
			server := grpc.NewServer()
			runtime.RegisterSandboxServiceServer(server, tc.service)
			t.Cleanup(func() { server.Stop(); _ = listener.Close() })
			go func() { _ = server.Serve(listener) }()
			connection, err := grpc.NewClient("passthrough:///checkpoint-identity",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
			require.NoError(t, err)
			t.Cleanup(func() { _ = connection.Close() })
			response, err := runtime.NewSandboxServiceClient(connection).DescribeCheckpointArtifacts(context.Background(),
				&runtime.DescribeCheckpointArtifactsRequest{CheckpointDir: dir})
			require.Equal(t, tc.code, status.Code(err), "%v", err)
			if tc.code != codes.OK {
				require.Nil(t, response, "an old server cannot silently supply a weaker pin")
				return
			}
			require.Equal(t, dir, response.GetCheckpointDir())
			require.Equal(t, expected.RootDigest, response.GetExpectedRootDigest())
			require.False(t, strings.Contains(response.GetExpectedRootDigest(), "manifest.json"))
		})
	}
}
