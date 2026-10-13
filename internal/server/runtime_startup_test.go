// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

func TestRequiredRuntimeFailureRejectsStartup(t *testing.T) {
	base := t.TempDir()
	registry := filepath.Join(base, "registry.json")
	oss := filepath.Join(base, "oss.json")
	ossAuths := filepath.Join(base, "oss_auths.json")
	registryAuths := filepath.Join(base, "registry_auths.json")
	require.NoError(t, os.WriteFile(registry, []byte(`{"type":"registry","registry":{}}`), 0600))
	require.NoError(t, os.WriteFile(oss, []byte(`{"type":"oss","oss":{}}`), 0600))
	require.NoError(t, os.WriteFile(ossAuths, []byte(`{}`), 0600))
	require.NoError(t, os.WriteFile(registryAuths, []byte(`{"auths":{}}`), 0600))
	configuration := fmt.Sprintf(`rootDir=%q
storeDir=%q
[plugin.network]
nat_backend="iptables"
[plugin.resource]
disable_cgroup=true
max_instance_num=4
[plugin.runtime]
filestore_dir=%q
[plugin.runtime.runsc]
platform="systrap"
[plugin.runtime.runtime_binary]
runsc=%q
[plugin.image]
root=%q
oss_template=%q
nydus_template=%q
oss_auths_path=%q
registry_auths_path=%q
cgroup_memory_limit="0"
`, filepath.Join(base, "root"), filepath.Join(base, "store"), filepath.Join(base, "filestore"), filepath.Join(base, "missing-runsc"), filepath.Join(base, "images"), oss, registry, ossAuths, registryAuths)
	configPath := filepath.Join(base, "config.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(configuration), 0600))
	service, err := NewSandboxService(filepath.Join(base, "home"), configPath)
	if service != nil {
		service.Shutdown()
	}
	require.ErrorContains(t, err, "runtime")
	require.Nil(t, service, "failed required runtime must not become a usable service")
	_, statErr := os.Stat(filepath.Join(base, "store", ".pod_host"))
	require.NoError(t, statErr, "initialization evidence must remain after failure")
}

func runtimeStartupFixture(t *testing.T, names ...string) *sandboxService {
	t.Helper()
	h := &sandboxService{serviceHandler: cmap.New[svc.Handler]()}
	h.config.RootDir = t.TempDir()
	h.config.RuntimeConfig.RuntimeBinary = make(map[string]string)
	for _, name := range names {
		h.config.RuntimeConfig.RuntimeBinary[name] = "/fixture/" + name
	}
	return h
}

func TestRequiredRuntimeRetryPreservesFailureAndDeadline(t *testing.T) {
	h := runtimeStartupFixture(t, config.RuntimeNameRunsc)
	cause := errors.New("required initialization failed")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	calls := 0
	started := time.Now()
	err := h.loadRuntimeHandlersWithContext(ctx, func(config.Config, string, string) (svc.Handler, error) {
		calls++
		return nil, cause
	})
	require.ErrorIs(t, err, cause)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, 1, calls)
	require.Less(t, time.Since(started), time.Second)
	require.False(t, h.serviceHandler.Has(config.RuntimeNameRunsc))
}

func TestRequiredRuntimeTransientFailureRetriesAndRegistersOnce(t *testing.T) {
	h := runtimeStartupFixture(t, config.RuntimeNameRunsc)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	handler := svc.NewFakeRuntimeHandler()
	create := func(config.Config, string, string) (svc.Handler, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("transient initialization failure")
		}
		return handler, nil
	}
	require.NoError(t, h.loadRuntimeHandlersWithContext(ctx, create))
	require.Equal(t, 2, calls)
	loaded, ok := h.serviceHandler.Get(config.RuntimeNameRunsc)
	require.True(t, ok)
	require.Same(t, handler, loaded)
	require.NoError(t, h.loadRuntimeHandlersWithContext(ctx, create))
	require.Equal(t, 2, calls, "already registered handlers must not be initialized again")
}

func TestOptionalRuntimeFailureDoesNotBlockRequiredRuntime(t *testing.T) {
	h := runtimeStartupFixture(t, config.RuntimeNameKata, config.RuntimeNameRunsc)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, h.loadRuntimeHandlersWithContext(ctx, func(_ config.Config, _ string, name string) (svc.Handler, error) {
		if name == config.RuntimeNameKata {
			return nil, errors.New("optional host support absent")
		}
		return svc.NewFakeRuntimeHandler(), nil
	}))
	require.True(t, h.serviceHandler.Has(config.RuntimeNameRunsc))
	require.False(t, h.serviceHandler.Has(config.RuntimeNameKata))
}

func TestRuntimeStartupCancellationCannotPublishLateSuccess(t *testing.T) {
	for _, name := range []string{config.RuntimeNameRunsc, config.RuntimeNameKata} {
		t.Run(name, func(t *testing.T) {
			h := runtimeStartupFixture(t, name)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := h.loadRuntimeHandlersWithContext(ctx, func(config.Config, string, string) (svc.Handler, error) {
				cancel()
				if name == config.RuntimeNameKata {
					return nil, errors.New("optional failure after cancellation")
				}
				return svc.NewFakeRuntimeHandler(), nil
			})
			require.ErrorIs(t, err, context.Canceled)
			require.False(t, h.serviceHandler.Has(name))
		})
	}
}

func TestRuntimeStartupBundleDirectoryFailureStopsInitialization(t *testing.T) {
	h := runtimeStartupFixture(t, config.RuntimeNameRunsc)
	require.NoError(t, os.WriteFile(filepath.Join(h.config.RootDir, "containers"), []byte("original file"), 0600))
	err := h.loadRuntimeHandlersWithContext(context.Background(), func(config.Config, string, string) (svc.Handler, error) {
		t.Fatal("initializer must not run after bundle directory failure")
		return nil, nil
	})
	require.ErrorContains(t, err, "bundle directory")
	data, err := os.ReadFile(filepath.Join(h.config.RootDir, "containers"))
	require.NoError(t, err)
	require.Equal(t, "original file", string(data))
}
