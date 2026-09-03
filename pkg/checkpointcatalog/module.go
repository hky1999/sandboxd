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

package checkpointcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Module serves the catalog over a Unix-socket admin endpoint:
//
//	GET /api/v1/checkpoints              -> {"checkpoints": [...Entry]}
//	GET /api/v1/checkpoints/{id}/verify  -> VerifyResult
//
// The catalog has no state of its own — every request re-scans the
// configured roots — so there is no lifecycle beyond the listener.
type Module struct {
	cfg      Config
	listener net.Listener

	mu     sync.Mutex
	closed bool
}

// NewModule binds the socket (replacing a stale one) and starts serving.
// It follows the resourcemanager module shape so operators configure and
// inspect both the same way.
func NewModule(cfg Config) (*Module, error) {
	if cfg.SockPath == "" {
		return nil, errors.New("checkpoint catalog requires sock_path")
	}
	if len(cfg.Dirs) == 0 {
		return nil, errors.New("checkpoint catalog requires at least one dir to inventory")
	}
	if _, err := os.Stat(cfg.SockPath); err == nil {
		os.Remove(cfg.SockPath)
	}
	ln, err := net.Listen("unix", cfg.SockPath)
	if err != nil {
		return nil, err
	}
	m := &Module{cfg: cfg, listener: ln}
	srv := &http.Server{Handler: m.handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Warnf("checkpointcatalog: http server stopped: %v", err)
		}
	}()
	return m, nil
}

// Close shuts the listener down.
func (m *Module) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	m.listener.Close()
}

func (m *Module) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/checkpoints", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		entries, err := List(ctx, m.cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string][]Entry{"checkpoints": entries})
	})
	mux.HandleFunc("/api/v1/checkpoints/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/checkpoints/")
		id, action, found := strings.Cut(rest, "/")
		if id == "" || !found || action != "verify" || strings.Contains(action, "/") {
			http.Error(w, "unknown endpoint", http.StatusNotFound)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		result, err := Verify(ctx, m.cfg, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, result)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, body any) {
	encoded, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(encoded, '\n'))
}
