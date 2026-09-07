// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"flag"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/identityresolver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	sock := flag.String("sock", "/run/sandboxd/sandboxd.sock", "local sandboxd Unix socket")
	listen := flag.String("listen", "127.0.0.1:8093", "resolver HTTP listen address")
	tokenFile := flag.String("token-file", "", "private file containing resolver bearer token")
	flag.Parse()
	if !filepath.IsAbs(*sock) {
		log.Fatal("sandboxd socket must be an absolute local path")
	}
	info, err := os.Lstat(*tokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		log.Fatal("token-file must be a private regular file of at most 4096 bytes")
	}
	raw, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatal("cannot read resolver token")
	}
	conn, err := grpc.NewClient("unix://"+*sock, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(8<<20)))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	handler, err := identityresolver.New(runtime.NewSandboxServiceClient(conn), strings.TrimSpace(string(raw)))
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	log.Fatal(server.ListenAndServe())
}
