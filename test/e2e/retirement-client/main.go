// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

// retirement-client sends one explicit lifecycle RPC to an owned fixture.
// It does not retry, fall back to legacy methods or decide budget settlement.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func invoke(ctx context.Context, client runtimeapi.SandboxServiceClient, method string, data []byte) (proto.Message, error) {
	decode := func(message proto.Message) error { return protojson.Unmarshal(data, message) }
	switch method {
	case "StartOperation":
		request := new(runtimeapi.StartOperationRequest)
		if err := decode(request); err != nil {
			return nil, err
		}
		return client.StartOperation(ctx, request)
	case "GetStartOperation":
		request := new(runtimeapi.GetStartOperationRequest)
		if err := decode(request); err != nil {
			return nil, err
		}
		return client.GetStartOperation(ctx, request)
	case "DeleteIfGeneration":
		request := new(runtimeapi.DeleteIfGenerationRequest)
		if err := decode(request); err != nil {
			return nil, err
		}
		return client.DeleteIfGeneration(ctx, request)
	case "List":
		request := new(runtimeapi.ListSandboxesRequest)
		if err := decode(request); err != nil {
			return nil, err
		}
		return client.List(ctx, request)
	case "Stats":
		request := new(runtimeapi.StatsRequest)
		if err := decode(request); err != nil {
			return nil, err
		}
		return client.Stats(ctx, request)
	default:
		return nil, fmt.Errorf("unsupported explicit fixture RPC %q", method)
	}
}

func main() {
	socket := flag.String("socket", "", "owned Unix socket path")
	method := flag.String("method", "", "one lifecycle method")
	request := flag.String("request", "", "non-sensitive fixture request JSON file")
	timeout := flag.Duration("timeout", 30*time.Second, "bounded RPC duration")
	flag.Parse()
	if !filepath.IsAbs(*socket) || !filepath.IsAbs(*request) || *timeout <= 0 || *timeout > 2*time.Minute {
		fmt.Fprintln(os.Stderr, "absolute fixture paths and bounded timeout required")
		os.Exit(2)
	}
	data, err := os.ReadFile(*request)
	if err != nil || len(data) > 1024*1024 {
		fmt.Fprintln(os.Stderr, "bounded fixture request unavailable")
		os.Exit(2)
	}
	connection, err := grpc.NewClient("unix://"+*socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := invoke(ctx, runtimeapi.NewSandboxServiceClient(connection), *method, data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	output, err := (protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}).Marshal(response)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(output))
}
