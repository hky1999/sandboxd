// crtool is a minimal gRPC client for sandboxd's runtime.v1.SandboxService,
// exposing List / Stats / Checkpoint / DeleteCheckpoint / Restore for the
// AKernel_scheduler C/R microbenchmarks. It dials sandboxd's unix socket
// directly, bypassing akernel-sdk (which does not expose C/R).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "crtool: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	sock := flag.String("sock", "/run/sandboxd/sandboxd.sock", "sandboxd unix socket")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fatal("usage: crtool [-sock PATH] list|stats <id>|checkpoint <id> -dir D [-leave-running] [-compress] [-timeout S]|restore -config F -dir D|delete-checkpoint -dir D -id CP [-sandbox ID] [-size N] [-sha256 H]")
	}

	conn, err := grpc.NewClient("unix://"+*sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fatal("dial: %v", err)
	}
	defer conn.Close()
	c := runtime.NewSandboxServiceClient(conn)
	ctx := context.Background()

	switch args[0] {
	case "list":
		resp, err := c.List(ctx, &runtime.ListSandboxesRequest{})
		if err != nil {
			fatal("list: %v", err)
		}
		out, _ := protojson.Marshal(resp)
		fmt.Println(string(out))
	case "stats":
		if len(args) < 2 {
			fatal("stats needs <id>")
		}
		resp, err := c.Stats(ctx, &runtime.StatsRequest{ID: args[1]})
		if err != nil {
			fatal("stats: %v", err)
		}
		out, _ := protojson.Marshal(resp)
		fmt.Println(string(out))
	case "checkpoint":
		fs := flag.NewFlagSet("checkpoint", flag.ExitOnError)
		dir := fs.String("dir", "", "checkpoint artifact directory (required)")
		cpid := fs.String("cpid", "", "checkpoint id (required)")
		leave := fs.Bool("leave-running", false, "keep source sandbox alive")
		withFs := fs.Bool("fs", false, "include writable-layer (fscheckpoint) artifact")
		compress := fs.Bool("compress", false, "compress artifact")
		timeout := fs.Int64("timeout", 0, "timeout seconds")
		fs.Parse(args[1:])
		if len(fs.Args()) < 1 || *dir == "" || *cpid == "" {
			fatal("checkpoint needs <sandbox-id> -dir and -cpid")
		}
		req := &runtime.CheckpointRequest{
			ID:                fs.Args()[0],
			CheckpointID:      *cpid,
			CheckpointDir:     *dir,
			LeaveRunning:      *leave,
			IncludeFilesystem: *withFs,
			Compress:          *compress,
			Timeout:           *timeout,
			TraceID:           "crtool",
		}
		t0 := time.Now()
		resp, err := c.Checkpoint(ctx, req)
		dt := time.Since(t0)
		if err != nil {
			fatal("checkpoint (%v): %v", dt, err)
		}
		out, _ := protojson.Marshal(resp)
		fmt.Printf("elapsed_ms=%d %s\n", dt.Milliseconds(), string(out))
	case "delete-checkpoint":
		fs := flag.NewFlagSet("delete-checkpoint", flag.ExitOnError)
		dir := fs.String("dir", "", "checkpoint dir (required)")
		cpID := fs.String("id", "", "checkpoint id (required)")
		sbID := fs.String("sandbox", "", "source sandbox id")
		size := fs.Int64("size", 0, "expected size")
		sha := fs.String("sha256", "", "expected sha256")
		fs.Parse(args[1:])
		if *dir == "" || *cpID == "" {
			fatal("delete-checkpoint needs -dir and -id")
		}
		resp, err := c.DeleteCheckpoint(ctx, &runtime.DeleteCheckpointRequest{
			CheckpointDir:   *dir,
			CheckpointID:    *cpID,
			SourceSandboxID: *sbID,
			ExpectedSize:    *size,
			ExpectedSha256:  *sha,
		})
		if err != nil {
			fatal("delete-checkpoint: %v", err)
		}
		out, _ := protojson.Marshal(resp)
		fmt.Println(string(out))
	case "start":
		fs := flag.NewFlagSet("start", flag.ExitOnError)
		cfgFile := fs.String("config", "", "JSON file with a StartRequest message")
		text := fs.Bool("text", false, "config file is proto text format (as logged by sandboxd)")
		fs.Parse(args[1:])
		if *cfgFile == "" {
			fatal("start needs -config (StartRequest json)")
		}
		raw, err := os.ReadFile(*cfgFile)
		if err != nil {
			fatal("read config: %v", err)
		}
		cfg := &runtime.StartRequest{}
		if *text {
			if err := (prototext.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, cfg); err != nil {
				fatal("parse config (text): %v", err)
			}
		} else if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, cfg); err != nil {
			fatal("parse config: %v", err)
		}
		t0 := time.Now()
		resp, err := c.Start(ctx, cfg)
		dt := time.Since(t0)
		if err != nil {
			fatal("start (%v): %v", dt, err)
		}
		out, _ := protojson.Marshal(resp)
		fmt.Printf("elapsed_ms=%d %s\n", dt.Milliseconds(), string(out))
	case "restore":
		fs := flag.NewFlagSet("restore", flag.ExitOnError)
		cfgFile := fs.String("config", "", "JSON file with a StartRequest message")
		text := fs.Bool("text", false, "config file is proto text format (as logged by sandboxd)")
		dir := fs.String("dir", "", "checkpoint dir")
		cpID := fs.String("id", "", "checkpoint id")
		sha := fs.String("sha256", "", "expected sha256")
		size := fs.Int64("size", 0, "expected size")
		fs.Parse(args[1:])
		if *cfgFile == "" || *dir == "" {
			fatal("restore needs -config (StartRequest json) and -dir")
		}
		raw, err := os.ReadFile(*cfgFile)
		if err != nil {
			fatal("read config: %v", err)
		}
		cfg := &runtime.StartRequest{}
		if *text {
			if err := (prototext.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, cfg); err != nil {
				fatal("parse config (text): %v", err)
			}
		} else if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, cfg); err != nil {
			fatal("parse config: %v", err)
		}
		req := &runtime.RestoreRequest{
			Config:         cfg,
			CheckpointDir:  *dir,
			CheckpointID:   *cpID,
			ExpectedSha256: *sha,
			ExpectedSize:   *size,
		}
		t0 := time.Now()
		resp, err := c.Restore(ctx, req)
		dt := time.Since(t0)
		if err != nil {
			fatal("restore (%v): %v", dt, err)
		}
		out, _ := protojson.Marshal(resp)
		fmt.Printf("elapsed_ms=%d %s\n", dt.Milliseconds(), string(out))
	case "pause", "resume":
		if len(args) < 2 {
			fatal("%s needs <sandbox-id>", args[0])
		}
		start := time.Now()
		var resp *runtime.PauseResponse
		var err error
		if args[0] == "pause" {
			resp, err = c.Pause(ctx, &runtime.PauseRequest{ID: args[1]})
		} else {
			resp, err = c.Resume(ctx, &runtime.PauseRequest{ID: args[1]})
		}
		if err != nil {
			fatal("%s: %v", args[0], err)
		}
		out, _ := protojson.Marshal(resp)
		fmt.Printf("elapsed_ms=%.3f %s\n", float64(time.Since(start).Microseconds())/1000.0, string(out))
	case "delete":
		fs := flag.NewFlagSet("delete", flag.ExitOnError)
		timeout := fs.Int64("timeout", 30, "timeout seconds")
		fs.Parse(args[1:])
		if len(fs.Args()) < 1 {
			fatal("delete needs <sandbox-id>")
		}
		resp, err := c.Delete(ctx, &runtime.DeleteRequest{ID: fs.Args()[0], Timeout: *timeout})
		if err != nil {
			fatal("delete: %v", err)
		}
		out, _ := protojson.Marshal(resp)
		fmt.Println(string(out))
	case "wait":
		if len(args) < 2 {
			fatal("wait needs <id>")
		}
		resp, err := c.Wait(ctx, &runtime.WaitRequest{ID: args[1]})
		if err != nil {
			fatal("wait: %v", err)
		}
		b, _ := json.Marshal(resp)
		fmt.Println(string(b))
	default:
		fatal("unknown subcommand %q", args[0])
	}
}
