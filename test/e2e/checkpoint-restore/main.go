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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type options struct {
	action                   string
	socket                   string
	runtime                  string
	rootfs                   string
	sandboxID                string
	targetID                 string
	requestFile              string
	checkpointDir            string
	timeout                  time.Duration
	checkpointTimeoutSeconds uint
	memoryMB                 float64
	cpu                      int
	storageMB                uint64
	extraConfig              string
	compress                 bool
	leaveRunning             bool
	snapshotType             string
	expectedGeneration       string
	operationID              string
	operationIDSet           bool
	expectedRootDigest       string
	expectedRootDigestSet    bool
	expectedRequestDigest    string
	expectedRequestDigestSet bool
	stdout                   string
	stderr                   string
	workloadCmd              string
	mounts                   stringList
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

// parseFlags binds the command line onto one options value. The two
// operation-mode flags additionally record their presence: an explicitly
// passed but empty --operation-id or --expected-root-digest is intent, not
// omission, and must fail validation instead of silently selecting the
// legacy path. errorOutput receives the flag package's usage text, so tests
// can parse real argv quietly.
func parseFlags(args []string, errorOutput io.Writer) (options, error) {
	var value options
	flags := flag.NewFlagSet("checkpoint-restore", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	flags.StringVar(&value.action, "action", "",
		"start, checkpoint, restore, delete, get-start-operation, or checkpoint-root")
	flags.StringVar(&value.socket, "socket", "", "sandboxd Unix socket")
	flags.StringVar(&value.runtime, "runtime", "runsc", "runtime handler")
	flags.StringVar(&value.stdout, "stdout", "/var/log/sandboxd/checkpoint-workload.stdout", "sandbox console output path")
	flags.StringVar(&value.stderr, "stderr", "/var/log/sandboxd/checkpoint-runtime.stderr", "sandbox runtime error log path")
	flags.StringVar(&value.rootfs, "rootfs", "", "local rootfs path")
	flags.StringVar(&value.sandboxID, "sandbox-id", "", "source sandbox ID")
	flags.StringVar(&value.targetID, "target-id", "", "restored sandbox ID")
	flags.StringVar(&value.requestFile, "request-file", "", "persisted StartRequest JSON")
	flags.StringVar(&value.checkpointDir, "checkpoint-dir", "", "caller-owned checkpoint directory")
	flags.DurationVar(&value.timeout, "timeout", 5*time.Minute, "client operation timeout")
	flags.UintVar(
		&value.checkpointTimeoutSeconds,
		"checkpoint-timeout-seconds",
		180,
		"sandboxd checkpoint timeout in seconds",
	)
	flags.Float64Var(&value.memoryMB, "memory-mb", 128, "sandbox memory in MiB")
	flags.IntVar(&value.cpu, "cpu", 500, "CPU quota (milli-CPU)")
	flags.Uint64Var(&value.storageMB, "storage-mb", 64, "writable layer in MiB")
	flags.StringVar(&value.extraConfig, "extra-config", "",
		"runtime-specific configuration as a JSON object")
	flags.BoolVar(&value.compress, "compress", true, "compress checkpoint artifacts")
	flags.BoolVar(&value.leaveRunning, "leave-running", true, "leave source running")
	flags.StringVar(&value.snapshotType, "snapshot-type", "",
		"checkpoint flavor: empty (auto), Full, Incremental, or SoftDirty")
	flags.StringVar(&value.expectedGeneration, "expected-generation", "",
		"resource_generation the checkpointed or deleted sandbox must still be on "+
			"(empty keeps the unconditional checkpoint/delete RPCs)")
	flags.StringVar(&value.operationID, "operation-id", "",
		"persistent start operation ID: switches start/restore to "+
			"StartWithOperation and names the operation to query")
	flags.StringVar(&value.expectedRootDigest, "expected-root-digest", "",
		"hex sha-256 over the entire checkpoint content root "+
			"(the shared checksum algorithm, scheme v2; required for "+
			"restore with --operation-id)")
	flags.StringVar(&value.expectedRequestDigest, "expected-request-digest", "",
		"hex sha-256 over the exact --request-file bytes a resumable "+
			"restore must replay (optional pin for restore with "+
			"--operation-id; compared against the bytes actually read, "+
			"before any RPC)")
	flags.StringVar(&value.workloadCmd, "workload-cmd", "",
		"override the built-in start workload command (template warmup hooks)")
	flag.Var(&value.mounts, "mount",
		"repeatable mount formatted as host_path:target[:type[:opt1,opt2]]")
	flag.Parse()

func main() {
	value, err := parseFlags(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkpoint-restore: %v\n", err)
		os.Exit(1)
	}
	if err := run(value); err != nil {
		fmt.Fprintf(os.Stderr, "checkpoint-restore: %v\n", err)
		os.Exit(runExitCode(err))
	}
}

// exitOperationNotFound is the process exit code answering a
// get-start-operation query whose operation record does not exist. It is the
// structured not-found signal for callers driving this CLI as a subprocess:
// they key on the exit code (or parse stdout), never on error text, so an
// ambiguous transport failure can fail closed instead of being mistaken for
// an absent record.
const exitOperationNotFound = 3

// errOperationNotFound marks a get-start-operation reply whose record is
// absent on the server (gRPC NotFound). It stays distinct from every other
// query failure so runExitCode can map exactly this condition to
// exitOperationNotFound.
var errOperationNotFound = errors.New("start operation not found")

// runExitCode maps a run error onto the process exit code. The generic
// failure stays 1; the structured operation-not-found answer of a
// get-start-operation query is exitOperationNotFound.
func runExitCode(err error) int {
	if errors.Is(err, errOperationNotFound) {
		return exitOperationNotFound
	}
	return 1
}

// validateOptions rejects every flag misuse — unknown actions, action/flag
// conflicts, malformed values, and missing required fields of the operation
// mode — before the socket is dialed, so a bad invocation never opens a
// connection to sandboxd.
func validateOptions(value options) error {
	switch value.action {
	case "start", "checkpoint", "restore", "delete", "get-start-operation", "checkpoint-root":
	default:
		return errors.New("--action must be start, checkpoint, restore, delete, get-start-operation, or checkpoint-root")
	}
	if value.action == "checkpoint-root" {
		return validateCheckpointRootOptions(value)
	}
	if value.expectedGeneration != "" && value.action != "checkpoint" && value.action != "delete" {
		return errors.New("--expected-generation is only valid for checkpoint and delete")
	}
	if value.socket == "" {
		return errors.New("--socket is required")
	}
	if err := validateExpectedGeneration(value.expectedGeneration); err != nil {
		return err
	}
	return validateOperationFlags(value)
}

// validateCheckpointRootOptions enforces the read-only contract of
// --action checkpoint-root: the action takes --checkpoint-dir and optionally
// --request-file (whose bytes it only hashes). Everything else — the daemon
// socket included — is a conflicted invocation rather than a default to
// honor, so the action can never silently become a daemon RPC or carry a
// start payload.
func validateCheckpointRootOptions(value options) error {
	if value.checkpointDir == "" {
		return errors.New("--checkpoint-dir is required for checkpoint-root")
	}
	if !filepath.IsAbs(value.checkpointDir) {
		return errors.New("--checkpoint-dir must be absolute for checkpoint-root")
	}
	if value.requestFile != "" && !filepath.IsAbs(value.requestFile) {
		return errors.New("--request-file must be absolute for checkpoint-root")
	}
	if value.socket != "" || value.operationIDSet || value.expectedRootDigestSet ||
		value.expectedRequestDigestSet || value.expectedGeneration != "" ||
		value.sandboxID != "" || value.targetID != "" ||
		value.rootfs != "" || value.snapshotType != "" || value.workloadCmd != "" {
		return errors.New("--action checkpoint-root takes only --checkpoint-dir and " +
			"--request-file (no socket, no payload, no operation flags)")
	}
	return nil
}

// checkpointRootOutput is the strict stdout contract of the checkpoint-root
// action: one JSON object with exactly the keys root and scheme — plus
// request_sha256 exactly when --request-file was passed — and nothing else,
// so a caller can reject mixed or partial output instead of guessing.
type checkpointRootOutput struct {
	Root          string `json:"root"`
	Scheme        string `json:"scheme"`
	RequestSHA256 string `json:"request_sha256,omitempty"`
}

// maxRequestFileBytes is the fixed metadata bound on the request file the
// checkpoint-root action may hash: a StartRequest document is tiny, so a
// file beyond this bound is a mistyped path, not a request.
const maxRequestFileBytes = 1 << 20

// checkpointRoot derives and prints the content-root identity of a local
// checkpoint directory. It is deliberately offline: no socket is dialed, the
// action reads only the sealed manifest and the chunk sidecars (metadata,
// never artifact payloads) through the shared checkpointroot.Bind — the one
// algorithm the server's admission and the runtime's restore boundary use —
// and it modifies nothing in the directory. With --request-file it also
// hashes the exact request bytes (one bounded read) and appends
// request_sha256, so an orchestrator can pin the restore request content in
// the same roundtrip that pins the artifact root.
func checkpointRoot(value options) error {
	binding, err := checkpointroot.Bind(value.checkpointDir)
	if err != nil {
		return fmt.Errorf("checkpoint-root: %w", err)
	}
	output := checkpointRootOutput{
		Root:   binding.RootDigest,
		Scheme: binding.Scheme,
	}
	if value.requestFile != "" {
		digest, err := hashRequestFileBounded(value.requestFile)
		if err != nil {
			return fmt.Errorf("checkpoint-root: %w", err)
		}
		output.RequestSHA256 = digest
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

// hashRequestFileBounded hashes the exact request-file bytes in one bounded
// read: the stat refuses a non-regular or oversized file before any byte is
// buffered, and the read itself is limit-bounded so growth between the stat
// and the read cannot force an unbounded buffer.
func hashRequestFileBounded(path string) (string, error) {
	data, err := readRequestFileBounded(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func readRequestFileBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("request file %s is not a regular file", path)
	}
	if info.Size() > maxRequestFileBytes {
		return nil, fmt.Errorf("request file %s exceeds the %d-byte bound", path, maxRequestFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRequestFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRequestFileBytes {
		return nil, fmt.Errorf("request file %s exceeds the %d-byte bound while reading", path, maxRequestFileBytes)
	}
	return data, nil
}

func run(value options) error {
	if err := validateOptions(value); err != nil {
		return err
	}
	// The read-only identity action never opens a connection: it answers
	// from the local directory alone, so it must be dispatched before the
	// dial and must stay unreachable past it.
	if value.action == "checkpoint-root" {
		return checkpointRoot(value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), value.timeout)
	defer cancel()
	connection, err := grpc.DialContext(
		ctx,
		"passthrough:///sandboxd",
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", value.socket)
		}),
	)
	if err != nil {
		return err
	}
	defer connection.Close()
	client := runtime.NewSandboxServiceClient(connection)

	switch value.action {
	case "start":
		return start(ctx, client, value)
	case "checkpoint":
		return checkpoint(ctx, client, value)
	case "restore":
		return restore(ctx, client, value)
	case "delete":
		return deleteSandbox(ctx, client, value)
	case "get-start-operation":
		return getStartOperation(ctx, client, value)
	default:
		return errors.New("--action must be start, checkpoint, restore, delete, get-start-operation, or checkpoint-root")
	}
}

func start(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.expectedGeneration != "" {
		return errors.New("--expected-generation is only valid for checkpoint and delete")
	}
	if value.operationID != "" {
		return startWithOperation(ctx, client, value)
	}
	request, err := buildStartRequest(value)
	if err != nil {
		return err
	}
	response, err := client.Start(ctx, request)
	if err != nil {
		return err
	}
	if response.Code != 0 || response.ID != value.sandboxID {
		return fmt.Errorf("start response = %+v", response)
	}
	fmt.Println(response.ID)
	return nil
}

// buildStartRequest assembles the StartRequest shared by the legacy Start and
// the operation-wrapped StartWithOperation paths — including persisting it to
// the request file a later restore replays — so both modes start the exact
// same sandbox.
func buildStartRequest(value options) (*runtime.StartRequest, error) {
	if value.rootfs == "" || value.sandboxID == "" {
		return nil, errors.New("--rootfs and --sandbox-id are required for start")
	}
	if value.requestFile == "" {
		return nil, errors.New("--request-file is required for start")
	}
	if value.storageMB > ^uint64(0)/(1024*1024) {
		return nil, errors.New("--storage-mb overflows bytes")
	}
	mounts, err := parseMountFlags(value.mounts)
	if err != nil {
		return err
	}
	request := &runtime.StartRequest{
		SandboxID: value.sandboxID,
		Runtime:   value.runtime,
		Rootfs: &runtime.RootfsConfig{
			Type: runtime.RootfsSrcType_LOCAL,
			Source: &runtime.RootfsConfig_Path{
				Path: value.rootfs,
			},
		},
		Command: []string{
			"/bin/sh",
			"-c",
			workloadCommand(value.workloadCmd),
		},
		Cwd:     "/",
		Network: "sandbox",
		Mounts:  mounts,
		Stdout:  "/var/log/sandboxd/checkpoint-workload.stdout",
		Stderr:  "/var/log/sandboxd/checkpoint-runtime.stderr",
		Resources: map[string]float64{
			"CPU":    float64(value.cpu),
			"Memory": value.memoryMB,
		},
		WritableLayerLimitBytes: value.storageMB * 1024 * 1024,
		ExtraConfig:             value.extraConfig,
	}
	data, err := protojson.MarshalOptions{
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(request)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(value.requestFile, append(data, '\n'), 0600); err != nil {
		return nil, err
	}
	return request, nil
}

func parseMountFlags(values []string) ([]*runtime.Mount, error) {
	mounts := make([]*runtime.Mount, 0, len(values))
	for _, value := range values {
		parts := strings.SplitN(value, ":", 4)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf(
				"invalid mount %q, expected host_path:target[:type[:opt1,opt2]]",
				value,
			)
		}
		mountType := "bind"
		if len(parts) >= 3 && parts[2] != "" {
			mountType = parts[2]
		}
		options := []string{"rbind", "rw"}
		if len(parts) == 4 && parts[3] != "" {
			options = strings.Split(parts[3], ",")
		}
		mounts = append(mounts, &runtime.Mount{
			Type:    mountType,
			Target:  parts[1],
			Options: options,
			Source: &runtime.Mount_HostPath{
				HostPath: parts[0],
			},
		})
	}
	return mounts, nil
}

// workloadCommand returns the guest workload for a start: an explicit hook
// overrides the built-in regression workload. Hook authors keep full control
// but must keep the sandbox alive — end with an idle loop.
func workloadCommand(hook string) string {
	if hook != "" {
		return hook
	}
	return "if [ -e /var/checkpoint-started ]; then " +
		"echo restarted > /var/checkpoint-restarted; fi; " +
		"echo started > /var/checkpoint-started; " +
		// The anonymous 100MiB blob gives the dirty-page ledgers a
		// substantial first window; the fsyncs land the marker files
		// on the writable layer, where a sealed artifact can read
		// them back with debugfs (the guest page cache is otherwise
		// still unflushed at snapshot pause time).
		"dd if=/dev/zero of=/tmp/blob bs=1M count=100 conv=fsync 2>/dev/null; sync; " +
		"counter=0; while :; do counter=$((counter + 1)); " +
		"echo \"$counter\" > /var/checkpoint-counter; sync; sleep 0.1; done"
}

func checkpoint(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.sandboxID == "" || value.checkpointDir == "" {
		return errors.New("--sandbox-id and --checkpoint-dir are required for checkpoint")
	}
	if value.checkpointTimeoutSeconds == 0 || value.checkpointTimeoutSeconds > uint(^uint32(0)) {
		return errors.New("--checkpoint-timeout-seconds must fit in a non-zero uint32")
	}
	if err := validateExpectedGeneration(value.expectedGeneration); err != nil {
		return err
	}
	request := &runtime.CheckpointRequest{
		ID:             value.sandboxID,
		CheckpointDir:  value.checkpointDir,
		TimeoutSeconds: uint32(value.checkpointTimeoutSeconds),
		Compress:       value.compress,
		LeaveRunning:   value.leaveRunning,
		SnapshotType:   value.snapshotType,
	}
	if value.expectedGeneration == "" {
		if _, err := client.Checkpoint(ctx, request); err != nil {
			return fmt.Errorf("checkpoint: %w", err)
		}
		return nil
	}
	// The generation precondition must hold atomically with the checkpoint:
	// falling back to the unconditional RPC would snapshot an incarnation the
	// caller no longer owns, so every failure — Unimplemented included — is
	// fatal.
	if _, err := client.CheckpointIfGeneration(ctx, &runtime.CheckpointIfGenerationRequest{
		Checkpoint:         request,
		ExpectedGeneration: value.expectedGeneration,
	}); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	return nil
}

// maxExpectedGenerationLength bounds --expected-generation so a mistyped
// flag (a file path, say) cannot reach the service as a generation label.
const maxExpectedGenerationLength = 256

// validateExpectedGeneration accepts the unset value that keeps the legacy
// unconditional RPCs and rejects labels the service compares verbatim:
// blank strings and oversized ones. The helpers re-run this check so direct
// callers (tests included) stay as safe as the CLI.
func validateExpectedGeneration(value string) error {
	if value == "" {
		return nil
	}
	if strings.TrimSpace(value) == "" {
		return errors.New("--expected-generation must not be blank")
	}
	if len(value) > maxExpectedGenerationLength {
		return fmt.Errorf("--expected-generation must be at most %d bytes", maxExpectedGenerationLength)
	}
	return nil
}

// maxOperationIDLength bounds --operation-id. The daemon persists operations
// under their ID, so the value doubles as a path element and must stay short
// and path-safe.
const maxOperationIDLength = 128

// validateOperationIDFormat accepts exactly the identities the daemon accepts
// — ^[A-Za-z0-9][A-Za-z0-9._-]*$, at most 128 bytes — so a mistyped ID the
// service would reject anyway fails here, before the dial. The leading
// alphanumeric also rules out `.`, `..`, and other relative path elements.
// The CLI generates nothing on the caller's behalf, so an absent or malformed
// ID is always an error where the ID is required.
func validateOperationIDFormat(id string) error {
	if id == "" {
		return errors.New("--operation-id must not be empty")
	}
	if len(id) > maxOperationIDLength {
		return fmt.Errorf("--operation-id must be at most %d bytes", maxOperationIDLength)
	}
	first := id[0]
	if !((first >= '0' && first <= '9') ||
		(first >= 'a' && first <= 'z') ||
		(first >= 'A' && first <= 'Z')) {
		return fmt.Errorf(
			"--operation-id must match ^[A-Za-z0-9][A-Za-z0-9._-]*$ "+
				"(%q starts with %q)",
			id,
			first,
		)
	}
	for index := 1; index < len(id); index++ {
		character := id[index]
		switch {
		case character >= '0' && character <= '9',
			character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character == '-', character == '_', character == '.':
		default:
			return fmt.Errorf(
				"--operation-id contains unsupported character %q at byte %d "+
					"(must match ^[A-Za-z0-9][A-Za-z0-9._-]*$)",
				character,
				index,
			)
		}
	}
	return nil
}

// validateExpectedRootDigest accepts exactly 64 hex characters — the encoded
// sha-256 over the entire checkpoint content root under the shared checksum
// algorithm (scheme v2), not the digest of any single file — and passes them
// through verbatim; the daemon remains the authority on whether the pinned
// root matches the directory content.
func validateExpectedRootDigest(digest string) error {
	if len(digest) != 64 {
		return errors.New("--expected-root-digest must be exactly 64 hex characters")
	}
	for index := 0; index < len(digest); index++ {
		character := digest[index]
		switch {
		case character >= '0' && character <= '9',
			character >= 'a' && character <= 'f',
			character >= 'A' && character <= 'F':
		default:
			return fmt.Errorf(
				"--expected-root-digest contains non-hex character %q at byte %d",
				character,
				index,
			)
		}
	}
	return nil
}

// validateExpectedRequestDigest accepts exactly 64 hex characters — the
// encoded sha-256 over the exact request-file bytes — and passes them through
// verbatim; the CLI remains the authority on whether the pinned digest
// matches the bytes it actually reads and sends.
func validateExpectedRequestDigest(digest string) error {
	if digest == "" {
		return nil
	}
	if len(digest) != 64 {
		return errors.New("--expected-request-digest must be exactly 64 hex characters")
	}
	for index := 0; index < len(digest); index++ {
		character := digest[index]
		switch {
		case character >= '0' && character <= '9',
			character >= 'a' && character <= 'f',
			character >= 'A' && character <= 'F':
		default:
			return fmt.Errorf(
				"--expected-request-digest contains non-hex character %q at byte %d",
				character,
				index,
			)
		}
	}
	return nil
}

// validateOperationFlags enforces the persistent-operation flag contract:
// explicitly passed but empty new flags fail rather than silently selecting
// the legacy path, only the right actions accept --operation-id,
// --expected-root-digest belongs only to the operation-mode restore, the
// query action carries no start payload, and the operation modes have their
// required fields. It runs before the socket is dialed and the mode helpers
// re-run their share so direct callers (tests included) stay as safe as the
// CLI.
func validateOperationFlags(value options) error {
	// Presence, not non-emptiness, signals intent: `--operation-id=` is a
	// malformed operation mode, not a request for legacy Start.
	if value.operationIDSet && value.operationID == "" {
		return errors.New("--operation-id must not be empty")
	}
	if value.expectedRootDigestSet && value.expectedRootDigest == "" {
		return errors.New("--expected-root-digest must not be empty")
	}
	if value.expectedRootDigest != "" &&
		(value.action != "restore" || value.operationID == "") {
		return errors.New("--expected-root-digest is only valid for restore with --operation-id")
	}
	// The request-content pin is optional (a caller may not have one), but an
	// explicitly passed one is intent: empty or malformed values fail here,
	// before the socket is dialed, instead of silently restoring unpinned
	// bytes under the same operation ID.
	if value.expectedRequestDigestSet && value.expectedRequestDigest == "" {
		return errors.New("--expected-request-digest must not be empty")
	}
	if value.expectedRequestDigest != "" &&
		(value.action != "restore" || value.operationID == "") {
		return errors.New("--expected-request-digest is only valid for restore with --operation-id")
	}
	if value.expectedRequestDigest != "" {
		if err := validateExpectedRequestDigest(value.expectedRequestDigest); err != nil {
			return err
		}
	}
	if value.operationID == "" {
		if value.action == "get-start-operation" {
			return errors.New("--operation-id is required for get-start-operation")
		}
		return nil
	}
	if err := validateOperationIDFormat(value.operationID); err != nil {
		return err
	}
	switch value.action {
	case "start":
		if value.rootfs == "" || value.sandboxID == "" || value.requestFile == "" {
			return errors.New("--rootfs, --sandbox-id, and --request-file are required for start")
		}
	case "restore":
		if value.targetID == "" || value.checkpointDir == "" || value.requestFile == "" ||
			value.expectedRootDigest == "" {
			return errors.New("--target-id, --request-file, --checkpoint-dir, and " +
				"--expected-root-digest are required for restore with --operation-id")
		}
		if err := validateExpectedRootDigest(value.expectedRootDigest); err != nil {
			return err
		}
	case "get-start-operation":
		// The query takes no start payload: any of these flags set is a
		// conflicted invocation, not a default.
		if value.sandboxID != "" || value.targetID != "" || value.requestFile != "" ||
			value.checkpointDir != "" || value.rootfs != "" || value.snapshotType != "" ||
			value.workloadCmd != "" {
			return errors.New("--action get-start-operation takes only --socket, " +
				"--timeout, and --operation-id")
		}
	default:
		return errors.New("--operation-id is only valid for start, restore, and get-start-operation")
	}
	return nil
}

func restore(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.expectedGeneration != "" {
		return errors.New("--expected-generation is only valid for checkpoint and delete")
	}
	if value.operationID != "" {
		return restoreWithOperation(ctx, client, value)
	}
	if value.targetID == "" || value.checkpointDir == "" {
		return errors.New("--target-id and --checkpoint-dir are required for restore")
	}
	if value.requestFile == "" {
		return errors.New("--request-file is required for restore")
	}
	request, _, err := loadRestoreRequest(value)
	if err != nil {
		return err
	}
	response, err := client.Start(ctx, request)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if response.Code != 0 || response.ID != value.targetID {
		return fmt.Errorf("restore response = %+v", response)
	}
	fmt.Println(response.ID)
	return nil
}

// loadRestoreRequest replays the persisted StartRequest under the restore
// target ID and checkpoint directory, the shared prefix of both restore modes.
// It also returns the hex sha-256 over the exact bytes it just read — one
// read, one hash — so an operation-mode caller compares the pinned request
// digest against the very bytes that were parsed and sent, never a second
// independent read of the file.
func loadRestoreRequest(value options) (*runtime.StartRequest, string, error) {
	data, err := readRequestFileBounded(value.requestFile)
	if err != nil {
		return nil, "", err
	}
	request := new(runtime.StartRequest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, request); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	request.SandboxID = value.targetID
	request.CheckpointInfo = &runtime.CheckpointInfo{
		CheckpointDir: value.checkpointDir,
	}
	return request, hex.EncodeToString(sum[:]), nil
}

// startWithOperation runs the persistent start mode. The legacy Start RPC is
// never called here: a failure of StartWithOperation — Unimplemented from an
// older server included — is terminal, because a silent fallback would create
// a sandbox outside the durable operation the caller is about to reconcile.
func startWithOperation(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if err := validateOperationIDFormat(value.operationID); err != nil {
		return err
	}
	if value.expectedRootDigest != "" {
		return errors.New("--expected-root-digest is only valid for restore")
	}
	request, err := buildStartRequest(value)
	if err != nil {
		return err
	}
	status, err := client.StartWithOperation(ctx, &runtime.StartWithOperationRequest{
		OperationID: value.operationID,
		SandboxID:   value.sandboxID,
		Start:       request,
	})
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	return reportStartOperation(status, value.operationID, value.sandboxID, "start")
}

// restoreWithOperation runs the persistent restore mode. Unlike the legacy
// restore it requires the caller to pin the artifact root digest: the
// operation must bind to the content it restores, not just a path. The CLI
// never invents an operation ID or digest on the caller's behalf. An optional
// --expected-request-digest additionally pins the request bytes: it is
// compared against the hash of the SAME bytes loadRestoreRequest just parsed
// — one read, hashed once — and any mismatch fails BEFORE the
// StartWithOperation RPC, so a request file mutated at the same path can
// never ride the operation identity.
func restoreWithOperation(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if err := validateOperationIDFormat(value.operationID); err != nil {
		return err
	}
	if value.targetID == "" || value.checkpointDir == "" || value.requestFile == "" ||
		value.expectedRootDigest == "" {
		return errors.New("--target-id, --request-file, --checkpoint-dir, and " +
			"--expected-root-digest are required for restore with --operation-id")
	}
	if err := validateExpectedRootDigest(value.expectedRootDigest); err != nil {
		return err
	}
	if err := validateExpectedRequestDigest(value.expectedRequestDigest); err != nil {
		return err
	}
	request, requestDigest, err := loadRestoreRequest(value)
	if err != nil {
		return err
	}
	if value.expectedRequestDigest != "" && requestDigest != value.expectedRequestDigest {
		return fmt.Errorf(
			"restore: request file %s hashes to %s but --expected-request-digest pins %s — the request content changed at this path; refusing to issue operation %q",
			value.requestFile, requestDigest, value.expectedRequestDigest, value.operationID,
		)
	}
	status, err := client.StartWithOperation(ctx, &runtime.StartWithOperationRequest{
		OperationID: value.operationID,
		SandboxID:   value.targetID,
		Start:       request,
		RestoreArtifacts: &runtime.RestoreArtifactIdentity{
			CheckpointDir:      value.checkpointDir,
			ExpectedRootDigest: value.expectedRootDigest,
		},
	})
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	return reportStartOperation(status, value.operationID, value.targetID, "restore")
}

// getStartOperation queries one durable start operation record. A zero exit
// proves only that the record was retrieved and echoes the requested
// operation ID: SUCCEEDED is a historical fact about the generation the
// operation created, not an assertion that the sandbox still exists or still
// runs, so every state is printed verbatim and the caller reconciles liveness
// separately.
func getStartOperation(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.operationID == "" {
		return errors.New("--operation-id is required for get-start-operation")
	}
	if err := validateOperationIDFormat(value.operationID); err != nil {
		return err
	}
	status, err := client.GetStartOperation(ctx, &runtime.GetStartOperationRequest{
		OperationID: value.operationID,
	})
	if err != nil {
		// Absence is the one answer callers may act on (a NotFound record
		// proves the operation was never admitted, so the same operation may
		// be re-issued). Mark exactly the gRPC NotFound status with the
		// structured sentinel; every other failure — Unimplemented, a
		// transport error, a deadline — stays a plain error so subprocess
		// callers fail closed instead of grepping stderr for "not found".
		if gstatus.Code(err) == codes.NotFound {
			return fmt.Errorf("get-start-operation: %w: %w", errOperationNotFound, err)
		}
		return fmt.Errorf("get-start-operation: %w", err)
	}
	if status == nil {
		return errors.New("get-start-operation: empty operation status")
	}
	// A healthy daemon never answers with an unbound record or an UNSPECIFIED
	// state; treat the obviously malformed as protocol errors instead of
	// printing something a caller might reconcile against.
	if status.GetOperationID() == "" || status.GetSandboxID() == "" {
		return fmt.Errorf(
			"get-start-operation: malformed record with empty identity (%+v)",
			status,
		)
	}
	switch status.GetState() {
	case runtime.StartOperationState_START_OPERATION_STATE_RUNNING,
		runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED,
		runtime.StartOperationState_START_OPERATION_STATE_FAILED,
		runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN:
	default:
		return fmt.Errorf("get-start-operation: invalid record state %d", status.GetState())
	}

	if status.GetOperationID() != value.operationID {
		return fmt.Errorf(
			"get-start-operation: status operation_id %q does not match requested %q",
			status.GetOperationID(),
			value.operationID,
		)
	}
	return printOperationStatus(status)
}

// maxResourceGenerationLength bounds the daemon-assigned generation a
// SUCCEEDED receipt must carry, matching the service-side identity limit.
const maxResourceGenerationLength = 128

// reportStartOperation emits the durable operation status as protojson on
// stdout — the operation mode's entire stdout contract, with no human success
// line mixed in — but only exits zero when the record is a proven SUCCEEDED
// for exactly the requested identity. RUNNING, UNKNOWN, and FAILED are
// printed first so the caller can reconcile the spent operation ID, then
// reported as an error: a pending or unproven outcome must never masquerade
// as a completed restore. A receipt naming a different operation or sandbox
// is not the requested record at all, so it fails without stdout output.
func reportStartOperation(
	status *runtime.StartOperationStatus,
	operationID string,
	sandboxID string,
	action string,
) error {
	if status == nil {
		return fmt.Errorf("%s: empty operation status", action)
	}
	if status.GetOperationID() != operationID {
		return fmt.Errorf(
			"%s: status operation_id %q does not match requested %q",
			action,
			status.GetOperationID(),
			operationID,
		)
	}
	if status.GetSandboxID() != sandboxID {
		return fmt.Errorf(
			"%s: status sandbox_id %q does not match requested %q",
			action,
			status.GetSandboxID(),
			sandboxID,
		)
	}
	if status.GetState() != runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED {
		if err := printOperationStatus(status); err != nil {
			return err
		}
		return fmt.Errorf(
			"%s: operation state %s is not SUCCEEDED; reconcile operation %q before issuing a new one",
			action,
			status.GetState(),
			operationID,
		)
	}
	generation := status.GetResourceGeneration()
	if strings.TrimSpace(generation) == "" || len(generation) > maxResourceGenerationLength {
		if err := printOperationStatus(status); err != nil {
			return err
		}
		return fmt.Errorf(
			"%s: SUCCEEDED status must carry a non-blank resource_generation of at most %d bytes",
			action,
			maxResourceGenerationLength,
		)
	}
	return printOperationStatus(status)
}

// printOperationStatus writes one StartOperationStatus to stdout as protojson
// with snake_case field names and unpopulated fields emitted, so the state is
// always explicit for the caller's reconciliation.
func printOperationStatus(status *runtime.StartOperationStatus) error {
	data, err := protojson.MarshalOptions{
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(status)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// deleteSandbox releases a sandbox, cleaning its runtime state and writable
// layer — the acceptance counterpart to checkpoint/restore (previously only
// reachable through the sbox CLI). With --expected-generation set it retires
// exactly that incarnation through DeleteIfGeneration and verifies the
// receipt.
func deleteSandbox(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.sandboxID == "" {
		return errors.New("--sandbox-id is required for delete")
	}
	if err := validateExpectedGeneration(value.expectedGeneration); err != nil {
		return err
	}
	if value.expectedGeneration == "" {
		if _, err := client.Delete(ctx, &runtime.DeleteRequest{
			ID: value.sandboxID,
		}); err != nil {
			return fmt.Errorf("delete: %w", err)
		}
		return nil
	}
	// Conditional retirement is the point of the flag: never fall back to
	// the unconditional Delete, whatever the failure (Unimplemented included)
	// — that would retire an incarnation the caller did not name.
	response, err := client.DeleteIfGeneration(ctx, &runtime.DeleteIfGenerationRequest{
		ID:                 value.sandboxID,
		ExpectedGeneration: value.expectedGeneration,
	})
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	if response.GetRetiredGeneration() != value.expectedGeneration {
		return fmt.Errorf(
			"delete: retired generation %q does not match expected %q",
			response.GetRetiredGeneration(),
			value.expectedGeneration,
		)
	}
	return nil
}
