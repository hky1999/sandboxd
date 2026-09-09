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
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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
	recoveryTimeoutSeconds   uint
	abortTimeoutSeconds      uint
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
		"start, checkpoint, restore, delete, get-start-operation, "+
			"get-checkpoint-operation, recover-checkpoint-operation, "+
			"abort-checkpoint-operation, or checkpoint-root")
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
	flags.UintVar(
		&value.recoveryTimeoutSeconds,
		"recovery-timeout-seconds",
		180,
		"bounded timeout in seconds of one recover-checkpoint-operation "+
			"attempt (joins a still-running original execution, runs the "+
			"runtime recovery, and acknowledges; never part of the original "+
			"request digest)",
	)
	flags.UintVar(
		&value.abortTimeoutSeconds,
		"abort-timeout-seconds",
		180,
		"bounded timeout in seconds of one abort-checkpoint-operation "+
			"attempt (joins a still-running original execution, runs the "+
			"runtime abort, and acknowledges; never part of the original "+
			"request digest)",
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
		"persistent operation ID: switches start/restore to "+
			"StartWithOperation, checkpoint to CheckpointWithOperation, "+
			"and names the operation to query")
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
// get-start-operation or get-checkpoint-operation query whose operation record
// does not exist. It is the structured not-found signal for callers driving
// this CLI as a subprocess: they key on the exit code (or parse stdout), never
// on error text, so an ambiguous transport failure can fail closed instead of
// being mistaken for an absent record.
const exitOperationNotFound = 3

// errOperationNotFound marks a get-start-operation reply whose record is
// absent on the server (gRPC NotFound). It stays distinct from every other
// query failure so runExitCode can map exactly this condition to
// exitOperationNotFound.
var errOperationNotFound = errors.New("start operation not found")

// errCheckpointOperationNotFound marks a get-checkpoint-operation reply whose
// record is absent on the server (gRPC NotFound). It shares the structured
// exitOperationNotFound answer with the start-operation query while keeping
// its own message, so stderr stays accurate for each action.
var errCheckpointOperationNotFound = errors.New("checkpoint operation not found")

// runExitCode maps a run error onto the process exit code. The generic
// failure stays 1; the structured operation-not-found answer of a query
// action is exitOperationNotFound.
func runExitCode(err error) int {
	if errors.Is(err, errOperationNotFound) ||
		errors.Is(err, errCheckpointOperationNotFound) {
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
	case "start", "checkpoint", "restore", "delete", "get-start-operation",
		"get-checkpoint-operation", "recover-checkpoint-operation",
		"abort-checkpoint-operation", "checkpoint-root":
	default:
		return errors.New("--action must be start, checkpoint, restore, delete, " +
			"get-start-operation, get-checkpoint-operation, " +
			"recover-checkpoint-operation, abort-checkpoint-operation, " +
			"or checkpoint-root")
	}
	if value.action == "checkpoint-root" {
		return validateCheckpointRootOptions(value)
	}
	if value.expectedGeneration != "" &&
		value.action != "checkpoint" && value.action != "delete" &&
		value.action != "recover-checkpoint-operation" &&
		value.action != "abort-checkpoint-operation" {
		return errors.New("--expected-generation is only valid for checkpoint, delete, " +
			"recover-checkpoint-operation, and abort-checkpoint-operation")
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
	case "get-checkpoint-operation":
		return getCheckpointOperation(ctx, client, value, os.Stdout)
	case "recover-checkpoint-operation":
		return recoverCheckpointOperation(ctx, client, value, os.Stdout)
	case "abort-checkpoint-operation":
		return abortCheckpointOperation(ctx, client, value, os.Stdout)
	default:
		return errors.New("--action must be start, checkpoint, restore, delete, " +
			"get-start-operation, get-checkpoint-operation, " +
			"recover-checkpoint-operation, abort-checkpoint-operation, " +
			"or checkpoint-root")
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
	if value.operationID != "" {
		return checkpointWithOperation(ctx, client, value, request, os.Stdout)
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

// checkpointOperationMaxTimeoutSeconds mirrors the service-side ceiling of
// identified checkpoint operations; the legacy checkpoint bound (a non-zero
// uint32) is unchanged and stays wider on purpose.
const checkpointOperationMaxTimeoutSeconds = 600

// maxCheckpointDirLength mirrors the service-side canonical directory bound a
// checkpoint operation record can carry.
const maxCheckpointDirLength = 4096

// checkpointWithOperation runs the identified source checkpoint mode. The
// complete legacy CheckpointRequest — id, directory spelling, timeout,
// compression, leave_running, snapshot type — is passed to
// CheckpointWithOperation unchanged, so the operation binds the exact request
// the caller named. The legacy Checkpoint and CheckpointIfGeneration RPCs are
// never called here: any failure of CheckpointWithOperation, Unimplemented
// from an older server included, is terminal, because the daemon records the
// operation before its side effects and a fallback would checkpoint outside
// the durable identity the caller is about to reconcile. An RPC error carries
// no usable payload — after one, the only next step is querying the operation
// ID, never reissuing an older RPC.
func checkpointWithOperation(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
	request *runtime.CheckpointRequest,
	out io.Writer,
) error {
	if err := validateOperationIDFormat(value.operationID); err != nil {
		return err
	}
	if value.sandboxID == "" || value.checkpointDir == "" {
		return errors.New("--sandbox-id and --checkpoint-dir are required for checkpoint")
	}
	if value.expectedGeneration == "" {
		return errors.New("--expected-generation is required for checkpoint with --operation-id")
	}
	if err := validateExpectedGeneration(value.expectedGeneration); err != nil {
		return err
	}
	if value.leaveRunning {
		return errors.New("checkpoint with --operation-id requires --leave-running=false " +
			"(identified checkpoints are stop-and-copy)")
	}
	if !filepath.IsAbs(value.checkpointDir) {
		return errors.New("--checkpoint-dir must be absolute for checkpoint with --operation-id")
	}
	if value.checkpointTimeoutSeconds < 1 ||
		value.checkpointTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
		return fmt.Errorf(
			"--checkpoint-timeout-seconds must be between 1 and %d for checkpoint with --operation-id",
			checkpointOperationMaxTimeoutSeconds,
		)
	}
	wrapped := &runtime.CheckpointWithOperationRequest{
		OperationID:        value.operationID,
		Checkpoint:         request,
		ExpectedGeneration: value.expectedGeneration,
	}
	digest, err := checkpointOperationRequestDigest(wrapped)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	status, err := client.CheckpointWithOperation(ctx, wrapped)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	return reportCheckpointOperation(status, value, digest, out)
}

// checkpointOperationRequestDigest fingerprints a checkpoint operation request
// exactly as the service does: clone the wrapped request, drop the operation
// ID (it is the key being bound, not part of the intent), marshal
// deterministically, and hash with SHA-256. Every semantic field — sandbox ID,
// directory spelling, timeout, compression, leave_running, snapshot type, and
// the exact expected generation — is covered, so the CLI can prove the receipt
// it receives answers for the request it sent.
func checkpointOperationRequestDigest(request *runtime.CheckpointWithOperationRequest) (string, error) {
	normalized := proto.Clone(request).(*runtime.CheckpointWithOperationRequest)
	normalized.OperationID = ""
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("encode checkpoint operation request deterministically: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// validStrictHex64Digest accepts exactly 64 lowercase hex characters. Every
// digest the service records — the bound request digest and the sealed
// artifact root alike — is the lowercase hex encoding of a SHA-256, so an
// uppercase or malformed value in a reply is a protocol error to reject, not
// a spelling to normalize.
func validStrictHex64Digest(digest string) bool {
	if len(digest) != checkpointroot.DigestHexLen {
		return false
	}
	for index := 0; index < len(digest); index++ {
		character := digest[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// validCheckpointOperationState reports whether a reply carries one of the
// states a healthy daemon answers with; UNSPECIFIED and out-of-range values
// are protocol errors, never records to reconcile against.
func validCheckpointOperationState(state runtime.CheckpointOperationState) bool {
	switch state {
	case runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING,
		runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED,
		runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED,
		runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN:
		return true
	default:
		return false
	}
}

// validCheckpointOperationRecoveryProtocol reports whether a reply carries a
// recovery protocol this build understands. The protocol is a record
// property, never content: a legacy UNSPECIFIED record, a WITNESS record,
// and a WITNESS_ABORTABLE record are all legal history wherever facts are
// compared, so none is normalized away — but an out-of-range value is a
// protocol error. An unsupported protocol must be rejected, never
// reinterpreted as the legacy one, because whether a record holds runtime
// evidence decides what may be recovered from it.
func validCheckpointOperationRecoveryProtocol(
	protocol runtime.CheckpointOperationRecoveryProtocol,
) bool {
	switch protocol {
	case runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED,
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS,
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE:
		return true
	default:
		return false
	}
}

// witnessCapableCheckpointProtocol reports whether a record admitted under
// this protocol holds runtime evidence an explicit reconciliation can act
// on: WITNESS and WITNESS_ABORTABLE records are both eligible for
// RecoverCheckpointOperation, while a legacy record holds no witness and is
// refused by the service before any reply.
func witnessCapableCheckpointProtocol(
	protocol runtime.CheckpointOperationRecoveryProtocol,
) bool {
	switch protocol {
	case runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS,
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE:
		return true
	default:
		return false
	}
}

// validateAbortConfirmedShape enforces the one structural rule of
// abort_confirmed across every receipt consumer: the durable abort fact may
// be restated only by a FAILED record under the WITNESS_ABORTABLE protocol,
// without a sealed root. A SUCCEEDED record carrying it is contradictory —
// a confirmed abort never produces a checkpoint success — no matter how
// valid its root is, and no other state or protocol may claim it. The field
// is never more than shape here: a legal abort_confirmed=true proves no
// release, which stays evidence_released's per-call fact.
func validateAbortConfirmedShape(
	status *runtime.CheckpointOperationStatus,
	caller string,
) error {
	if !status.GetAbortConfirmed() {
		return nil
	}
	if status.GetState() == runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED &&
		status.GetRecoveryProtocol() ==
			runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE &&
		status.GetArtifactRootDigest() == "" && status.GetArtifactRootScheme() == "" {
		return nil
	}
	return fmt.Errorf(
		"%s: reply reports abort_confirmed=true on a %s record under recovery protocol %s; malformed reply",
		caller, status.GetState(), status.GetRecoveryProtocol(),
	)
}

// checkpointOperationIdentityConflict names the first way a reply fails to
// answer for exactly the request the CLI just sent: the echoed operation and
// sandbox identities, the bound source generation, the canonical form of the
// requested directory, and the digest of the very request just sent. caller
// prefixes every message so the failing action stays identifiable. Identity
// is all it checks — state, sealed-root, protocol, and release evidence are
// each action's separate contract.
func checkpointOperationIdentityConflict(
	status *runtime.CheckpointOperationStatus,
	value options,
	digest string,
	caller string,
) string {
	if status == nil {
		return caller + ": empty operation status"
	}
	if status.GetOperationID() != value.operationID {
		return fmt.Sprintf(
			"%s: status operation_id %q does not match requested %q",
			caller, status.GetOperationID(), value.operationID,
		)
	}
	if status.GetSandboxID() != value.sandboxID {
		return fmt.Sprintf(
			"%s: status sandbox_id %q does not match requested %q",
			caller, status.GetSandboxID(), value.sandboxID,
		)
	}
	if status.GetSourceGeneration() != value.expectedGeneration {
		return fmt.Sprintf(
			"%s: status source_generation %q does not match requested %q",
			caller, status.GetSourceGeneration(), value.expectedGeneration,
		)
	}
	if canonical := filepath.Clean(value.checkpointDir); status.GetCheckpointDir() != canonical {
		return fmt.Sprintf(
			"%s: status checkpoint_dir %q does not match the canonical form %q of the requested directory",
			caller, status.GetCheckpointDir(), canonical,
		)
	}
	if status.GetRequestDigest() != digest {
		return fmt.Sprintf(
			"%s: status request_digest %q does not match the digest %q of the request just sent",
			caller, status.GetRequestDigest(), digest,
		)
	}
	return ""
}

// reportCheckpointOperation turns a CheckpointWithOperation reply into the
// identified checkpoint's entire stdout contract, and only a proven SUCCEEDED
// receipt for exactly the requested identity exits zero. The identity checks
// — operation ID, sandbox ID, source generation, canonical directory, and the
// digest of the very request just sent — run before any output, so a receipt
// for another intent never reaches stdout. RUNNING, FAILED, and UNKNOWN are
// printed first (their state field says not-succeeded) so the caller can
// reconcile the spent operation ID, then reported as an error. A receipt that
// claims SUCCEEDED without a strict lowercase hex64 sealed root under the
// shared checkpoint-root scheme proves nothing, so it fails without output: a
// success-shaped record followed by an error is exactly the partial success
// output a caller must never have to disambiguate.
//
// evidence_released is serialized but never gated here: a first-issue success
// that acknowledged in the same call reports true and needs nothing further,
// while a replay of a durable success reports false by construction — the
// checkpoint DID succeed, so the CLI reports that fact and the release gate
// belongs to the caller that requires it (the explicit recovery action).
func reportCheckpointOperation(
	status *runtime.CheckpointOperationStatus,
	value options,
	digest string,
	out io.Writer,
) error {
	if conflict := checkpointOperationIdentityConflict(status, value, digest, "checkpoint"); conflict != "" {
		return errors.New(conflict)
	}
	if !validCheckpointOperationState(status.GetState()) {
		return fmt.Errorf("checkpoint: invalid record state %d", status.GetState())
	}
	if !validCheckpointOperationRecoveryProtocol(status.GetRecoveryProtocol()) {
		return fmt.Errorf(
			"checkpoint: reply reports unrecognized recovery protocol %d; refusing to treat an unknown protocol as legacy",
			status.GetRecoveryProtocol(),
		)
	}
	if err := validateAbortConfirmedShape(status, "checkpoint"); err != nil {
		return err
	}
	if status.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED {
		if status.GetArtifactRootDigest() != "" || status.GetArtifactRootScheme() != "" {
			return fmt.Errorf(
				"checkpoint: %s record carries a sealed root; malformed reply",
				status.GetState(),
			)
		}
		if err := printCheckpointOperationStatus(status, out); err != nil {
			return err
		}
		return fmt.Errorf(
			"checkpoint: operation state %s is not SUCCEEDED; reconcile operation %q before issuing a new one",
			status.GetState(),
			value.operationID,
		)
	}
	if !validStrictHex64Digest(status.GetArtifactRootDigest()) {
		return fmt.Errorf(
			"checkpoint: SUCCEEDED record must carry a strict lowercase hex64 artifact_root_digest, got %q",
			status.GetArtifactRootDigest(),
		)
	}
	if status.GetArtifactRootScheme() != checkpointroot.Scheme {
		return fmt.Errorf(
			"checkpoint: SUCCEEDED record root scheme %q is not %q",
			status.GetArtifactRootScheme(),
			checkpointroot.Scheme,
		)
	}
	return printCheckpointOperationStatus(status, out)
}

// getCheckpointOperation queries one durable checkpoint operation record and
// nothing else: it never executes work, never reads artifacts, and never
// inspects the source sandbox, so a historical SUCCEEDED is printed verbatim
// as the recorded fact it is. The reply must be a well-formed record — a
// bound identity, a canonical directory, a strict request digest, a known
// state, and the sealed root exactly on SUCCEEDED and nowhere else — and it
// must echo the queried operation ID; anything else is a protocol error
// without stdout output. A query answer alone does not prove the record binds
// the caller's request payload: reconciling that is the caller's replay, not
// this query.
func getCheckpointOperation(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
	out io.Writer,
) error {
	if value.operationID == "" {
		return errors.New("--operation-id is required for get-checkpoint-operation")
	}
	if err := validateOperationIDFormat(value.operationID); err != nil {
		return err
	}
	status, err := client.GetCheckpointOperation(ctx, &runtime.GetCheckpointOperationRequest{
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
			return fmt.Errorf("get-checkpoint-operation: %w: %w", errCheckpointOperationNotFound, err)
		}
		return fmt.Errorf("get-checkpoint-operation: %w", err)
	}
	if err := validateCheckpointOperationRecordReply(status, value.operationID); err != nil {
		return err
	}
	return printCheckpointOperationStatus(status, out)
}

// recoverCheckpointOperation runs the explicit recovery of one ALREADY
// recorded checkpoint operation. The request reconstructs the COMPLETE
// original CheckpointWithOperation payload from the same flags that first
// issued it — sandbox ID, directory spelling, original checkpoint timeout,
// compression, leave_running, snapshot type, and the exact expected
// generation — and carries it unchanged inside RecoverCheckpointOperationRequest
// beside an independent recovery timeout. The recovery timeout bounds only
// this reconciliation attempt; the ORIGINAL checkpoint timeout keeps its role
// in the request digest, so the two flags are never substituted for one
// another, and the digest the CLI validates against is computed from the
// reconstructed original payload alone.
//
// There is deliberately no fallback and no structured not-found answer: any
// RPC failure — Unimplemented from an older server, a transport error, a
// deadline, a refused legacy or FAILED record included — is terminal. A
// recovery targets an operation the caller already holds a record for;
// callers reconciling a possibly-absent record use the query action. After
// one RPC error the only next step is querying or recovering the same
// operation ID again, never re-issuing an older checkpoint RPC.
func recoverCheckpointOperation(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
	out io.Writer,
) error {
	if err := validateOperationIDFormat(value.operationID); err != nil {
		return err
	}
	if value.sandboxID == "" || value.checkpointDir == "" {
		return errors.New("--sandbox-id and --checkpoint-dir are required for " +
			"recover-checkpoint-operation")
	}
	if value.expectedGeneration == "" {
		return errors.New("--expected-generation is required for " +
			"recover-checkpoint-operation (it repeats the ORIGINAL operation binding)")
	}
	if err := validateExpectedGeneration(value.expectedGeneration); err != nil {
		return err
	}
	if value.leaveRunning {
		return errors.New("recover-checkpoint-operation requires --leave-running=false " +
			"(the original identified checkpoint was stop-and-copy, and the recovery " +
			"repeats its exact payload)")
	}
	if !filepath.IsAbs(value.checkpointDir) {
		return errors.New("--checkpoint-dir must be absolute for recover-checkpoint-operation")
	}
	if value.checkpointTimeoutSeconds < 1 ||
		value.checkpointTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
		return fmt.Errorf(
			"--checkpoint-timeout-seconds must be between 1 and %d for "+
				"recover-checkpoint-operation (it repeats the ORIGINAL checkpoint timeout, "+
				"which the request digest covers)",
			checkpointOperationMaxTimeoutSeconds,
		)
	}
	if value.recoveryTimeoutSeconds < 1 ||
		value.recoveryTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
		return fmt.Errorf(
			"--recovery-timeout-seconds must be between 1 and %d for "+
				"recover-checkpoint-operation",
			checkpointOperationMaxTimeoutSeconds,
		)
	}
	original := &runtime.CheckpointWithOperationRequest{
		OperationID: value.operationID,
		Checkpoint: &runtime.CheckpointRequest{
			ID:             value.sandboxID,
			CheckpointDir:  value.checkpointDir,
			TimeoutSeconds: uint32(value.checkpointTimeoutSeconds),
			Compress:       value.compress,
			LeaveRunning:   value.leaveRunning,
			SnapshotType:   value.snapshotType,
		},
		ExpectedGeneration: value.expectedGeneration,
	}
	digest, err := checkpointOperationRequestDigest(original)
	if err != nil {
		return fmt.Errorf("recover-checkpoint-operation: %w", err)
	}
	status, err := client.RecoverCheckpointOperation(ctx, &runtime.RecoverCheckpointOperationRequest{
		Operation:              original,
		RecoveryTimeoutSeconds: uint32(value.recoveryTimeoutSeconds),
	})
	if err != nil {
		return fmt.Errorf("recover-checkpoint-operation: %w", err)
	}
	return reportRecoveredCheckpointOperation(status, value, digest, out)
}

// reportRecoveredCheckpointOperation turns a RecoverCheckpointOperation reply
// into the recovery action's entire stdout contract. A zero exit proves the
// strongest fact this action exists for, all of it from THIS response: the
// operation is SUCCEEDED for exactly the reconstructed original request, the
// record reports a witness-capable recovery protocol — WITNESS or
// WITNESS_ABORTABLE; explicit recovery is defined for those records only,
// and the service refuses legacy ones before replying, so a reply claiming
// otherwise is a protocol error — and this invocation completed the runtime
// acknowledgment — evidence_released=true — which is the release of the
// evidence-retention gate the caller recovers
// for. A SUCCEEDED receipt without that release proof is printed first — the
// success fact may be durable and worth reconciling — and then reported as
// an error, exactly like every non-SUCCEEDED state, so a zero exit can never
// be mistaken for a completed release.
func reportRecoveredCheckpointOperation(
	status *runtime.CheckpointOperationStatus,
	value options,
	digest string,
	out io.Writer,
) error {
	const caller = "recover-checkpoint-operation"
	if conflict := checkpointOperationIdentityConflict(status, value, digest, caller); conflict != "" {
		return errors.New(conflict)
	}
	if !validCheckpointOperationState(status.GetState()) {
		return fmt.Errorf("%s: invalid record state %d", caller, status.GetState())
	}
	if !validCheckpointOperationRecoveryProtocol(status.GetRecoveryProtocol()) {
		return fmt.Errorf(
			"%s: reply reports unrecognized recovery protocol %d; refusing to treat an unknown protocol as legacy",
			caller, status.GetRecoveryProtocol(),
		)
	}
	if !witnessCapableCheckpointProtocol(status.GetRecoveryProtocol()) {
		return fmt.Errorf(
			"%s: record reports recovery protocol %s, but explicit recovery is defined for witness-capable records only "+
				"(legacy records are refused by the service and cannot be recovered)",
			caller, status.GetRecoveryProtocol(),
		)
	}
	if err := validateAbortConfirmedShape(status, caller); err != nil {
		return err
	}
	if status.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED {
		if status.GetArtifactRootDigest() != "" || status.GetArtifactRootScheme() != "" {
			return fmt.Errorf(
				"%s: %s record carries a sealed root; malformed reply",
				caller, status.GetState(),
			)
		}
		if err := printCheckpointOperationStatus(status, out); err != nil {
			return err
		}
		return fmt.Errorf(
			"%s: operation state %s is not SUCCEEDED; the attempt reconciled nothing and the operation ID is unchanged",
			caller, status.GetState(),
		)
	}
	if !validStrictHex64Digest(status.GetArtifactRootDigest()) {
		return fmt.Errorf(
			"%s: SUCCEEDED record must carry a strict lowercase hex64 artifact_root_digest, got %q",
			caller, status.GetArtifactRootDigest(),
		)
	}
	if status.GetArtifactRootScheme() != checkpointroot.Scheme {
		return fmt.Errorf(
			"%s: SUCCEEDED record root scheme %q is not %q",
			caller, status.GetArtifactRootScheme(), checkpointroot.Scheme,
		)
	}
	if !status.GetEvidenceReleased() {
		// The success may be durable, but THIS call did not complete the
		// acknowledgment — a recovery answering false releases nothing, and
		// treating it as complete would unbind the evidence gate from any
		// proven fact. Print the record for reconciliation, then fail.
		if err := printCheckpointOperationStatus(status, out); err != nil {
			return err
		}
		return fmt.Errorf(
			"%s: SUCCEEDED record reports evidence_released=false — this response did not complete the runtime acknowledgment; the release of the retained evidence is unproven, retry the recovery of operation %q",
			caller, value.operationID,
		)
	}
	return printCheckpointOperationStatus(status, out)
}

// abortCheckpointOperation runs the explicit abort of one ALREADY recorded
// checkpoint operation admitted under the witness-abortable protocol. Like
// the recovery, the request reconstructs the COMPLETE original
// CheckpointWithOperation payload from the same flags that first issued it —
// sandbox ID, directory spelling, original checkpoint timeout, compression,
// leave_running, snapshot type, and the exact expected generation — and
// carries it unchanged inside AbortCheckpointOperationRequest beside an
// independent abort timeout. The abort timeout bounds only this attempt; the
// ORIGINAL checkpoint timeout keeps its role in the request digest, so the
// two flags are never substituted for one another, and the digest the CLI
// validates against is computed from the reconstructed original payload
// alone.
//
// There is deliberately no fallback and no structured not-found answer: any
// RPC failure — Unimplemented from a server that predates the abort RPC or
// has not wired it yet, a transport error, a deadline, a refused legacy,
// WITNESS-only, or non-FAILED record included — is terminal, and no other
// checkpoint or recovery RPC is ever attempted. After one RPC error the only
// next step is querying the same operation ID again.
func abortCheckpointOperation(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
	out io.Writer,
) error {
	if err := validateOperationIDFormat(value.operationID); err != nil {
		return err
	}
	if value.sandboxID == "" || value.checkpointDir == "" {
		return errors.New("--sandbox-id and --checkpoint-dir are required for " +
			"abort-checkpoint-operation")
	}
	if value.expectedGeneration == "" {
		return errors.New("--expected-generation is required for " +
			"abort-checkpoint-operation (it repeats the ORIGINAL operation binding)")
	}
	if err := validateExpectedGeneration(value.expectedGeneration); err != nil {
		return err
	}
	if value.leaveRunning {
		return errors.New("abort-checkpoint-operation requires --leave-running=false " +
			"(the original identified checkpoint was stop-and-copy, and the abort " +
			"repeats its exact payload)")
	}
	if !filepath.IsAbs(value.checkpointDir) {
		return errors.New("--checkpoint-dir must be absolute for abort-checkpoint-operation")
	}
	if value.checkpointTimeoutSeconds < 1 ||
		value.checkpointTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
		return fmt.Errorf(
			"--checkpoint-timeout-seconds must be between 1 and %d for "+
				"abort-checkpoint-operation (it repeats the ORIGINAL checkpoint timeout, "+
				"which the request digest covers)",
			checkpointOperationMaxTimeoutSeconds,
		)
	}
	if value.abortTimeoutSeconds < 1 ||
		value.abortTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
		return fmt.Errorf(
			"--abort-timeout-seconds must be between 1 and %d for "+
				"abort-checkpoint-operation",
			checkpointOperationMaxTimeoutSeconds,
		)
	}
	original := &runtime.CheckpointWithOperationRequest{
		OperationID: value.operationID,
		Checkpoint: &runtime.CheckpointRequest{
			ID:             value.sandboxID,
			CheckpointDir:  value.checkpointDir,
			TimeoutSeconds: uint32(value.checkpointTimeoutSeconds),
			Compress:       value.compress,
			LeaveRunning:   value.leaveRunning,
			SnapshotType:   value.snapshotType,
		},
		ExpectedGeneration: value.expectedGeneration,
	}
	digest, err := checkpointOperationRequestDigest(original)
	if err != nil {
		return fmt.Errorf("abort-checkpoint-operation: %w", err)
	}
	status, err := client.AbortCheckpointOperation(ctx, &runtime.AbortCheckpointOperationRequest{
		Operation:           original,
		AbortTimeoutSeconds: uint32(value.abortTimeoutSeconds),
	})
	if err != nil {
		return fmt.Errorf("abort-checkpoint-operation: %w", err)
	}
	return reportAbortedCheckpointOperation(status, value, digest, out)
}

// reportAbortedCheckpointOperation turns an AbortCheckpointOperation reply
// into the abort action's entire stdout contract. A zero exit proves, all of
// it from THIS response: the operation is FAILED for exactly the
// reconstructed original request — an explicit abort never produces a
// success — the record reports the WITNESS_ABORTABLE recovery protocol (the
// abort is defined for those records only; the service refuses legacy,
// WITNESS-only, and non-FAILED records before replying, so a reply claiming
// otherwise is a protocol error), the durable abort fact is confirmed —
// abort_confirmed=true — and THIS invocation completed the evidence release
// — evidence_released=true, the per-call fact. The two are deliberately not
// interchangeable: abort_confirmed is restated by every later reply and a
// historical true proves no release, so a FAILED receipt missing either is
// printed first — the failure fact is worth reconciling — and then reported
// as an error, exactly like every non-FAILED state, so a zero exit can never
// be mistaken for anything but a fully acknowledged abort. A confirmed abort
// stays a failure: it authorizes no checkpoint success and no artifact.
func reportAbortedCheckpointOperation(
	status *runtime.CheckpointOperationStatus,
	value options,
	digest string,
	out io.Writer,
) error {
	const caller = "abort-checkpoint-operation"
	if conflict := checkpointOperationIdentityConflict(status, value, digest, caller); conflict != "" {
		return errors.New(conflict)
	}
	if !validCheckpointOperationState(status.GetState()) {
		return fmt.Errorf("%s: invalid record state %d", caller, status.GetState())
	}
	if !validCheckpointOperationRecoveryProtocol(status.GetRecoveryProtocol()) {
		return fmt.Errorf(
			"%s: reply reports unrecognized recovery protocol %d; refusing to treat an unknown protocol as legacy",
			caller, status.GetRecoveryProtocol(),
		)
	}
	if status.GetRecoveryProtocol() !=
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE {
		return fmt.Errorf(
			"%s: record reports recovery protocol %s, but the explicit abort is defined for WITNESS_ABORTABLE records only "+
				"(legacy and WITNESS records are refused by the service and cannot be aborted)",
			caller, status.GetRecoveryProtocol(),
		)
	}
	if status.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED {
		// A SUCCEEDED record legitimately carries its sealed root; RUNNING
		// and UNKNOWN must not. Every non-FAILED answer is printed for
		// reconciliation — the abort confirmed nothing — and then fails.
		if status.GetArtifactRootDigest() != "" || status.GetArtifactRootScheme() != "" {
			if status.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED {
				return fmt.Errorf(
					"%s: %s record carries a sealed root; malformed reply",
					caller, status.GetState(),
				)
			}
		}
		if err := printCheckpointOperationStatus(status, out); err != nil {
			return err
		}
		return fmt.Errorf(
			"%s: operation state %s is not FAILED; the abort was not confirmed and the operation ID is unchanged",
			caller, status.GetState(),
		)
	}
	if status.GetArtifactRootDigest() != "" || status.GetArtifactRootScheme() != "" {
		return fmt.Errorf(
			"%s: FAILED record carries a sealed root; malformed reply",
			caller,
		)
	}
	// The durable abort fact and this call's release are deliberately both
	// demanded: a confirmed abort without the release leaves the evidence
	// gate held, and a release without the confirmed abort proves no abort
	// at all. Print the record for reconciliation, then fail.
	if !status.GetAbortConfirmed() || !status.GetEvidenceReleased() {
		if err := printCheckpointOperationStatus(status, out); err != nil {
			return err
		}
		return fmt.Errorf(
			"%s: FAILED record reports abort_confirmed=%t and evidence_released=%t — this response did not complete both the abort acknowledgment and the evidence release; retry the abort of operation %q",
			caller, status.GetAbortConfirmed(), status.GetEvidenceReleased(), value.operationID,
		)
	}
	return printCheckpointOperationStatus(status, out)
}

// validateCheckpointOperationRecordReply enforces the record syntax and the
// queried-ID echo of a GetCheckpointOperation answer. It checks only what the
// query itself can prove — shape and self-consistency — and deliberately not
// whether the record matches any caller intent.
func validateCheckpointOperationRecordReply(
	status *runtime.CheckpointOperationStatus,
	operationID string,
) error {
	if status == nil {
		return errors.New("get-checkpoint-operation: empty operation status")
	}
	if status.GetOperationID() == "" || !config.IsValidSandboxID(status.GetSandboxID()) {
		return fmt.Errorf(
			"get-checkpoint-operation: malformed record with empty identity (%+v)",
			status,
		)
	}
	generation := status.GetSourceGeneration()
	if strings.TrimSpace(generation) == "" || len(generation) > maxExpectedGenerationLength {
		return fmt.Errorf(
			"get-checkpoint-operation: malformed record source_generation %q",
			generation,
		)
	}
	dir := status.GetCheckpointDir()
	if !filepath.IsAbs(dir) || dir != filepath.Clean(dir) ||
		dir == string(filepath.Separator) || len(dir) > maxCheckpointDirLength {
		return fmt.Errorf(
			"get-checkpoint-operation: malformed record checkpoint_dir %q",
			dir,
		)
	}
	if !validStrictHex64Digest(status.GetRequestDigest()) {
		return fmt.Errorf(
			"get-checkpoint-operation: malformed record request_digest %q",
			status.GetRequestDigest(),
		)
	}
	if !validCheckpointOperationState(status.GetState()) {
		return fmt.Errorf("get-checkpoint-operation: invalid record state %d", status.GetState())
	}
	// The protocol is reported by every reply, and every defined value is
	// legal history here — legacy records keep querying and replaying
	// unchanged. An out-of-range value is a protocol error: an unknown
	// protocol must not be silently read as the legacy one, because the field
	// decides which records hold recoverable runtime evidence.
	if !validCheckpointOperationRecoveryProtocol(status.GetRecoveryProtocol()) {
		return fmt.Errorf(
			"get-checkpoint-operation: reply reports unrecognized recovery protocol %d",
			status.GetRecoveryProtocol(),
		)
	}
	// abort_confirmed is validated for shape only — a legal historical true
	// (FAILED, WITNESS_ABORTABLE, no root) is printed as the durable fact it
	// is, and the query never infers a release or any outcome change from it.
	if err := validateAbortConfirmedShape(status, "get-checkpoint-operation"); err != nil {
		return err
	}
	// The sealed root is exactly the SUCCEEDED evidence: mandatory with a
	// strict lowercase hex64 digest under the shared scheme, and absent on
	// every other state.
	if status.GetState() == runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED {
		if !validStrictHex64Digest(status.GetArtifactRootDigest()) {
			return fmt.Errorf(
				"get-checkpoint-operation: SUCCEEDED record must carry a strict lowercase hex64 artifact_root_digest, got %q",
				status.GetArtifactRootDigest(),
			)
		}
		if status.GetArtifactRootScheme() != checkpointroot.Scheme {
			return fmt.Errorf(
				"get-checkpoint-operation: SUCCEEDED record root scheme %q is not %q",
				status.GetArtifactRootScheme(),
				checkpointroot.Scheme,
			)
		}
	} else if status.GetArtifactRootDigest() != "" || status.GetArtifactRootScheme() != "" {
		return fmt.Errorf(
			"get-checkpoint-operation: %s record carries a sealed root; malformed reply",
			status.GetState(),
		)
	}
	if status.GetOperationID() != operationID {
		return fmt.Errorf(
			"get-checkpoint-operation: status operation_id %q does not match requested %q",
			status.GetOperationID(),
			operationID,
		)
	}
	return nil
}

// printCheckpointOperationStatus writes one CheckpointOperationStatus to the
// output writer as protojson with snake_case field names and unpopulated
// fields emitted, so the state is always explicit for the caller's
// reconciliation. Taking an io.Writer keeps stdout and error text separable
// and lets tests capture the exact bytes.
func printCheckpointOperationStatus(
	status *runtime.CheckpointOperationStatus,
	out io.Writer,
) error {
	data, err := protojson.MarshalOptions{
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(status)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
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
		if value.action == "get-checkpoint-operation" {
			return errors.New("--operation-id is required for get-checkpoint-operation")
		}
		if value.action == "recover-checkpoint-operation" {
			return errors.New("--operation-id is required for recover-checkpoint-operation")
		}
		if value.action == "abort-checkpoint-operation" {
			return errors.New("--operation-id is required for abort-checkpoint-operation")
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
	case "checkpoint":
		// The identified checkpoint is stop-and-copy only: the service refuses
		// a leave-running request outright, so the CLI demands the explicit
		// opt-down instead of forwarding a request bound to fail — and never
		// silently sends leave_running=true under an operation identity.
		if value.sandboxID == "" || value.checkpointDir == "" {
			return errors.New("--sandbox-id and --checkpoint-dir are required for " +
				"checkpoint with --operation-id")
		}
		if value.expectedGeneration == "" {
			return errors.New("--expected-generation is required for checkpoint with --operation-id")
		}
		if value.leaveRunning {
			return errors.New("checkpoint with --operation-id requires --leave-running=false " +
				"(identified checkpoints are stop-and-copy)")
		}
		if !filepath.IsAbs(value.checkpointDir) {
			return errors.New("--checkpoint-dir must be absolute for checkpoint with --operation-id")
		}
		if value.checkpointTimeoutSeconds < 1 ||
			value.checkpointTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
			return fmt.Errorf(
				"--checkpoint-timeout-seconds must be between 1 and %d for checkpoint with --operation-id",
				checkpointOperationMaxTimeoutSeconds,
			)
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
	case "get-checkpoint-operation":
		// Same query discipline: the action answers from the operation record
		// alone, so any payload flag set here is explicit intent to be
		// rejected, not a default to silently ignore.
		if value.sandboxID != "" || value.targetID != "" || value.requestFile != "" ||
			value.checkpointDir != "" || value.rootfs != "" || value.snapshotType != "" ||
			value.workloadCmd != "" {
			return errors.New("--action get-checkpoint-operation takes only --socket, " +
				"--timeout, and --operation-id")
		}
	case "recover-checkpoint-operation":
		// The recovery repeats the ORIGINAL identified checkpoint payload, so
		// it demands exactly the same complete fixed request — the service
		// recomputes the request digest from this payload and refuses the
		// operation ID when any field changed. The original timeout keeps its
		// digest role; the recovery timeout only bounds this attempt.
		if value.sandboxID == "" || value.checkpointDir == "" {
			return errors.New("--sandbox-id and --checkpoint-dir are required for " +
				"recover-checkpoint-operation")
		}
		if value.expectedGeneration == "" {
			return errors.New("--expected-generation is required for recover-checkpoint-operation")
		}
		if value.leaveRunning {
			return errors.New("recover-checkpoint-operation requires --leave-running=false " +
				"(the original identified checkpoint was stop-and-copy)")
		}
		if !filepath.IsAbs(value.checkpointDir) {
			return errors.New("--checkpoint-dir must be absolute for recover-checkpoint-operation")
		}
		if value.checkpointTimeoutSeconds < 1 ||
			value.checkpointTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
			return fmt.Errorf(
				"--checkpoint-timeout-seconds must be between 1 and %d for recover-checkpoint-operation",
				checkpointOperationMaxTimeoutSeconds,
			)
		}
		if value.recoveryTimeoutSeconds < 1 ||
			value.recoveryTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
			return fmt.Errorf(
				"--recovery-timeout-seconds must be between 1 and %d for recover-checkpoint-operation",
				checkpointOperationMaxTimeoutSeconds,
			)
		}
	case "abort-checkpoint-operation":
		// The abort repeats the ORIGINAL identified checkpoint payload too —
		// the service recomputes the request digest from it and refuses the
		// operation ID when any field changed — and adds only its own
		// attempt bound. The original timeout keeps its digest role; the
		// abort timeout never enters the digest.
		if value.sandboxID == "" || value.checkpointDir == "" {
			return errors.New("--sandbox-id and --checkpoint-dir are required for " +
				"abort-checkpoint-operation")
		}
		if value.expectedGeneration == "" {
			return errors.New("--expected-generation is required for abort-checkpoint-operation")
		}
		if value.leaveRunning {
			return errors.New("abort-checkpoint-operation requires --leave-running=false " +
				"(the original identified checkpoint was stop-and-copy)")
		}
		if !filepath.IsAbs(value.checkpointDir) {
			return errors.New("--checkpoint-dir must be absolute for abort-checkpoint-operation")
		}
		if value.checkpointTimeoutSeconds < 1 ||
			value.checkpointTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
			return fmt.Errorf(
				"--checkpoint-timeout-seconds must be between 1 and %d for abort-checkpoint-operation",
				checkpointOperationMaxTimeoutSeconds,
			)
		}
		if value.abortTimeoutSeconds < 1 ||
			value.abortTimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
			return fmt.Errorf(
				"--abort-timeout-seconds must be between 1 and %d for abort-checkpoint-operation",
				checkpointOperationMaxTimeoutSeconds,
			)
		}
	default:
		return errors.New("--operation-id is only valid for start, restore, checkpoint, " +
			"get-start-operation, get-checkpoint-operation, recover-checkpoint-operation, " +
			"and abort-checkpoint-operation")
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
