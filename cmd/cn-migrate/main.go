// Command cn-migrate moves one running sandbox to another node with a
// stop-and-resume window: checkpoint on the source, publish to the store,
// place on a compatible peer (the source excluded — a draining node must
// never receive its own workload back), materialize and restore there, and
// only delete the source once the target is verified RUNNING.
//
// The run is pinned to one source incarnation: the generation captured from
// a structured inspect before checkpointing names the incarnation in every
// conditional operation, so a sandbox deleted and recreated on the source is
// neither snapshotted nor retired by mistake.
//
// Node commands run through an executor template (-exec) so the CLI stays
// decoupled from the cluster shape: "kubectl exec <pod> --" for the kind
// test bed, an ssh wrapper for bare metal, or a direct runner when a
// future master calls in-process. The template's {node} placeholder is
// substituted per target; commands are the existing per-node CLIs.
//
//	cn-migrate -sandbox sbox-x -exec "kubectl exec {node} --" \
//	           -source <source-node> -store http://minio:19000/bucket \
//	           [-nodes http://n1:18090,http://n2:18090] [-to <node>] [-json]
//
// Exit codes: 0 migrated, 1 failed, 2 usage error. Exit 1 alone does not
// say which side holds the sandbox — the report's error names the state
// left behind (rolled back, target-owned, or unknown target outcome).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/checkpointlocator"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"google.golang.org/protobuf/encoding/protojson"
)

// sourceGenerationLabel is the daemon-owned physical incarnation identity
// (assigned by Start, mirrored into sandbox labels). It is the value the
// conditional CheckpointIfGeneration/DeleteIfGeneration preconditions compare.
const sourceGenerationLabel = "akernel.scheduler/resource-generation"

// maxSourceGenerationBytes is the common bound for checkpoint and retirement.
// DeleteIfGeneration accepts at most 128 bytes, even though checkpoint accepts 256.
const maxSourceGenerationBytes = 128

type stepLog struct {
	Step   string `json:"step"`
	Detail string `json:"detail,omitempty"`
	TookMs int64  `json:"took_ms"`
	Failed bool   `json:"failed,omitempty"`
}

type migrateReport struct {
	Sandbox          string    `json:"sandbox"`
	Source           string    `json:"source"`
	Target           string    `json:"target,omitempty"`
	Checkpoint       string    `json:"checkpoint_dir"`
	SourceGeneration string    `json:"source_generation,omitempty"`
	MigrationID      string    `json:"migration_id,omitempty"`
	Journal          string    `json:"journal,omitempty"`
	Stage            string    `json:"stage,omitempty"`
	Steps            []stepLog `json:"steps"`
	OK               bool      `json:"ok"`
	Error            string    `json:"error,omitempty"`
}

func main() {
	sandbox := flag.String("sandbox", "", "sandbox ID to migrate")
	source := flag.String("source", "", "source node name (executor {node} value)")
	execTpl := flag.String("exec", "", "node command executor template with {node} placeholder")
	storeSpec := flag.String("store", "", "chunk store spec (http://endpoint/bucket or directory)")
	nodes := flag.String("nodes", "", "comma-separated node catalog addresses for placement")
	to := flag.String("to", "", "preferred target node name (default: locator decides)")
	srcGen := flag.String("source-generation", "", "require this source generation label (default: the value captured from source inspect)")
	journalPath := flag.String("journal", "", "durable migration journal file (absolute path; paired with -migration-id it enables the resumable mode)")
	migrationID := flag.String("migration-id", "", "stable migration identity for the resumable mode (paired with -journal; derives the checkpoint directory and target operation ID)")
	ckReq := flag.String("request-file", "/mnt/cn/ck/req.json", "StartRequest JSON for the restore")
	bin := flag.String("bin", "/mnt/cn/bin", "per-node CLI binary directory")
	wait := flag.Duration("wait", 180*time.Second, "per-step timeout")
	jsonOut := flag.Bool("json", false, "machine-readable report")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-migrate -sandbox ID -source NODE -exec TPL -store SPEC -nodes ADDR[,ADDR...] [-to NODE] [-json]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *sandbox == "" || *source == "" || *execTpl == "" || *storeSpec == "" || *nodes == "" {
		flag.Usage()
		os.Exit(2)
	}

	report := migrateReport{Sandbox: *sandbox, Source: *source, Checkpoint: migrationCheckpointDir(*sandbox)}
	// Each attempt gets its own immutable checkpoint ID: a retry must never
	// overwrite a generation a previous (possibly still-live) target already
	// restored from, and published objects stay addressable under the old ID.
	// Nanosecond granularity still admits collisions across processes; the
	// sandbox ID and run directory keep attempts practically distinct.
	report.Checkpoint = fmt.Sprintf("%s-%d", report.Checkpoint, time.Now().UnixNano())
	fail := func(step, detail string) {
		report.Error = detail
		report.Steps = append(report.Steps, stepLog{Step: step, Detail: detail, Failed: true})
		finish(report, *jsonOut, false)
	}
	var emptyProgressFlag string
	flag.Visit(func(f *flag.Flag) {
		if (f.Name == "journal" && *journalPath == "") || (f.Name == "migration-id" && *migrationID == "") {
			emptyProgressFlag = f.Name
		}
	})
	if emptyProgressFlag != "" {
		fail("arguments", "explicit -"+emptyProgressFlag+" must not be empty")
	}
	if *srcGen != "" && (strings.TrimSpace(*srcGen) == "" || len(*srcGen) > maxSourceGenerationBytes) {
		fail("arguments", "-source-generation must be non-blank and at most 128 bytes")
	}
	// The resumable mode is opt-in through the explicit, paired flags. Every
	// derived-identity rule is enforced here, before any node command: an
	// invalid pair must never reach a node, because the first side effect
	// would already be naming a migration identity.
	if (*journalPath == "") != (*migrationID == "") {
		fail("arguments", "-journal and -migration-id must be passed together to enable the resumable migration mode")
	}
	if *journalPath != "" {
		if !filepath.IsAbs(*journalPath) {
			fail("arguments", "-journal must be an absolute path")
		}
		if err := validateMigrationID(*migrationID); err != nil {
			fail("arguments", err.Error())
		}
		if *to == *source {
			fail("arguments", fmt.Sprintf("target -to %s equals the source node", *to))
		}
		runResumableMigration(resumableConfig{
			sandbox:     *sandbox,
			source:      *source,
			execTpl:     *execTpl,
			storeSpec:   *storeSpec,
			nodes:       *nodes,
			to:          *to,
			srcGen:      *srcGen,
			ckReq:       *ckReq,
			bin:         *bin,
			wait:        *wait,
			jsonOut:     *jsonOut,
			journalPath: *journalPath,
			migrationID: *migrationID,
		})
		return
	}
	// run executes one node command; success is the exit status, not the
	// output — several CLIs print nothing on success.
	run := func(node, step string, args ...string) (string, bool) {
		started := time.Now()
		tpl := strings.ReplaceAll(*execTpl, "{node}", node)
		full := append(strings.Fields(tpl), args...)
		ctx, cancel := context.WithTimeout(context.Background(), *wait)
		defer cancel()
		cmd := exec.CommandContext(ctx, full[0], full[1:]...)
		out, err := cmd.CombinedOutput()
		trimmed := strings.TrimSpace(string(out))
		report.Steps = append(report.Steps, stepLog{
			Step: step, Detail: trimmed, TookMs: time.Since(started).Milliseconds(), Failed: err != nil,
		})
		return trimmed, err == nil
	}
	// Ownership phases gate the compensation path (F2): rolling the source
	// back is only safe while nothing has been started on the target. Once
	// the restore command has been issued the target may be running even if
	// its response was lost — and nothing this CLI can observe proves the
	// request dead: a delete followed by an absent listing does not cancel
	// an in-flight restore — so compensation stops entirely and the operator
	// resolves the target; once the target is verified RUNNING it owns the
	// sandbox outright and the only legal failure mode left is
	// source-cleanup-pending.
	const (
		phaseCheckpointing   = iota // checkpoint in flight; outcome unknown on failure
		phaseSourceOwned            // checkpoint sealed; target untouched; rollback is safe
		phaseTargetRestoring        // restore issued; outcome unknown; no automatic compensation
		phaseTargetOwned            // target verified RUNNING; never roll back
	)
	phase := phaseCheckpointing
	rollbackSource := func(detail string) string {
		if _, ok := run(*source, "rollback-restore", *bin+"/checkpoint-restore",
			"--action", "restore", "--socket", "/run/sandboxd/sandboxd.sock",
			"--target-id", *sandbox, "--request-file", *ckReq,
			"--checkpoint-dir", report.Checkpoint); ok {
			return detail + " (rolled back: source restored and running from local checkpoint)"
		}
		return detail + " (ROLLBACK FAILED — source finalized; checkpoint preserved at " +
			report.Checkpoint + " on source for manual recovery)"
	}
	failPastCheckpoint := func(step, detail string) {
		switch phase {
		case phaseSourceOwned:
			detail = rollbackSource(detail)
		case phaseTargetRestoring:
			// The restore response (or the verify listing) never arrived;
			// the target may already be running the sandbox. No command
			// this CLI can issue proves the in-flight restore was dropped
			// (a delete plus an empty listing is not such a proof), so any
			// automatic compensation — deleting the target or restoring
			// the source — could destroy the only live copy or create a
			// second writer. Fail closed: issue neither, keep the
			// checkpoint and the target as they are, and let the operator
			// resolve the pending restore / the actual writer first.
			detail += " (TARGET OUTCOME UNKNOWN — no rollback and no target delete: an in-flight restore cannot be proven cancelled; checkpoint " +
				report.Checkpoint + " and target " + report.Target +
				" are preserved. Resolve the pending restore or the actual writer on the target first, then recover manually)"
		case phaseTargetOwned:
			detail += " (target verified RUNNING and owns the sandbox; no rollback — retry conditional retirement with the captured source generation to finish cleanup)"
		}
		fail(step, detail)
	}

	// 1. Confirm the sandbox is running on the source.
	if _, ok := run(*source, "list", *bin+"/sbox", "--address", "/run/sandboxd/sandboxd.sock", "list"); !ok {
		fail("list", "source listing failed")
	}
	if !listHasRunningSandbox(report.lastDetail(), *sandbox) {
		fail("list", fmt.Sprintf("sandbox %s not RUNNING on source %s", *sandbox, *source))
	}
	if *to == *source {
		fail("place", fmt.Sprintf("target -to %s equals the source node", *to))
	}

	// 2. Pin the incarnation this migration owns. The listing above is only
	// an existence probe; the generation every later conditional operation
	// names comes from a structured inspect of this one sandbox. A node (or
	// CLI build) that cannot produce that identity fails here, before any
	// checkpoint: a bare-ID checkpoint would snapshot whatever incarnation
	// happens to hold the ID now.
	if _, ok := run(*source, "inspect", *bin+"/sbox",
		"--address", "/run/sandboxd/sandboxd.sock", "inspect", *sandbox); !ok {
		fail("inspect", "source inspect failed — cannot pin the source generation; refusing to checkpoint")
	}
	generation, genErr := sourceGeneration(report.lastDetail(), *sandbox)
	if genErr != nil {
		fail("inspect", fmt.Sprintf("cannot pin the source generation: %v", genErr))
	}
	if *srcGen != "" && *srcGen != generation {
		fail("inspect", fmt.Sprintf(
			"source %s holds generation %q but -source-generation requires %q — the sandbox was replaced on the source; refusing to checkpoint the replacement",
			*source, generation, *srcGen))
	}
	report.SourceGeneration = generation

	// 3. Checkpoint it, conditionally on the pinned generation: the server
	// refuses a replaced incarnation before allocating any checkpoint
	// output, so this run can never seal an incarnation it did not name.
	// --leave-running=false gives stop-and-copy semantics: the source
	// freezes at the checkpoint instant, sandboxd finalizes it after the
	// seal, and no post-checkpoint write can be lost or double-applied. A
	// failed command does NOT prove the server never executed it (timeout,
	// lost reply): probe the source before claiming anything about its
	// state (F2).
	if _, ok := run(*source, "checkpoint", *bin+"/checkpoint-restore",
		"--action", "checkpoint", "--socket", "/run/sandboxd/sandboxd.sock",
		"--request-file", *ckReq, "--sandbox-id", *sandbox,
		"--checkpoint-dir", report.Checkpoint, "--compress=false",
		"--leave-running=false",
		"--expected-generation", report.SourceGeneration); !ok {
		if out, ok2 := run(*source, "probe-source", *bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "list"); ok2 &&
			listHasRunningSandbox(out, *sandbox) {
			fail("checkpoint", "checkpoint failed; source probe still observes the sandbox RUNNING — the checkpoint request's outcome is unknown (a failed command does not prove it was not executed) and no further action is taken here")
		}
		fail("checkpoint", "checkpoint failed; the source does not confirm the sandbox RUNNING (probe unreachable or not RUNNING) — the checkpoint request's outcome is unknown; the sealed local checkpoint at "+
			report.Checkpoint+" (if complete) supports a manual rollback-restore")
	}
	phase = phaseSourceOwned

	// 4. Publish on the source node (paths are node-local; the executor
	// runs cn-publish where the checkpoint landed, idempotent either way).
	if _, ok := run(*source, "publish", *bin+"/cn-publish",
		"-checkpoint-dir", report.Checkpoint, "-store", *storeSpec); !ok {
		failPastCheckpoint("publish", "cn-publish failed on source")
	}

	// 5. Place: federate node records, decide with the source excluded.
	nodeRecords, fetchErrs := checkpointlocator.FetchAll(context.Background(), strings.Split(*nodes, ","))
	_ = fetchErrs
	// The compat tuple comes from a catalog that lists the checkpoint —
	// normally the source node's; try every address since the orchestrator
	// stays filesystem-free either way.
	var compat *checkpointlocator.CheckpointCompat
	var compatErr error
	for _, addr := range strings.Split(*nodes, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		var c *checkpointlocator.CheckpointCompat
		c, compatErr = checkpointlocator.FetchCheckpointCompat(context.Background(), addr, dirBase(report.Checkpoint))
		if compatErr == nil {
			compat = c
			break
		}
	}
	if compatErr != nil {
		failPastCheckpoint("place", compatErr.Error())
	}
	// An explicit -to is honored by making it the only eligible candidate:
	// the locator still applies the compat gate, so an incompatible or
	// draining pick fails here instead of silently overriding safety.
	exclude := []string{*source}
	if *to != "" {
		exclude = append(exclude, nodeIDsExcept(nodeRecords, *source, *to)...)
	}
	placement, err := checkpointlocator.Decide(checkpointlocator.Input{
		CheckpointID:     dirBase(report.Checkpoint),
		Compat:           compat,
		OriginNodeID:     *source,
		ExcludeNodes:     exclude,
		RequirePublished: true,
		PublishState:     checkpointpublish.StatePublished,
		Nodes:            nodeRecords,
	})
	if err != nil {
		failPastCheckpoint("place", err.Error())
	}
	report.Target = placement.NodeID

	// 6. Materialize + restore on the target.
	if _, ok := run(placement.NodeID, "materialize", *bin+"/cn-fetch",
		"-into", report.Checkpoint, "-id", dirBase(report.Checkpoint), "-store", *storeSpec); !ok {
		failPastCheckpoint("materialize", "cn-fetch failed on target")
	}
	// The restore command is about to be issued: from here a lost or
	// failed reply does not mean the target stayed down, and nothing this
	// CLI can observe proves the request dead — so every failure until
	// the target is verified RUNNING is reported as TARGET OUTCOME
	// UNKNOWN and compensation stops; past verification the target owns
	// the sandbox (F2).
	phase = phaseTargetRestoring
	if _, ok := run(placement.NodeID, "restore", *bin+"/checkpoint-restore",
		"--action", "restore", "--socket", "/run/sandboxd/sandboxd.sock",
		"--target-id", *sandbox, "--request-file", *ckReq,
		"--checkpoint-dir", report.Checkpoint); !ok {
		failPastCheckpoint("restore", "restore failed on target")
	}

	// 7. Verify RUNNING on the target before declaring success. Parse the
	// tab-separated listing instead of substring matching: a plain
	// strings.Contains would also match longer IDs sharing a prefix.
	verified := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := run(placement.NodeID, "verify", *bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "list"); ok &&
			listHasRunningSandbox(report.lastDetail(), *sandbox) {
			verified = true
			break
		}
		time.Sleep(3 * time.Second)
	}
	if !verified {
		failPastCheckpoint("verify", "target never reported the sandbox running")
	}
	// The target is confirmed RUNNING: it owns the sandbox from here on,
	// and no later failure may resurrect the source (F2).
	phase = phaseTargetOwned

	// 8. Retire the source copy. With --leave-running=false the source was
	// already finalized at checkpoint time; the conditional delete remains
	// as an idempotent confirmation — a completed retirement receipt for
	// the pinned generation replays as success. Its failure is fatal
	// (source-cleanup-pending): a lingering copy would be a second writer.
	// There is deliberately no fallback. An unconditional sbox delete could
	// retire a replacement incarnation that reused the ID, and an empty
	// listing is an absence observation, not a retirement proof — neither
	// may substitute for the generation-scoped receipt.
	if _, ok := run(*source, "delete-source", *bin+"/checkpoint-restore",
		"--action", "delete", "--socket", "/run/sandboxd/sandboxd.sock",
		"--sandbox-id", *sandbox,
		"--expected-generation", report.SourceGeneration); !ok {
		failPastCheckpoint("delete-source",
			"source-cleanup-pending: conditional retirement of generation "+report.SourceGeneration+
				" failed — retry the same generation-scoped delete (a completed receipt replays) or reconcile the receipt manually; an unconditional delete must not be used")
	}
	report.OK = true
	finish(report, *jsonOut, true)
}

func (r *migrateReport) lastDetail() string {
	if len(r.Steps) == 0 {
		return ""
	}
	return r.Steps[len(r.Steps)-1].Detail
}

// listHasRunningSandbox additionally requires the row to report the
// SANDBOX_STATE_RUNNING state, so a half-created or exited sandbox cannot
// pass verification.
func listHasRunningSandbox(listOutput, sandboxID string) bool {
	return sandboxListState(listOutput, sandboxID) == "SANDBOX_STATE_RUNNING"
}

// sourceGeneration reads one complete `sbox inspect` result — the marshaled
// runtime.SandboxStatus of exactly one sandbox — and returns the incarnation
// identity (akernel.scheduler/resource-generation label) the migration will
// checkpoint and later retire.
//
// The whole trimmed output must parse as that single JSON value: strict
// protojson rejects free text around the document, trailing content, and
// unknown fields, so a warning line or a scraped fragment fails instead of
// being guessed at. Every shape sbox emits for the state field is accepted —
// the enum name string, its number, or omission, since
// SANDBOX_STATE_RUNNING is the proto3 zero value and encoding/json omits it.
func sourceGeneration(inspectOutput, sandboxID string) (string, error) {
	var status runtime.SandboxStatus
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(inspectOutput), &status); err != nil {
		return "", fmt.Errorf("parse SandboxStatus JSON: %w", err)
	}
	if status.ID != sandboxID {
		return "", fmt.Errorf("inspected id %q does not match the migrated sandbox %q", status.ID, sandboxID)
	}
	if status.State != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		return "", fmt.Errorf("inspected state %s is not SANDBOX_STATE_RUNNING", status.State)
	}
	generation := status.Labels[sourceGenerationLabel]
	if strings.TrimSpace(generation) == "" {
		return "", fmt.Errorf("no non-blank %q label — a pre-generation source node cannot be migrated safely", sourceGenerationLabel)
	}
	if len(generation) > maxSourceGenerationBytes {
		return "", fmt.Errorf("%q label is %d bytes, over the %d-byte bound", sourceGenerationLabel, len(generation), maxSourceGenerationBytes)
	}
	return generation, nil
}

// sandboxListState returns the STATUS column of the row whose ID column
// equals sandboxID exactly, or "" when absent. The listing is rendered by
// text/tabwriter, whose output pads columns with spaces (the tabs become
// alignment padding), so rows are split on whitespace: IDs and states
// contain none.
func sandboxListState(listOutput, sandboxID string) string {
	for _, line := range strings.Split(listOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == sandboxID {
			return fields[1]
		}
	}
	return ""
}

// nodeIDsExcept lists node IDs other than keepA/keepB so an explicit -to
// can be expressed through the locator's ExcludeNodes without bypassing
// its compat gate.
func nodeIDsExcept(records []checkpointlocator.NodeRecord, keepA, keepB string) []string {
	var rest []string
	for _, n := range records {
		if n.ID != keepA && n.ID != keepB {
			rest = append(rest, n.ID)
		}
	}
	return rest
}

func migrationCheckpointDir(sandbox string) string {
	return "/mnt/cn/ck/m-" + sandbox
}

func dirBase(path string) string {
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func finish(report migrateReport, jsonOut bool, ok bool) {
	if jsonOut {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Printf("migrate %s: %s -> %s ok=%v (%d steps)\n",
			report.Sandbox, report.Source, report.Target, report.OK, len(report.Steps))
		if report.Error != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", report.Error)
		}
		for _, step := range report.Steps {
			mark := "ok"
			if step.Failed {
				mark = "FAIL"
			}
			fmt.Fprintf(os.Stderr, "  [%s] %s (%dms) %s\n", mark, step.Step, step.TookMs, truncate(step.Detail, 120))
		}
	}
	if !ok {
		os.Exit(1)
	}
	os.Exit(0)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
