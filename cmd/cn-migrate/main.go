// Command cn-migrate moves one running sandbox to another node with a
// stop-and-resume window: checkpoint on the source, publish to the store,
// place on a compatible peer (the source excluded — a draining node must
// never receive its own workload back), materialize and restore there, and
// only delete the source once the target is verified RUNNING.
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
// Exit codes: 0 migrated, 1 failed (source preserved), 2 usage error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointlocator"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
)

type stepLog struct {
	Step   string `json:"step"`
	Detail string `json:"detail,omitempty"`
	TookMs int64  `json:"took_ms"`
	Failed bool   `json:"failed,omitempty"`
}

type migrateReport struct {
	Sandbox    string    `json:"sandbox"`
	Source     string    `json:"source"`
	Target     string    `json:"target,omitempty"`
	Checkpoint string    `json:"checkpoint_dir"`
	Steps      []stepLog `json:"steps"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
}

func main() {
	sandbox := flag.String("sandbox", "", "sandbox ID to migrate")
	source := flag.String("source", "", "source node name (executor {node} value)")
	execTpl := flag.String("exec", "", "node command executor template with {node} placeholder")
	storeSpec := flag.String("store", "", "chunk store spec (http://endpoint/bucket or directory)")
	nodes := flag.String("nodes", "", "comma-separated node catalog addresses for placement")
	to := flag.String("to", "", "preferred target node name (default: locator decides)")
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
	// the restore command is in flight the target may be running even if
	// its response was lost, so a rollback first has to fence the target;
	// once the target is verified RUNNING it owns the sandbox outright and
	// the only legal failure mode left is source-cleanup-pending.
	const (
		phaseCheckpointing   = iota // checkpoint in flight; outcome unknown on failure
		phaseSourceOwned            // checkpoint sealed; target untouched; rollback is safe
		phaseTargetRestoring        // restore issued; target state unknown; fence before rollback
		phaseTargetOwned            // target verified RUNNING; never roll back
	)
	phase := phaseCheckpointing
	fenceTarget := func(target string) bool {
		// Idempotent stop+delete plus an absence check: only a confirmed
		// fence makes a source rollback safe again.
		run(target, "fence-target", *bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "delete", *sandbox)
		if out, ok := run(target, "confirm-fenced", *bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "list"); ok &&
			!listHasSandbox(out, *sandbox) {
			return true
		}
		return false
	}
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
			// the target may already be running the sandbox. Only a
			// confirmed fence clears the way for a rollback — otherwise
			// restoring the source would create dual writers.
			target := report.Target
			if target != "" && fenceTarget(target) {
				detail = rollbackSource(detail)
			} else {
				detail += " (TARGET OUTCOME UNKNOWN and could not be fenced; rollback skipped to avoid dual writers — resolve the target manually, then restore the source from " +
					report.Checkpoint + " if needed)"
			}
		case phaseTargetOwned:
			detail += " (target verified RUNNING and owns the sandbox; no rollback — delete the lingering source copy manually to finish cleanup)"
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

	// 2. Checkpoint it. --leave-running=false gives stop-and-copy
	// semantics: the source freezes at the checkpoint instant, sandboxd
	// finalizes it after the seal, and no post-checkpoint write can be
	// lost or double-applied. A failed command does NOT prove the server
	// never executed it (timeout, lost reply): probe the source before
	// claiming anything about its state (F2).
	if _, ok := run(*source, "checkpoint", *bin+"/checkpoint-restore",
		"--action", "checkpoint", "--socket", "/run/sandboxd/sandboxd.sock",
		"--request-file", *ckReq, "--sandbox-id", *sandbox,
		"--checkpoint-dir", report.Checkpoint, "--compress=false",
		"--leave-running=false"); !ok {
		if out, ok2 := run(*source, "probe-source", *bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "list"); ok2 &&
			listHasRunningSandbox(out, *sandbox) {
			fail("checkpoint", "checkpoint failed; sandbox still RUNNING on source (not executed)")
		}
		fail("checkpoint", "checkpoint failed and the sandbox is gone from the source — outcome unknown; the sealed local checkpoint at "+
			report.Checkpoint+" (if complete) supports a manual rollback-restore")
	}
	phase = phaseSourceOwned

	// 3. Publish on the source node (paths are node-local; the executor
	// runs cn-publish where the checkpoint landed, idempotent either way).
	if _, ok := run(*source, "publish", *bin+"/cn-publish",
		"-checkpoint-dir", report.Checkpoint, "-store", *storeSpec); !ok {
		failPastCheckpoint("publish", "cn-publish failed on source")
	}

	// 4. Place: federate node records, decide with the source excluded.
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

	// 5. Materialize + restore on the target.
	if _, ok := run(placement.NodeID, "materialize", *bin+"/cn-fetch",
		"-into", report.Checkpoint, "-id", dirBase(report.Checkpoint), "-store", *storeSpec); !ok {
		failPastCheckpoint("materialize", "cn-fetch failed on target")
	}
	// The restore command is about to be issued: from here a lost or
	// failed reply does not mean the target stayed down, so compensation
	// must fence the target before touching the source (F2).
	phase = phaseTargetRestoring
	if _, ok := run(placement.NodeID, "restore", *bin+"/checkpoint-restore",
		"--action", "restore", "--socket", "/run/sandboxd/sandboxd.sock",
		"--target-id", *sandbox, "--request-file", *ckReq,
		"--checkpoint-dir", report.Checkpoint); !ok {
		failPastCheckpoint("restore", "restore failed on target")
	}

	// 6. Verify RUNNING on the target before declaring success. Parse the
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

	// 7. Retire the source copy. With --leave-running=false the source was
	// already finalized at checkpoint time; the explicit delete is kept as
	// an idempotent confirmation and its failure is fatal — a lingering
	// copy would be a second writer.
	if _, ok := run(*source, "delete-source", *bin+"/sbox",
		"--address", "/run/sandboxd/sandboxd.sock", "delete", *sandbox); !ok {
		if out, ok2 := run(*source, "confirm-source-gone", *bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "list"); ok2 &&
			!listHasSandbox(out, *sandbox) {
			// Already retired by the checkpoint — acceptable.
		} else {
			failPastCheckpoint("delete-source",
				"source delete failed and the sandbox still lists on the source — resolve manually to avoid dual writers")
		}
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

// listHasSandbox parses the tab-separated `sbox list` output and reports
// whether the sandbox ID appears as an exact ID column value.
func listHasSandbox(listOutput, sandboxID string) bool {
	return sandboxListState(listOutput, sandboxID) != ""
}

// listHasRunningSandbox additionally requires the row to report the
// SANDBOX_STATE_RUNNING state, so a half-created or exited sandbox cannot
// pass verification.
func listHasRunningSandbox(listOutput, sandboxID string) bool {
	return sandboxListState(listOutput, sandboxID) == "SANDBOX_STATE_RUNNING"
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
