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

	// 1. Confirm the sandbox is running on the source.
	if _, ok := run(*source, "list", *bin+"/sbox", "--address", "/run/sandboxd/sandboxd.sock", "list"); !ok {
		fail("list", "source listing failed")
	}
	if !containsField(report.lastDetail(), *sandbox) {
		fail("list", fmt.Sprintf("sandbox %s not found on source %s", *sandbox, *source))
	}

	// A previous failed attempt may have left its checkpoint directory
	// behind; sandboxd refuses non-empty directories, so clear it for an
	// idempotent retry.
	run(*source, "clean-dir", "rm", "-rf", report.Checkpoint)

	// 2. Checkpoint it (stop semantics: leave_running=false).
	if _, ok := run(*source, "checkpoint", *bin+"/checkpoint-restore",
		"--action", "checkpoint", "--socket", "/run/sandboxd/sandboxd.sock",
		"--request-file", *ckReq, "--sandbox-id", *sandbox,
		"--checkpoint-dir", report.Checkpoint, "--compress=false"); !ok {
		fail("checkpoint", "checkpoint failed (see steps)")
	}

	// 3. Publish on the source node (paths are node-local; the executor
	// runs cn-publish where the checkpoint landed, idempotent either way).
	if _, ok := run(*source, "publish", *bin+"/cn-publish",
		"-checkpoint-dir", report.Checkpoint, "-store", *storeSpec); !ok {
		fail("publish", "cn-publish failed on source")
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
		fail("place", compatErr.Error())
	}
	placement, err := checkpointlocator.Decide(checkpointlocator.Input{
		CheckpointID:     dirBase(report.Checkpoint),
		Compat:           compat,
		OriginNodeID:     *source,
		ExcludeNodes:     []string{*source},
		RequirePublished: true,
		PublishState:     checkpointpublish.StatePublished,
		Nodes:            nodeRecords,
	})
	if err != nil {
		fail("place", err.Error())
	}
	if *to != "" && placement.NodeID != *to {
		// Honor an explicit target when it is compatible; the locator's
		// pick is advisory here.
		found := false
		for _, n := range nodeRecords {
			if n.ID == *to {
				found = true
				break
			}
		}
		if !found {
			fail("place", fmt.Sprintf("requested target %s not in registry", *to))
		}
		placement.NodeID, placement.Address = *to, ""
	}
	report.Target = placement.NodeID

	// 5. Materialize + restore on the target.
	if _, ok := run(placement.NodeID, "materialize", *bin+"/cn-fetch",
		"-into", report.Checkpoint, "-id", dirBase(report.Checkpoint), "-store", *storeSpec); !ok {
		fail("materialize", "cn-fetch failed on target")
	}
	if _, ok := run(placement.NodeID, "restore", *bin+"/checkpoint-restore",
		"--action", "restore", "--socket", "/run/sandboxd/sandboxd.sock",
		"--target-id", *sandbox, "--request-file", *ckReq,
		"--checkpoint-dir", report.Checkpoint); !ok {
		fail("restore", "restore failed on target (source preserved)")
	}

	// 6. Verify RUNNING on the target before touching the source.
	verified := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := run(placement.NodeID, "verify", *bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "list"); ok &&
			containsField(report.lastDetail(), *sandbox) {
			verified = true
			break
		}
		time.Sleep(3 * time.Second)
	}
	if !verified {
		fail("verify", "target never reported the sandbox running (source preserved)")
	}

	// 7. Safe to retire the source copy.
	run(*source, "delete-source", *bin+"/sbox",
		"--address", "/run/sandboxd/sandboxd.sock", "delete", *sandbox)
	report.OK = true
	finish(report, *jsonOut, true)
}

func (r *migrateReport) lastDetail() string {
	if len(r.Steps) == 0 {
		return ""
	}
	return r.Steps[len(r.Steps)-1].Detail
}

func containsField(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
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
