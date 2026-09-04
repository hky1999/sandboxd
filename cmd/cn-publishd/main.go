// Command cn-publishd automatically offloads sealed checkpoints to the
// chunk store: it watches the configured artifact roots and publishes
// anything sealed but not yet published, newest first, idempotently.
//
// The daemon is stateless — the persisted publish state machine under
// <root>/.publish/ is the whole truth — so restarts resume and S3 outages
// retry on the next round (fail-open to local restores throughout).
//
//	cn-publishd -roots /mnt/cn/ck -store http://minio:19000/bucket [-interval 30s]
//	cn-publishd ... -once      # single round (cron / runbook / master call)
//	cn-publishd ... -json     # machine-readable round summaries
//
// Exit codes (programmatic-callers contract): 0 all dirty artifacts
// published, 1 some failed this round (will retry), 2 usage error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// roundOutcome is the machine-readable summary of one scan round.
type roundOutcome struct {
	StartedAt time.Time         `json:"started_at"`
	Duration  string            `json:"duration"`
	Published []string          `json:"published"`
	Skipped   int               `json:"skipped"`
	Failed    map[string]string `json:"failed,omitempty"`
}

type pendingArtifact struct {
	dir     string
	id      string
	created time.Time
}

func main() {
	roots := flag.String("roots", "", "comma-separated artifact roots to watch")
	storeSpec := flag.String("store", "", "chunk store spec (http://endpoint/bucket or directory)")
	interval := flag.Duration("interval", 30*time.Second, "scan interval")
	once := flag.Bool("once", false, "run a single round and exit")
	jsonOut := flag.Bool("json", false, "machine-readable round summaries")
	timeout := flag.Duration("timeout", 10*time.Minute, "per-publish deadline")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-publishd -roots DIR[,DIR...] -store SPEC [-interval 30s] [-once] [-json]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *roots == "" || *storeSpec == "" {
		flag.Usage()
		os.Exit(2)
	}
	store, err := chunkstore.Open(*storeSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	for {
		outcome := scanAndPublish(*roots, store, *timeout)
		if *jsonOut {
			encoded, _ := json.Marshal(outcome)
			fmt.Println(string(encoded))
		} else {
			fmt.Printf("round: published=%d skipped=%d failed=%d (%s)\n",
				len(outcome.Published), outcome.Skipped, len(outcome.Failed), outcome.Duration)
			for id, reason := range outcome.Failed {
				fmt.Fprintf(os.Stderr, "  failed %s: %s\n", id, reason)
			}
		}
		if *once {
			if len(outcome.Failed) > 0 {
				os.Exit(1)
			}
			return
		}
		time.Sleep(*interval)
	}
}

// scanAndPublish walks the roots, collects sealed-but-unpublished
// artifacts newest first, and publishes each. Already-published and
// in-flight (publishing) artifacts are skipped: publishing is not
// interrupted, only not restarted.
func scanAndPublish(roots string, store chunkstore.Store, timeout time.Duration) roundOutcome {
	outcome := roundOutcome{
		StartedAt: time.Now().UTC(),
		Failed:    map[string]string{},
	}
	var pending []pendingArtifact
	for _, root := range splitAndTrim(roots) {
		entries, err := os.ReadDir(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			outcome.Failed[root] = err.Error()
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == checkpointpublish.StateDirName {
				continue
			}
			dir := filepath.Join(root, entry.Name())
			// A manifest marks a sealed artifact; anything else is a
			// half-written checkpoint or an unrelated directory.
			if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
				continue
			}
			state, err := checkpointpublish.Status(dir)
			if err != nil || state == nil {
				continue // never published: candidate
			}
			switch state.State {
			case checkpointpublish.StatePublished, checkpointpublish.StatePublishing:
				outcome.Skipped++
			case checkpointpublish.StatePublishFailed:
				pending = append(pending, pendingArtifact{
					dir: dir, id: entry.Name(), created: state.StartedAt,
				})
			}
			continue
		}
	}
	// Unpublished artifacts never had a state file: a second pass over the
	// sealed directories picks up the ones Status returned nil for.
	for _, root := range splitAndTrim(roots) {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == checkpointpublish.StateDirName {
				continue
			}
			dir := filepath.Join(root, entry.Name())
			if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
				continue
			}
			if state, _ := checkpointpublish.Status(dir); state != nil {
				continue // handled above
			}
			info, err := entry.Info()
			created := time.Time{}
			if err == nil {
				created = info.ModTime()
			}
			pending = append(pending, pendingArtifact{dir: dir, id: entry.Name(), created: created})
		}
	}
	// Newest first: the most recent generation is the most likely restore
	// target, so it earns cross-node eligibility first.
	sort.Slice(pending, func(i, j int) bool { return pending[i].created.After(pending[j].created) })

	for _, artifact := range pending {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, err := checkpointpublish.Run(ctx, artifact.dir, artifact.id, store, storeSpecName(store))
		cancel()
		if err != nil {
			outcome.Failed[artifact.id] = err.Error()
			continue
		}
		outcome.Published = append(outcome.Published, artifact.id)
	}
	outcome.Duration = time.Since(outcome.StartedAt).Round(time.Millisecond).String()
	return outcome
}

func splitAndTrim(list string) []string {
	return strings.Split(strings.ReplaceAll(list, " ", ""), ",")
}

func storeSpecName(store chunkstore.Store) string {
	if remote, ok := store.(fmt.Stringer); ok {
		return remote.String()
	}
	return "store"
}
