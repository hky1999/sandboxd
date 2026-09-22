// Command cn-publishd automatically offloads sealed checkpoints to the
// chunk store: it watches the configured artifact roots and publishes
// anything sealed but not yet published, newest first (with a starvation
// promotion for old artifacts), idempotently.
//
// The daemon is stateless — the persisted publish state machine under
// <root>/.publish/ is the whole truth — so restarts resume and S3 outages
// retry under a bounded exponential backoff (fail-open to local restores
// throughout). The M1 lifecycle additions: a persisted "queued" record at
// discovery, INDEX-identity reconciliation for the crash window between
// remote INDEX commit and the local "published" write, retry bookkeeping
// on publish_failed records, backpressure observables, Prometheus metrics
// on -http-address, and per-artifact seal→remote_ready phase breakdown in
// the round summary.
//
//	cn-publishd -roots /mnt/cn/ck -store http://minio:19000/bucket [-interval 30s]
//	cn-publishd ... -once      # single round (cron / runbook / master call)
//	cn-publishd ... -json     # machine-readable round summaries
//	cn-publishd ... -http-address 127.0.0.1:9101   # /metrics
//
// Exit codes (programmatic-callers contract): 0 all dirty artifacts
// published, 1 some failed this round (will retry), 2 usage error.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// roundGauges is the live snapshot the /metrics endpoint renders between
// rounds (no client-library dependency).
var roundGauges atomic.Pointer[checkpointpublish.RoundResult]

func main() {
	roots := flag.String("roots", "", "comma-separated artifact roots to watch")
	storeSpec := flag.String("store", "", "chunk store spec (http://endpoint/bucket or directory)")
	interval := flag.Duration("interval", 30*time.Second, "scan interval")
	once := flag.Bool("once", false, "run a single round and exit")
	jsonOut := flag.Bool("json", false, "machine-readable round summaries")
	timeout := flag.Duration("timeout", 10*time.Minute, "per-publish deadline")
	stale := flag.Duration("stale", 10*time.Minute, "publishing state older than this is a crash leftover and is re-queued")
	compressChunks := flag.Bool("compress-chunks", false, "publish standalone memory chunks as zstd transport bodies (digests keep naming uncompressed bytes)")
	backoffBase := flag.Duration("backoff-base", 30*time.Second, "exponential retry base for publish_failed records (0 retries every round, the historical behavior)")
	backoffCap := flag.Duration("backoff-cap", 10*time.Minute, "retry backoff ceiling")
	starveAfter := flag.Duration("starve-after", time.Hour, "pending artifacts older than this are promoted ahead of newest-first (0 disables)")
	priorityIDs := flag.String("priority-id", "", "comma-separated artifact IDs to publish first (migration-waiting priority; restartable CLI entry, order preserved)")
	minFree := flag.String("min-free", "", "backpressure reserve for the artifact filesystem (e.g. 20G); at or below it rounds report backpressured")
	httpAddress := flag.String("http-address", "", "Prometheus-style metrics listen address (empty disables)")
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
	var minFreeBytes int64
	if *minFree != "" {
		minFreeBytes, err = parseBytes(*minFree)
		if err != nil {
			fmt.Fprintf(os.Stderr, "-min-free: %v\n", err)
			os.Exit(2)
		}
	}
	if *httpAddress != "" {
		// Bind SYNCHRONOUSLY before any scanning: a port conflict is a
		// deployment error and must fail the daemon visibly at startup,
		// not surface later as silently-missing metrics.
		if _, err := listenMetrics(*httpAddress); err != nil {
			fmt.Fprintf(os.Stderr, "publishd: metrics listener %s failed: %v\n", *httpAddress, err)
			os.Exit(2)
		}
	}

	rootsList := checkpointpublish.SplitRoots(*roots)
	for {
		outcome := checkpointpublish.ScanRound(context.Background(), checkpointpublish.ScanRoundOptions{
			Roots:          rootsList,
			Store:          store,
			StoreName:      storeSpecName(store),
			Timeout:        *timeout,
			CompressChunks: *compressChunks,
			StaleAfter:     *stale,
			BackoffBase:    *backoffBase,
			BackoffCap:     *backoffCap,
			StarveAfter:    *starveAfter,
			PriorityIDs:    checkpointpublish.SplitRoots(*priorityIDs),
		})
		roundGauges.Store(&outcome)
		if minFreeBytes > 0 {
			snap := checkpointpublish.SnapshotBackpressure(rootsList, checkpointpublish.BackpressureLimits{MinFreeBytes: minFreeBytes}, nil)
			if snap.Backpressured {
				fmt.Fprintf(os.Stderr, "publishd: BACKPRESSURED %s (pending=%d unpublished=%d oldest=%s free=%d)\n",
					snap.Reason, snap.Pending, snap.UnpublishedBytes, snap.OldestPendingAge.Round(time.Second), snap.FreeBytes)
			}
		}
		if *jsonOut {
			fmt.Println(checkpointpublish.MarshalRound(outcome))
		} else {
			fmt.Printf("round: published=%d skipped=%d failed=%d deferred=%d (%s)\n",
				len(outcome.Published), outcome.Skipped, len(outcome.Failed), len(outcome.Deferred), outcome.Duration)
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

// metricsMux builds the /metrics handler on its own mux so multiple
// listeners (and tests) never contend on DefaultServeMux.
func metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metricsHandler)
	return mux
}

// listenMetrics binds addr synchronously and serves in the background. The
// returned error is the BIND error itself — a conflict is observable by
// the caller immediately, with no goroutine exit race.
func listenMetrics(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() { _ = http.Serve(ln, metricsMux()) }()
	return ln, nil
}

// metricsHandler renders the round gauges in pure Prometheus text format.
// Labels are aggregate only (no artifact IDs — high-cardinality labels are
// a non-goal).
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if res := roundGauges.Load(); res != nil {
		fmt.Fprintf(w, "# HELP publishd_queue_depth Artifacts sealed but not yet remote_ready.\n")
		fmt.Fprintf(w, "# TYPE publishd_queue_depth gauge\n")
		fmt.Fprintf(w, "publishd_queue_depth %d\n", res.Pending)
		fmt.Fprintf(w, "# HELP publishd_unpublished_bytes On-disk bytes held by unpublished artifacts (unique copies).\n")
		fmt.Fprintf(w, "# TYPE publishd_unpublished_bytes gauge\n")
		fmt.Fprintf(w, "publishd_unpublished_bytes %d\n", res.UnpublishedBytes)
		fmt.Fprintf(w, "# HELP publishd_oldest_pending_age_seconds Age of the oldest unpublished artifact.\n")
		fmt.Fprintf(w, "# TYPE publishd_oldest_pending_age_seconds gauge\n")
		fmt.Fprintf(w, "publishd_oldest_pending_age_seconds %.3f\n", res.OldestPendingAge.Seconds())
		fmt.Fprintf(w, "# HELP publishd_round_published_total Artifacts published in the last round.\n")
		fmt.Fprintf(w, "# TYPE publishd_round_published_total gauge\n")
		fmt.Fprintf(w, "publishd_round_published_total %d\n", len(res.Published))
		fmt.Fprintf(w, "# HELP publishd_round_failed_total Artifacts failed in the last round (retrying under backoff).\n")
		fmt.Fprintf(w, "# TYPE publishd_round_failed_total gauge\n")
		fmt.Fprintf(w, "publishd_round_failed_total %d\n", len(res.Failed))
		fmt.Fprintf(w, "# HELP publishd_round_deferred_total Artifacts deferred by retry backoff in the last round.\n")
		fmt.Fprintf(w, "# TYPE publishd_round_deferred_total gauge\n")
		fmt.Fprintf(w, "publishd_round_deferred_total %d\n", len(res.Deferred))
		for _, ph := range res.Phases {
			fmt.Fprintf(w, "# HELP publishd_seal_to_ready_seconds Seal-to-remote-ready wall time per artifact (last round).\n")
			fmt.Fprintf(w, "# TYPE publishd_seal_to_ready_seconds gauge\n")
			fmt.Fprintf(w, "publishd_seal_to_ready_seconds{reconciled=\"%t\"} %.3f\n", ph.Reconciled, ph.SealToReady.Seconds())
			fmt.Fprintf(w, "# HELP publishd_queue_wait_seconds Discovery-to-publish-start wait per artifact (last round).\n")
			fmt.Fprintf(w, "# TYPE publishd_queue_wait_seconds gauge\n")
			fmt.Fprintf(w, "publishd_queue_wait_seconds{reconciled=\"%t\"} %.3f\n", ph.Reconciled, ph.QueueWait.Seconds())
			fmt.Fprintf(w, "# HELP publishd_publish_wall_seconds Publish-attempt wall per artifact (last round; attribution detail lives in the round JSON).\n")
			fmt.Fprintf(w, "# TYPE publishd_publish_wall_seconds gauge\n")
			fmt.Fprintf(w, "publishd_publish_wall_seconds{reconciled=\"%t\"} %.3f\n", ph.Reconciled, ph.PublishWall.Seconds())
			break // one exemplar per round: per-artifact series are high-cardinality
		}
	}
}

// parseBytes accepts sizes like 512K / 20G / 1T (binary byte suffixes) and
// plain byte counts. Empty input, non-numeric prefixes, trailing garbage,
// negative values, and overflow are errors — the flag parser must never
// silently accept a malformed reserve.
func parseBytes(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	factor := int64(1)
	switch c := s[len(s)-1]; c {
	case 'k', 'K', 'm', 'M', 'g', 'G', 't', 'T':
		switch c {
		case 'k', 'K':
			factor = 1 << 10
		case 'm', 'M':
			factor = 1 << 20
		case 'g', 'G':
			factor = 1 << 30
		case 't', 'T':
			factor = 1 << 40
		}
		s = s[:len(s)-1]
	}
	if s == "" {
		return 0, fmt.Errorf("size missing a number")
	}
	neg := false
	switch s[0] {
	case '+':
		s = s[1:]
	case '-':
		neg = true
		s = s[1:]
	}
	if s == "" {
		return 0, fmt.Errorf("size missing a number")
	}
	var v int64
	for i := 0; i < len(s); i++ {
		d := s[i]
		if d < '0' || d > '9' {
			return 0, fmt.Errorf("invalid size %q (non-digit %q)", s, string(d))
		}
		if v > (1<<62)/10 {
			return 0, fmt.Errorf("size %q overflows", s)
		}
		v = v*10 + int64(d-'0')
		if v < 0 || (factor > 1 && v > (1<<63-1)/factor) {
			return 0, fmt.Errorf("size %q overflows", s)
		}
	}
	if neg {
		return 0, fmt.Errorf("negative size")
	}
	return v * factor, nil
}

func storeSpecName(store chunkstore.Store) string {
	if remote, ok := store.(fmt.Stringer); ok {
		return remote.String()
	}
	return "store"
}
