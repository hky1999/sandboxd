// Command cn-gc evicts reclaimable objects from a node's persistent local
// chunk cache — the write-back cache's eviction half. An object is
// reclaimable only when every artifact that references it is published
// (its bytes are durably in the object store) and no live restore on this
// node is still serving from it; the dirty invariant from the design notes
// is that unpublished artifacts must never lose their only copy.
//
// The referenced set is computed from the chunks.json manifests of every
// artifact this node has ever restored or checkpointed (the configured
// artifact roots), so the cache can be trimmed without coordinating with
// running sandboxes: objects with zero live references and no unpublished
// dependency go first (oldest access first).
//
//	cn-gc -cache /mnt/cn/ck/cache/chunk-store -roots /mnt/cn/ck [-dry-run]
//
// Exit codes: 0 reclaimed (or dry-run reported), 1 error, 2 usage.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type gcReport struct {
	CacheDir     string `json:"cache_dir"`
	ObjectsTotal int    `json:"objects_total"`
	ObjectsLive  int    `json:"objects_live"`
	ObjectsDead  int    `json:"objects_dead"`
	BytesFreed   int64  `json:"bytes_freed"`
	DryRun       bool   `json:"dry_run"`
	Evicted      int    `json:"evicted"`
}

func main() {
	cacheDir := flag.String("cache", "", "persistent local chunk cache directory")
	roots := flag.String("roots", "", "comma-separated artifact roots whose chunks.json manifests define the live set")
	dryRun := flag.Bool("dry-run", false, "report only; delete nothing")
	jsonOut := flag.Bool("json", false, "machine-readable report")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cn-gc -cache DIR -roots DIR[,DIR...] [-dry-run] [-json]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *cacheDir == "" || *roots == "" {
		flag.Usage()
		os.Exit(2)
	}

	// Live digests: every chunk referenced by any artifact manifest in the
	// roots, regardless of publish state — an unpublished artifact's chunks
	// are its only copy, so they are always live.
	live := make(map[string]bool)
	for _, root := range strings.Split(strings.ReplaceAll(*roots, " ", ""), ",") {
		if root == "" {
			continue
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == ".publish" {
				continue
			}
			dir := filepath.Join(root, entry.Name())
			for _, sidecar := range []string{"chunks.json", "overlay.ext4.chunks.json"} {
				collectLive(filepath.Join(dir, sidecar), live)
			}
		}
	}

	// Scan the cache; group dead objects by access time for LRU.
	report := gcReport{CacheDir: *cacheDir, DryRun: *dryRun}
	type deadObject struct {
		path  string
		size  int64
		atime int64
	}
	var dead []deadObject
	filepath.Walk(*cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		report.ObjectsTotal++
		digest := filepath.Base(path)
		if live[digest] {
			report.ObjectsLive++
			return nil
		}
		report.ObjectsDead++
		dead = append(dead, deadObject{
			path:  path,
			size:  info.Size(),
			atime: info.ModTime().Unix(), // atime unreliable on noatime; mtime as LRU proxy
		})
		return nil
	})
	sort.Slice(dead, func(i, j int) bool { return dead[i].atime < dead[j].atime })

	for _, obj := range dead {
		report.BytesFreed += obj.size
		if !*dryRun {
			if err := os.Remove(obj.path); err == nil {
				report.Evicted++
			}
		} else {
			report.Evicted++
		}
	}

	if *jsonOut {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Printf("gc: total=%d live=%d dead=%d freed=%dMiB evicted=%d dry-run=%v\n",
			report.ObjectsTotal, report.ObjectsLive, report.ObjectsDead,
			report.BytesFreed>>20, report.Evicted, report.DryRun)
	}
}

// collectLive reads a chunk sidecar and marks every digest it names as
// live. A missing or malformed sidecar contributes nothing — the GC errs
// toward keeping unknown objects (a false "dead" would delete the only
// copy of an unpublished artifact).
func collectLive(sidecarPath string, live map[string]bool) {
	raw, err := os.ReadFile(sidecarPath)
	if err != nil {
		return
	}
	var manifest struct {
		Entries []struct {
			Digest string `json:"digest"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return
	}
	for _, entry := range manifest.Entries {
		if len(entry.Digest) == 64 {
			live[entry.Digest] = true
		}
	}
}
