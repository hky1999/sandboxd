// Command firecracker-uffd-handler serves guest memory pages to a Firecracker
// microVM restored with the UFFD memory backend.
//
// Protocol (see firecracker src/vmm/src/persist.rs guest_memory_from_uffd):
// the handler binds the UDS path first; on /snapshot/load Firecracker connects
// and sends a JSON array of guest region mappings together with the userfaultfd
// descriptor via SCM_RIGHTS. Each pagefault event is resolved by copying
// chunk bytes from the backing file into the guest memory with UFFDIO_COPY.
//
// The handler exits when Firecracker disconnects (VM stopped), the uffd
// descriptor is hung up, or SIGTERM arrives: termination runs the same
// shutdown path and joins its workers instead of exiting abruptly.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkcache"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// regionMapping mirrors firecracker's GuestRegionUffdMapping.
type regionMapping struct {
	BaseHostVirtAddr uint64 `json:"base_host_virt_addr"`
	Size             uint64 `json:"size"`
	Offset           uint64 `json:"offset"`
	PageSize         uint64 `json:"page_size"`
}

// uffd_msg event kinds (linux/userfaultfd.h).
const (
	uffdEventRemove    = 0x03
	uffdEventPagefault = 0x12
)

// UFFD ioctls: _IOWR(UFFDIO=0xAA, nr, struct).
const (
	uffdioCopyNr = 0xC028AA03 // _IOWR(0xAA, 0x03, struct uffdio_copy) - 40 bytes
	uffdioWakeNr = 0xC010AA05 // _IOWR(0xAA, 0x05, struct uffdio_range) - 16 bytes
	uffdioZeroNr = 0xC020AA04 // _IOWR(0xAA, 0x04, struct uffdio_zeropage) - 32 bytes
)

const uffdMsgSize = 32 // event(8) + union(24)

// uffdioCopyArg is struct uffdio_copy; the kernel writes back the copied
// byte count in Copy. The struct must stay exactly 40 bytes.
type uffdioCopyArg struct {
	Dst  uint64
	Src  uint64
	Len  uint64
	Mode uint64
	Copy int64
}

type uffdioRangeArg struct {
	Start uint64
	Len   uint64
}

type uffdioZeroArg struct {
	Range uffdioRangeArg
	Mode  uint64
	Zero  int64
}

type chunkContentKey struct {
	digest string
	length uint64
}

// pageSource resolves a chunk of guest memory content: either directly from
// a local backing file, or through a sparse local cache filled from a remote
// HTTP range source on miss.
type pageSource struct {
	ctx  context.Context
	file *os.File // local backing (nil when remote mode is used)

	cachePath string // sparse local cache file (remote mode)
	cache     *os.File
	remote    string // base URL of the artifact memory file (remote mode)
	chunk     uint64
	client    *http.Client

	// chunkManifest/chunkStore switch fetchChunk to digest-addressed reads
	// from a content-addressed store (B-line distribution); nil keeps the
	// backing-file or HTTP-range source.
	chunkManifest *checkpointchunks.Manifest
	chunkStore    string
	// chunkLocal is a persistent content-addressed cache directory fronting
	// an http chunk-store: hits never touch the network; misses are verified
	// and persisted here for the next sandbox on this node.
	chunkLocal string
	// chunkCache is the M2 capacity-managed front for chunkLocal (same
	// directory, same layout). Non-nil only for http stores with -chunk-local
	// configured; it adds cross-process missing-chunk dedup, watermark
	// eviction, pins and crash reconciliation while preserving the verified
	// read / atomic publish semantics of the legacy path below.
	chunkCache *chunkcache.Manager
	// foreground counts in-flight fault-path fetches. Background prefetch
	// yields while it is positive: a missing page must never queue behind
	// speculative bulk work.
	foreground atomic.Int32

	inflightMu sync.Mutex
	inflight   map[uint64]chan struct{} // chunk index -> leader completion
	// fetched records the chunks whose cache bytes are fully written. A
	// sparse hole inside the cache reads back as a full-length run of
	// zeros once the file has been extended past it by ANY other chunk's
	// write, so length cannot distinguish "written" from "hole": only the
	// bitmap can. Guarded by inflightMu.
	fetched map[uint64]struct{}

	// Guarded by inflightMu. A verified digest points at an immutable cache
	// extent; duplicate positions copy it into their own logical offsets.
	// Payload buffers are not retained here. Include length to distinguish
	// malformed references and short tails without trusting a digest alone.
	verifiedDigests map[chunkContentKey]uint64
	digestInflight  map[chunkContentKey]chan struct{}

	persistenceMu          sync.Mutex
	persister              *chunkPersister
	persistenceStopped     bool
	persistenceWorkerCount int
}

func (src *pageSource) requestContext() context.Context {
	if src.ctx != nil {
		return src.ctx
	}
	return context.Background()
}

// zeroChunkLength recognizes content from its digest, never from sparse file
// allocation. The short tail has a different zero digest from a full chunk.
func (src *pageSource) zeroChunkLength(index uint64) uint64 {
	m := src.chunkManifest
	if m == nil || m.ChunkBytes <= 0 || index >= uint64(len(m.Entries)) {
		return 0
	}
	entry := m.Entries[index]
	if entry.Offset < 0 || entry.Offset >= m.FileSize {
		return 0
	}
	length := min(int64(m.ChunkBytes), m.FileSize-entry.Offset)
	if entry.Digest != checkpointchunks.ZeroChunkDigest(int(length)) {
		return 0
	}
	return uint64(length)
}

// resolveChunk returns the bytes for [fileOff, fileOff+want) clamped to the
// artifact end. The page fault path calls it with want = 4KiB: on an
// already-fetched chunk only those bytes are read back from the cache, not
// the whole 256KiB chunk (P4 — a full-chunk read per 4KiB fault amplifies
// user-space reads up to 64x while the guest walks sequential pages).
func (s *faultServer) resolveChunk(fileOff, want uint64) ([]byte, error) {
	if s.source.file != nil {
		buf := make([]byte, want)
		n, err := s.source.file.ReadAt(buf, int64(fileOff))
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, err
		}
		return buf[:n], nil
	}
	// Remote mode: fetch/cache at chunk granularity, but return the slice
	// starting at the REQUESTED file offset, not at the chunk boundary.
	// The caller (resolve) expects data for [fileOff, fileOff+copyLen).
	chunkIdx := fileOff / s.source.chunk
	cacheOff := chunkIdx * s.source.chunk
	subOff := fileOff - cacheOff // offset within the chunk
	src := s.source
	// A chunk whose manifest digest specifies zero bytes needs no remote object or
	// cache extent. Construct only the requested page/span, bounded by the tail.
	if length := src.zeroChunkLength(chunkIdx); length > 0 {
		if subOff >= length {
			return nil, io.EOF
		}
		return make([]byte, min(want, length-subOff)), nil
	}
	// A nonzero chunk is readable only once its fetch completed (bitmap). Reading
	// before that can return a hole: another worker's write to a higher
	// chunk extends the sparse file, and ReadAt then returns a full-length
	// zero buffer for this chunk's unwritten extent — indistinguishable
	// from real data by length alone.
	src.inflightMu.Lock()
	_, ready := src.fetched[chunkIdx]
	src.inflightMu.Unlock()
	if !ready {
		// Fault-path fetches count as foreground: background prefetch
		// yields while any of them is in flight (see the prefetch wrapper).
		src.foreground.Add(1)
		err := s.fetchChunk(chunkIdx)
		src.foreground.Add(-1)
		if err != nil {
			return nil, err
		}
	}
	// Page-granular read of exactly the requested span (clamped to the
	// chunk's end; the tail chunk may be short).
	span := src.chunk - subOff
	if want < span {
		span = want
	}
	buf, ok := s.readCache(cacheOff+subOff, span)
	if !ok {
		return nil, fmt.Errorf("chunk %d missing from cache after fetch", chunkIdx)
	}
	return buf, nil
}

// readCache reads n bytes back from the sparse cache at the given absolute
// offset. The caller must have established (via the fetched bitmap) that the
// enclosing nonzero chunk's bytes are fully written: a sparse hole reads back as a
// full-length run of zeros once the file has been extended past it, so this
// function deliberately does not try to validate completeness by length.
func (s *faultServer) readCache(off, n uint64) ([]byte, bool) {
	buf := make([]byte, n)
	read, err := s.source.cache.ReadAt(buf, int64(off))
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false
	}
	if read == 0 {
		return nil, false
	}
	return buf[:read], true
}

// fetchChunk pulls one chunk from the remote source, collapsing concurrent
// misses of the same chunk into a single request. A short response body is
// an error, never a partial cache fill: a truncated chunk reads back as a
// mix of stale bytes and holes (zeros), and serving that corrupts restored
// guest memory one silent page at a time.
func (s *faultServer) fetchChunk(chunkIdx uint64) error {
	src := s.source
	ctx := src.requestContext()
	const attempts = 3
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * 50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		src.inflightMu.Lock()
		if _, done := src.fetched[chunkIdx]; done {
			src.inflightMu.Unlock()
			// F1: the chunk is already verified in the cache or known zero. A background
			// prefetch reaching an already-served chunk must be a no-op:
			// refetching would overwrite verified bytes before the new copy
			// passes validation, and the stale bitmap would then vouch for
			// whatever landed there.
			return nil
		}
		if done, ok := src.inflight[chunkIdx]; ok {
			src.inflightMu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
			// The leader may have failed; the bitmap is the outcome of
			// record, so re-check it instead of assuming success (F1:
			// waiters used to return nil unconditionally).
			src.inflightMu.Lock()
			_, done := src.fetched[chunkIdx]
			src.inflightMu.Unlock()
			if done {
				return nil
			}
			lastErr = fmt.Errorf("chunk %d: concurrent fetch failed; retrying", chunkIdx)
			continue
		}
		done := make(chan struct{})
		src.inflight[chunkIdx] = done
		src.inflightMu.Unlock()
		err := func() error {
			defer func() {
				src.inflightMu.Lock()
				delete(src.inflight, chunkIdx)
				close(done)
				src.inflightMu.Unlock()
			}()
			if src.chunkManifest != nil {
				return s.fetchChunkFromStore(chunkIdx)
			}
			return s.fetchChunkRange(chunkIdx)
		}()
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// fetchChunkRange fills one chunk over plain HTTP Range from -remote (no
// chunk manifest, no digest). The body is fully buffered and length-checked
// before anything is written to the cache, so a truncated or failed refetch
// can never partially overwrite previously verified pages.
func (s *faultServer) fetchChunkRange(chunkIdx uint64) error {
	src := s.source
	start := chunkIdx * src.chunk
	req, err := http.NewRequestWithContext(src.requestContext(), http.MethodGet, src.remote, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, start+src.chunk-1))
	resp, err := src.client.Do(req)
	if err != nil {
		return fmt.Errorf("range fetch %s [%d,+%d): %w", src.remote, start, src.chunk, err)
	}
	defer resp.Body.Close()
	if chunkDebug {
		log.Printf("DEBUG fetch chunk=%d status=%s contentLen=%s", chunkIdx, resp.Status, resp.Header.Get("Content-Length"))
	}
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("range fetch %s: status %s", src.remote, resp.Status)
	}
	// The body must deliver the whole chunk. A server that advertises a
	// shorter Content-Length is describing the artifact tail; anything less
	// than that is a truncated transfer and must be retried, not cached.
	expected := int64(src.chunk)
	if resp.ContentLength >= 0 && resp.ContentLength < expected {
		expected = resp.ContentLength
	}
	if expected <= 0 {
		// Zero-length chunk past the artifact end: touch the cache so
		// readers see zeros instead of retrying forever.
		_, _ = src.cache.WriteAt(make([]byte, 1), int64(start))
		src.inflightMu.Lock()
		src.fetched[chunkIdx] = struct{}{}
		src.inflightMu.Unlock()
		return nil
	}
	buf := make([]byte, expected)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		return fmt.Errorf("chunk %d: truncated body: %w", chunkIdx, err)
	}
	// Publish: verified bytes land in the cache first, then the bitmap —
	// readers gate on the bitmap, so they can never observe partial writes.
	if _, err := src.cache.WriteAt(buf, int64(start)); err != nil {
		return fmt.Errorf("cache chunk %d: %w", chunkIdx, err)
	}
	src.inflightMu.Lock()
	src.fetched[chunkIdx] = struct{}{}
	src.inflightMu.Unlock()
	return nil
}

// fetchChunkFromStore fills one cache chunk from the content-addressed
// store: the chunk manifest names the digest for this offset, the object is
// streamed into the cache while being hashed, and a digest mismatch aborts
// WITHOUT publishing the bitmap — corrupted or missing objects are retried,
// never served. The retry loop around fetchChunk applies unchanged.
func (s *faultServer) fetchChunkFromStore(chunkIdx uint64) error {
	src := s.source
	manifest := src.chunkManifest
	if chunkIdx >= uint64(manifest.ChunkCount) {
		// Past the manifest: the artifact tail beyond the last chunk reads
		// as zeros. Touch the cache so readers see a present chunk.
		start := chunkIdx * src.chunk
		_, _ = src.cache.WriteAt(make([]byte, 1), int64(start))
		return nil
	}
	entry := manifest.Entries[chunkIdx]
	start := uint64(entry.Offset)
	end := start + uint64(manifest.ChunkBytes)
	if end > uint64(manifest.FileSize) {
		end = uint64(manifest.FileSize)
	}
	length := end - start
	if src.zeroChunkLength(chunkIdx) > 0 {
		src.inflightMu.Lock()
		src.fetched[chunkIdx] = struct{}{}
		src.inflightMu.Unlock()
		return nil
	}

	key := chunkContentKey{digest: entry.Digest, length: length}
	for {
		src.inflightMu.Lock()
		if offset, ok := src.verifiedDigests[key]; ok {
			src.inflightMu.Unlock()
			// The source bitmap was published after verification and is never
			// overwritten. Preserve the destination's logical cache layout.
			buf := make([]byte, length)
			if _, err := src.cache.ReadAt(buf, int64(offset)); err != nil {
				return fmt.Errorf("read verified digest %s from cache: %w", entry.Digest, err)
			}
			if _, err := src.cache.WriteAt(buf, int64(start)); err != nil {
				return fmt.Errorf("copy verified digest %s to chunk %d: %w", entry.Digest, chunkIdx, err)
			}
			src.inflightMu.Lock()
			src.fetched[chunkIdx] = struct{}{}
			src.inflightMu.Unlock()
			return nil
		}
		if done, ok := src.digestInflight[key]; ok {
			src.inflightMu.Unlock()
			select {
			case <-src.requestContext().Done():
				return src.requestContext().Err()
			case <-done:
			}
			// A failed leader leaves no verified extent. Elect a new leader
			// instead of exposing bytes from an incomplete download.
			continue
		}
		if src.digestInflight == nil {
			src.digestInflight = make(map[chunkContentKey]chan struct{})
		}
		done := make(chan struct{})
		src.digestInflight[key] = done
		src.inflightMu.Unlock()
		defer func() {
			src.inflightMu.Lock()
			delete(src.digestInflight, key)
			close(done)
			src.inflightMu.Unlock()
		}()
		break
	}

	// F1: download fully into a private buffer; nothing touches the shared
	// per-sandbox cache until the bytes have passed length + digest
	// verification. A failed or truncated refetch therefore can never
	// overwrite a previously verified chunk while its bitmap bit still
	// vouches for it, and the retry loop starts from clean state.
	//
	// The persistent local cache (when configured) is consulted first:
	// hits skip the network, and any local copy that proves unusable —
	// short, unreadable, or hash-mismatched — is evicted before failing so
	// the retry refetches from the store instead of hitting the same bad
	// bytes again (F6).
	var buf []byte
	localHit := false
	httpSource := strings.HasPrefix(src.chunkStore, "http://") || strings.HasPrefix(src.chunkStore, "https://")
	if src.chunkCache != nil && httpSource {
		// M2 managed node cache: verified read, cross-process missing-chunk
		// dedup, atomic publish, watermark eviction and pins live inside the
		// manager. The miss closure is the plain store download below.
		body, err := src.chunkCache.Fetch(src.requestContext(), entry.Digest, int64(length), func(c context.Context) ([]byte, error) {
			return s.fetchStoreBody(c, manifest, entry, int(length), httpSource)
		})
		if err != nil {
			return err
		}
		buf = body
		localHit = true
	} else {
		fill := func() error {
			if httpSource && src.chunkLocal != "" {
				localPath := filepath.Join(src.chunkLocal, entry.Digest[:2], entry.Digest)
				if fileExists(localPath) {
					f, err := os.Open(localPath)
					if err != nil {
						os.Remove(localPath)
						return fmt.Errorf("persistent chunk %s unreadable (evicted): %w", entry.Digest, err)
					}
					buf = make([]byte, length)
					// Exact length on the legacy persistent path too: stat
					// decides, so short AND overlong files are both evicted.
					_, rerr := readExactLocal(f, buf)
					f.Close()
					if rerr != nil {
						os.Remove(localPath)
						return fmt.Errorf("persistent chunk %s length mismatch (evicted): %w", entry.Digest, rerr)
					}
					if chunkDebug {
						log.Printf("DEBUG local-hit chunk=%d digest=%s", chunkIdx, entry.Digest[:12])
					}
					localHit = true
					return nil
				}
			}
			body, err := s.fetchStoreBody(src.requestContext(), manifest, entry, int(length), httpSource)
			if err != nil {
				return err
			}
			buf = body
			return nil
		}
		if err := fill(); err != nil {
			return err
		}
	}
	sum := sha256.Sum256(buf)
	if got := hex.EncodeToString(sum[:]); got != entry.Digest {
		if localHit {
			// Evict the poisoned persistent copy; the retry refetches from
			// the store instead of hitting the same bad bytes again.
			os.Remove(filepath.Join(src.chunkLocal, entry.Digest[:2], entry.Digest))
			return fmt.Errorf("persistent chunk %s failed verification (hashed %s); evicted, retrying from store",
				entry.Digest, got)
		}
		return fmt.Errorf("store chunk %s digest mismatch: hashed %s", entry.Digest, got)
	}
	// Verified: publish in order — cache bytes first, then the bitmap (the
	// only gate readers consult), then the rebuildable persistent copy.
	if _, err := src.cache.WriteAt(buf, int64(start)); err != nil {
		return fmt.Errorf("cache chunk %d: %w", chunkIdx, err)
	}
	if httpSource && src.chunkLocal != "" && !localHit {
		// Queue only a reference to immutable verified bytes. Bounded workers
		// read their payload on demand, keeping fsync off the fault path.
		src.schedulePersistence(persistRef{digest: entry.Digest, offset: start, length: length})
	}

	src.inflightMu.Lock()
	if src.verifiedDigests == nil {
		src.verifiedDigests = make(map[chunkContentKey]uint64)
	}
	src.verifiedDigests[key] = start
	src.fetched[chunkIdx] = struct{}{}
	src.inflightMu.Unlock()
	if chunkDebug {
		log.Printf("DEBUG store chunk=%d digest=%s bytes=%d", chunkIdx, entry.Digest[:12], length)
	}
	return nil
}

// yieldingFetch adapts fetchChunk for background prefetch: while any
// fault-path fetch is in flight (foreground > 0), speculative bulk work
// stands down instead of competing for store bandwidth and fetch slots.
func (s *faultServer) yieldingFetch(stop <-chan struct{}) func(uint64) error {
	return func(idx uint64) error {
		for s.source.foreground.Load() > 0 {
			select {
			case <-stop:
				return nil
			case <-time.After(2 * time.Millisecond):
			}
		}
		return s.fetchChunk(idx)
	}
}

// validateChunkPrefetchFlags enforces the chunk-store prefetch contract
// (P1-D): non-negative values, workers within the execution ceiling of 16
// (the runner never silently caps a configured value), a budget within the
// watermark MiB ceiling, and — the load-bearing rule — workers > 0
// REQUIRES a finite budget. An unbounded background walk is exactly the
// "lazy restore silently downloads the whole artifact" failure mode this
// path must not have.
func validateChunkPrefetchFlags(workers, budgetMB int) error {
	if workers < 0 {
		return fmt.Errorf("-chunk-prefetch must not be negative")
	}
	if workers > maxPrefetchWorkers {
		return fmt.Errorf("-chunk-prefetch must not exceed %d workers", maxPrefetchWorkers)
	}
	if budgetMB < 0 {
		return fmt.Errorf("-chunk-prefetch-budget-mb must not be negative")
	}
	if int64(budgetMB) > chunkcache.MaxWatermarkMiB {
		return fmt.Errorf("-chunk-prefetch-budget-mb exceeds the %d MiB bound", chunkcache.MaxWatermarkMiB)
	}
	if workers > 0 && budgetMB == 0 {
		return fmt.Errorf("-chunk-prefetch requires -chunk-prefetch-budget-mb > 0 (whole-artifact background download is not allowed on the chunk-store path)")
	}
	return nil
}

// maxPrefetchWorkers is the execution ceiling for background prefetch
// concurrency; configured values are REJECTED above it (never silently
// capped — P1-G). Legacy remote-memory prefetch keeps its historical
// clamp semantics and is unaffected.
const maxPrefetchWorkers = 16

// strictEOFProbe proves a body ended EXACTLY at the expected length: any
// further byte is overlong, a clean io.EOF is success, any other error
// fails, and repeated (0, nil) no-progress reads fail with io.ErrNoProgress
// — a zero read without EOF is NOT evidence the body ended (P1-E).
func strictEOFProbe(r io.Reader, what string, length int) error {
	var probe [1]byte
	tries := 0
	for {
		n, err := r.Read(probe[:])
		if n > 0 {
			return fmt.Errorf("%s: body longer than %d bytes", what, length)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: length probe after %d bytes: %w", what, length, err)
		}
		tries++
		if tries >= 4 {
			return fmt.Errorf("%s: length probe after %d bytes: %w", what, length, io.ErrNoProgress)
		}
	}
}

// prefetchPlan separates the two prefetch regimes (P1-D). The legacy
// remote-memory URL keeps its historical flags and semantics (default 4
// workers, budget 0 = walk the whole artifact). The chunk-store CAS path is
// OPT-IN: default workers 0 (no background GETs at all), and any explicit
// enable carries the finite budget validated above. Returns the effective
// worker count and budget in bytes (0 = unbounded legacy walk).
func prefetchPlan(remote, chunkStore string, legacyWorkers, legacyBudgetMB, chunkWorkers, chunkBudgetMB int) (workers int, budgetBytes uint64) {
	if chunkStore != "" {
		if chunkWorkers <= 0 {
			return 0, 0 // chunk-store default: zero background prefetch
		}
		return chunkWorkers, uint64(chunkBudgetMB) << 20
	}
	if remote != "" && legacyWorkers > 0 {
		if legacyBudgetMB > 0 {
			return legacyWorkers, uint64(legacyBudgetMB) << 20
		}
		return legacyWorkers, 0 // legacy whole-artifact walk stays allowed
	}
	return 0, 0
}

// fetchStoreBody downloads one chunk's bytes from the store — a pack range
// read, the compressed transport body, or the plain object, in that order —
// without consulting or updating any cache. When the node cache manager is
// active this runs under its per-digest lock, making it the single network
// fetch for the digest on the node. The body is NOT yet verified: callers
// (or the cache manager) hash it against the manifest digest before use.
func (s *faultServer) fetchStoreBody(ctx context.Context, manifest *checkpointchunks.Manifest, entry checkpointchunks.Chunk, length int, httpSource bool) ([]byte, error) {
	src := s.source
	if ref, ok := manifest.Packs[entry.Digest]; ok {
		store, err := chunkstore.Open(src.chunkStore)
		if err != nil {
			return nil, err
		}
		if ctx == nil {
			ctx = context.Background()
		}
		rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		key, err := ref.Key()
		if err != nil {
			return nil, err
		}
		data, err := store.(chunkstore.RangeReader).ReadKeyRange(rctx, key, chunkstore.ObjectRange{Offset: ref.Offset, Length: ref.Length, ObjectSize: ref.ObjectSize})
		if err != nil {
			return nil, fmt.Errorf("fetch packed chunk %s: %w", entry.Digest, err)
		}
		return data, nil
	}
	buf := make([]byte, length)
	if manifest.Compression == checkpointchunks.CompressionZstd {
		// Compressed transport body: the object at the ".z" key holds
		// a zstd stream decoding to exactly this chunk's bytes. A
		// missing compressed object is not an error — chunks shared
		// with pre-compression generations keep their plain objects,
		// so fall through to the plain fetch. Verification by the
		// caller hashes the DECODED bytes against the digest.
		fillCompressed := func() (bool, error) {
			land := func(compressed []byte) error {
				plain, err := chunkstore.DecompressChunkBody(compressed, length)
				if err != nil {
					return fmt.Errorf("decompress store chunk %s: %w", entry.Digest, err)
				}
				if len(plain) != length {
					return fmt.Errorf("decompress store chunk %s: %d bytes, want %d", entry.Digest, len(plain), length)
				}
				copy(buf, plain)
				return nil
			}
			limit := chunkstore.MaxCompressedChunkBytes(int64(length))
			if httpSource {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet,
					strings.TrimRight(src.chunkStore, "/")+"/"+chunkstore.CompressedKey(entry.Digest), nil)
				if err != nil {
					return false, fmt.Errorf("build compressed chunk request %s: %w", entry.Digest, err)
				}
				resp, err := storeHTTPClient.Do(req)
				if err != nil {
					return false, fmt.Errorf("fetch compressed chunk %s: %w", entry.Digest, err)
				}
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusNotFound {
					return false, nil
				}
				if resp.StatusCode != http.StatusOK {
					return false, fmt.Errorf("fetch compressed chunk %s: status %d", entry.Digest, resp.StatusCode)
				}
				compressed, err := chunkstore.ReadBounded(resp.Body, limit)
				if err != nil {
					return false, fmt.Errorf("read compressed chunk %s: %w", entry.Digest, err)
				}
				return true, land(compressed)
			}
			f, err := os.Open(filepath.Join(src.chunkStore, chunkstore.CompressedKey(entry.Digest)))
			if err != nil {
				if chunkstore.IsNotFound(err) {
					return false, nil // plain-object fallback (shared semantic)
				}
				return false, fmt.Errorf("open compressed chunk %s: %w", entry.Digest, err)
			}
			defer f.Close()
			compressed, err := chunkstore.ReadBounded(f, limit)
			if err != nil {
				return false, fmt.Errorf("read compressed chunk %s: %w", entry.Digest, err)
			}
			return true, land(compressed)
		}
		done, err := fillCompressed()
		if err != nil {
			return nil, err
		}
		if done {
			return buf, nil
		}
	}
	if httpSource {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimRight(src.chunkStore, "/")+"/"+entry.Digest[:2]+"/"+entry.Digest, nil)
		if err != nil {
			return nil, fmt.Errorf("build store chunk request %s: %w", entry.Digest, err)
		}
		resp, err := storeHTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch store chunk %s: %w", entry.Digest, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch store chunk %s: status %d", entry.Digest, resp.StatusCode)
		}
		if _, err := io.ReadFull(resp.Body, buf); err != nil {
			return nil, fmt.Errorf("fetch store chunk %s: %w", entry.Digest, err)
		}
		// Exact length: an overlong body must be rejected, not silently
		// truncated at the chunk boundary — and the end-of-body must be
		// PROVEN, never assumed (strictEOFProbe, P1-E).
		if err := strictEOFProbe(resp.Body, fmt.Sprintf("fetch store chunk %s", entry.Digest[:12]), length); err != nil {
			return nil, err
		}
		return buf, nil
	}
	objectPath := filepath.Join(src.chunkStore, entry.Digest[:2], entry.Digest)
	f, err := os.Open(objectPath)
	if err != nil {
		return nil, fmt.Errorf("open store chunk %s: %w", entry.Digest, err)
	}
	defer f.Close()
	if _, rerr := readExactLocal(f, buf); rerr != nil {
		return nil, fmt.Errorf("store chunk %s: %w", entry.Digest, rerr)
	}
	return buf, nil
}

// readExactLocal reads exactly len(buf) bytes and requires the FILE to be
// exactly that long: short and overlong are both length errors (an overlong
// file must not be silently truncated at the chunk boundary).
func readExactLocal(f *os.File, buf []byte) (int, error) {
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return n, err
	}
	fi, serr := f.Stat()
	if serr != nil {
		return n, serr
	}
	if fi.Size() != int64(len(buf)) {
		return n, fmt.Errorf("file length %d bytes, want %d", fi.Size(), len(buf))
	}
	return n, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// maxWatermarkMiB bounds every MiB<<20 shift site (chunkcache owns the
// exact value: MaxInt64>>20, so the shift can never overflow int64).
const maxWatermarkMiB = chunkcache.MaxWatermarkMiB

// nodeCacheEnabled reports whether the M2 chunk-cache manager fronts this
// handler: an http(s) chunk store AND an explicitly configured -chunk-local
// directory. An empty -chunk-local historically means "no local persistent
// cache" and must keep working without one.
func nodeCacheEnabled(store, localDir string) bool {
	if localDir == "" {
		return false
	}
	return strings.HasPrefix(store, "http://") || strings.HasPrefix(store, "https://")
}

// chunkDebug gates the per-chunk DEBUG lines: the fault path stays log-free
// in formal runs (per-chunk logging would dominate p95 on multi-thousand
// chunk artifacts); UFFD_TRACE opts in for diagnosis.
var chunkDebug = os.Getenv("UFFD_TRACE") != ""

// runtimePinDigests lists the unique chunk digests this handler may fetch:
// every manifest entry except all-zero chunks (which never have store
// objects or cache entries). Inherited entries are included — their bytes
// are fetched by digest from the content-addressed store like any other.
func runtimePinDigests(m *checkpointchunks.Manifest) []string {
	if m == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(m.Entries))
	digests := make([]string, 0, len(m.Entries))
	for _, e := range m.Entries {
		length := min(int64(m.ChunkBytes), m.FileSize-e.Offset)
		if length > 0 && e.Digest == checkpointchunks.ZeroChunkDigest(int(length)) {
			continue
		}
		if _, dup := seen[e.Digest]; dup {
			continue
		}
		seen[e.Digest] = struct{}{}
		digests = append(digests, e.Digest)
	}
	return digests
}

// offsetWriter adapts io.Copy onto an *os.File section.
type offsetWriter struct {
	f *os.File
	n int64
}

func newOffsetWriter(f *os.File, off int64) *offsetWriter { return &offsetWriter{f: f, n: off} }

func (w *offsetWriter) Write(p []byte) (int, error) {
	n, err := w.f.WriteAt(p, w.n)
	w.n += int64(n)
	return n, err
}

type faultServer struct {
	regions   []regionMapping
	chunk     uint64
	copyBytes uint64 // opt-in forward population; zero keeps the 4KiB default
	zeroPage  bool   // experimental manifest-proven zero supply, default off
	uffdFd    int
	source    *pageSource

	mu     sync.Mutex
	served uint64
}

// tryZeroPage returns false to use COPY when this range/kernel cannot supply
// zero pages. No allocation heuristic or unverified short read authorizes it.
func (s *faultServer) tryZeroPage(r regionMapping, off, length, dst uint64) (bool, error) {
	if !s.zeroPage || s.source.file != nil || (r.PageSize != 0 && r.PageSize != 4096) {
		return false, nil
	}
	m := s.source.chunkManifest
	if m == nil || m.ChunkBytes <= 0 || length == 0 {
		return false, nil
	}
	chunk := uint64(m.ChunkBytes)
	index, within := off/chunk, off%chunk
	zeroLength := s.source.zeroChunkLength(index)
	if within >= zeroLength || length > zeroLength-within || m.Entries[index].Offset != int64(off-within) {
		return false, nil
	}
	arg := uffdioZeroArg{Range: uffdioRangeArg{Start: dst, Len: length}}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(s.uffdFd), uintptr(uffdioZeroNr), uintptr(unsafe.Pointer(&arg)))
	if errno == 0 || errno == unix.EEXIST || (errno == unix.EAGAIN && arg.Zero >= 4096) {
		// Partial progress resolves the first fault, not the untouched suffix.
		return true, nil
	}
	switch errno {
	case unix.EINVAL, unix.EOPNOTSUPP, unix.ENOTTY, unix.EAGAIN, unix.EINTR:
		// COPY handles unsupported memory types and retries with no progress.
		return false, nil
	case unix.ENOSPC, unix.EFAULT:
		// Match COPY's racing-remove behavior; a later fault retries.
		return true, nil
	default:
		return false, fmt.Errorf("UFFDIO_ZEROPAGE addr=%#x len=%d: %w", dst, length, errno)
	}
}

func (s *faultServer) resolve(addr uint64) error {
	for _, r := range s.regions {
		if addr < r.BaseHostVirtAddr || addr >= r.BaseHostVirtAddr+r.Size {
			continue
		}
		fileOff := addr - r.BaseHostVirtAddr + r.Offset
		// Start at the faulting page, never at the chunk's earlier boundary:
		// an already-present prefix would return EEXIST without resolving
		// this fault. Forward population stops at the source chunk/region.
		const pageBytes = uint64(4096)
		off := fileOff &^ (pageBytes - 1)
		copyLen := pageBytes
		chunk := s.source.chunk
		if chunk == 0 {
			chunk = s.chunk
		}
		if s.copyBytes > pageBytes && chunk >= pageBytes {
			copyLen = min(s.copyBytes, chunk-off%chunk, r.Size-(addr-r.BaseHostVirtAddr))
			copyLen &^= pageBytes - 1
			if copyLen < pageBytes {
				copyLen = pageBytes
			}
		}
		dst := r.BaseHostVirtAddr + (off - r.Offset)
		if done, err := s.tryZeroPage(r, off, copyLen, dst); err != nil {
			return err
		} else if done {
			s.mu.Lock()
			s.served++
			s.mu.Unlock()
			return nil
		}
		buf, err := s.resolveChunk(off, copyLen)
		if err != nil {
			return err
		}
		if len(buf) == 0 {
			buf = make([]byte, copyLen) // past EOF: zero fill
		}
		if uint64(len(buf)) > copyLen {
			buf = buf[:copyLen] // trim to the requested forward span
		}
		if os.Getenv("UFFD_TRACE") != "" {
			head := 8
			if len(buf) < head {
				head = len(buf)
			}
			log.Printf("TRACE copy addr=%#x fileOff=%#x off=%#x dst=%#x len=%d head=%x",
				addr, fileOff, off, dst, len(buf), buf[:head])
		}
		arg := uffdioCopyArg{
			Dst:  dst,
			Src:  uint64(uintptr(unsafe.Pointer(&buf[0]))),
			Len:  uint64(len(buf)),
			Mode: 0, // UFFDIO_COPY wakes the faulting thread by default.
		}
		for {
			_, _, errno := unix.Syscall(
				unix.SYS_IOCTL, uintptr(s.uffdFd),
				uintptr(uffdioCopyNr), uintptr(unsafe.Pointer(&arg)),
			)
			runtime.KeepAlive(buf) // ioctl holds only the numeric source address
			if errno == 0 {
				break
			}
			if errno == unix.EEXIST {
				// Another thread already resolved this fault.
				return nil
			}
			if errno == unix.EAGAIN {
				// A partial COPY may stop at a later resident page. The
				// kernel has populated and woken the copied prefix; the
				// faulting first page is done. Do not retry from a chunk
				// boundary or claim that the unfilled suffix is resident.
				if arg.Copy >= int64(pageBytes) {
					break
				}
				continue
			}
			if errno == unix.ENOSPC || errno == unix.EFAULT {
				// Mostly seen with a racing remove; the fault will retry.
				return nil
			}
			return fmt.Errorf("UFFDIO_COPY addr=%#x len=%d: %w", addr, arg.Len, errno)
		}
		s.mu.Lock()
		s.served++
		s.mu.Unlock()
		return nil
	}
	return fmt.Errorf("pagefault address %#x outside all guest regions", addr)
}

func (s *faultServer) wake(start, length uint64) {
	arg := uffdioRangeArg{Start: start, Len: length}
	//nolint:errcheck // best effort ack
	unix.Syscall(unix.SYS_IOCTL, uintptr(s.uffdFd), uintptr(uffdioWakeNr), uintptr(unsafe.Pointer(&arg)))
}

// recvHandshake accepts Firecracker's connection and decodes the JSON mapping
// table plus the uffd descriptor passed via SCM_RIGHTS. The connection is
// returned OPEN: Firecracker never sends more data on it, so a read-side EOF
// is the reliable signal that the VMM process is gone — the uffd descriptor
// itself cannot provide one, because this handler holds the last reference
// after the VMM exits and userfaultfd never polls HUP for its holder.
//
// Cancellation is bounded: ctx closes the listening socket to unblock Accept
// and closes the accepted connection to unblock an incomplete ReadMsgUnix —
// neither syscall can wait on a context. Every rejection path closes the
// accepted connection, and a handshake that raced cancellation is never
// handed out as live. The kernel installs any SCM_RIGHTS descriptors the
// moment the read returns, so descriptors this handler does not consume are
// closed instead of leaking until process exit.
func recvHandshake(ctx context.Context, l net.Listener) ([]regionMapping, int, *net.UnixConn, error) {
	unblockAccept := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer unblockAccept()
	conn, err := l.Accept()
	if err != nil {
		return nil, -1, nil, fmt.Errorf("accept: %w", err)
	}
	c, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, -1, nil, errors.New("unexpected connection type")
	}
	// fail closes the accepted connection on every rejection below; the
	// callback above may already be closing it after a lost stop race, which
	// is idempotent.
	fail := func(err error) ([]regionMapping, int, *net.UnixConn, error) {
		_ = c.Close()
		return nil, -1, nil, err
	}
	buf := make([]byte, 4096)
	oob := make([]byte, 128)
	unblockRead := context.AfterFunc(ctx, func() { _ = c.Close() })
	n, oobn, flags, _, readErr := c.ReadMsgUnix(buf, oob)
	// SCM_RIGHTS descriptors are installed before ReadMsgUnix returns. Own
	// every received fd before taking cancellation or payload-error branches.
	var received []int
	kept := -1
	defer func() {
		for _, fd := range received {
			if fd != kept {
				_ = unix.Close(fd)
			}
		}
	}()
	cmsgs, controlErr := unix.ParseSocketControlMessage(oob[:oobn])
	if controlErr == nil {
		for _, cm := range cmsgs {
			if cm.Header.Level != unix.SOL_SOCKET || cm.Header.Type != unix.SCM_RIGHTS {
				continue
			}
			fds, err := unix.ParseUnixRights(&cm)
			if err != nil {
				controlErr = err
				break
			}
			received = append(received, fds...)
		}
	}
	stoppedCallback := unblockRead()
	if !stoppedCallback || ctx.Err() != nil {
		return fail(fmt.Errorf("handshake canceled: %w", ctx.Err()))
	}
	if readErr != nil {
		return fail(fmt.Errorf("read handshake: %w", readErr))
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return fail(errors.New("truncated handshake or descriptor message"))
	}
	if controlErr != nil {
		return fail(fmt.Errorf("parse control message: %w", controlErr))
	}
	var regions []regionMapping
	if err := json.Unmarshal(buf[:n], &regions); err != nil {
		return fail(fmt.Errorf("decode mappings %q: %w", string(buf[:n]), err))
	}
	if len(received) == 0 {
		return fail(errors.New("handshake carried no file descriptor"))
	}
	kept = received[0]
	return regions, kept, c, nil
}

// fileFullyAllocated reports whether path is a regular file whose allocated
// blocks cover its size — i.e. it has no holes. A blind-materialized memory
// file starts sparse (real bytes in the chunk store); a Firecracker-written
// image is fully allocated. When the stat cannot be narrowed to a Unix
// inode, assume allocated.
func fileFullyAllocated(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return uint64(st.Blocks)*512 >= uint64(info.Size())
}

// storeHTTPClient is the shared client for chunk-store fetches. A bounded
// timeout keeps a wedged store from occupying fault workers indefinitely
// (the default client has none).
var storeHTTPClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 16,
	},
}

// materializedMarkerPresent reports whether the artifact directory carries
// the blind-materialization marker naming the memory file as a remote
// placeholder.
func materializedMarkerPresent(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, ".materialized"))
	return !os.IsNotExist(err)
}

// uffdPollTimeoutMs bounds a single uffd wait. It is a fallback cadence for
// re-checking stop, not the shutdown latency: shutdown interrupts the wait
// through the cancellation wake descriptor below, so the timeout keeps its
// old value instead of being shortened.
const uffdPollTimeoutMs = 500

// cancelWake turns shutdown into readability on a polled descriptor. The uffd
// itself cannot report the VMM disappearing (see recvHandshake), and poll
// cannot watch a Go channel, so the fault loop polls the uffd together with
// this eventfd and shutdown writes it before any teardown that could block:
// a poll blocked on the uffd then returns immediately instead of sleeping out
// the timeout above.
//
// Ownership: the wait loop owns the descriptor and is the only side allowed
// to close it, after its final poll has returned. wake may be called from any
// goroutine at any time; it never writes after close — both take the same
// mutex and close latches first — so a descriptor number recycled by an
// unrelated open can never receive a stale wake write.
type cancelWake struct {
	mu     sync.Mutex
	fd     int
	closed bool
}

func newCancelWake() (*cancelWake, error) {
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	return &cancelWake{fd: fd}, nil
}

// pollFd returns the descriptor to include in the fault loop's poll set.
func (w *cancelWake) pollFd() unix.PollFd {
	return unix.PollFd{Fd: int32(w.fd), Events: unix.POLLIN}
}

// wake makes the descriptor readable until drained or closed. Repeated calls
// (repeated shutdown attempts) only add to the counter; saturation returns
// EAGAIN while leaving the descriptor readable, which is all wake promises.
// Best effort: if a write fails some other way, the poll timeout above still
// bounds how long the loop stays unaware of shutdown.
func (w *cancelWake) wake() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	var one [8]byte
	binary.NativeEndian.PutUint64(one[:], 1)
	for {
		_, err := unix.Write(w.fd, one[:])
		if err != unix.EINTR {
			return
		}
	}
}

// drain resets readiness so a wake that is not followed by a closed stop
// cannot spin the wait loop on an already-readable descriptor. Reading an
// idle nonblocking eventfd returns EAGAIN, which is the desired outcome.
func (w *cancelWake) drain() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	var buf [8]byte
	for {
		_, err := unix.Read(w.fd, buf[:])
		if err != unix.EINTR {
			return
		}
	}
}

// close is idempotent: a second close must not shut a descriptor number that
// has since been recycled by an unrelated open.
func (w *cancelWake) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	unix.Close(w.fd)
}

// pollUffdOrCancel waits for uffd readiness, uffd hangup, or a shutdown wake.
// EINTR is returned unwrapped so the caller retries the wait; a zero return
// with no flags is the timeout fallback, preserving the old single-descriptor
// poll semantics with only the wake descriptor added.
func pollUffdOrCancel(uffdFd int, wake *cancelWake, timeoutMs int) (cancelWoke, uffdReady, uffdHungUp bool, err error) {
	fds := []unix.PollFd{{Fd: int32(uffdFd), Events: unix.POLLIN}, wake.pollFd()}
	if _, err := unix.Poll(fds, timeoutMs); err != nil {
		return false, false, false, err
	}
	if fds[0].Revents&unix.POLLNVAL != 0 || fds[1].Revents&unix.POLLNVAL != 0 {
		return false, false, false, unix.EBADF
	}
	if fds[1].Revents&unix.POLLIN != 0 {
		// Shutdown closes stop before waking (runShutdown), so the caller's
		// stop check exits; draining keeps a wake without a closed stop —
		// only reachable from tests — from spinning on readability.
		wake.drain()
		cancelWoke = true
	}
	if fds[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
		uffdHungUp = true
	}
	if fds[0].Revents&unix.POLLIN != 0 {
		uffdReady = true
	}
	return cancelWoke, uffdReady, uffdHungUp, nil
}

// sourceStopper is the teardown half of shutdown. Splitting it out keeps
// runShutdown's ordering — wake before the potentially blocking persistence
// stop — directly testable without a live pageSource.
type sourceStopper interface {
	stopPersistence() *chunkPersister
}

// runShutdown performs the handler teardown exactly once. Order matters:
// close(stop) makes the woken loop exit rather than re-poll, wake interrupts
// any poll blocked on the uffd BEFORE the steps below it may block, and the
// source cancel plus persistence stop keep their original sequence so fault
// workers and persister workers still observe the same shutdown.
func runShutdown(once *sync.Once, stop chan struct{}, wake *cancelWake, cancelSource context.CancelFunc, src sourceStopper) {
	once.Do(func() {
		close(stop)
		wake.wake()
		cancelSource()
		src.stopPersistence()
	})
}

// startupCanceled reports whether err is the result of termination being
// requested during startup and, if so, logs an ordinary-exit line. main uses
// it to return instead of log.Fatal: a canceled startup must still run its
// deferred cleanup (socket path removal, context and signal-notifier
// release), which log.Fatal skips by exiting the process immediately.
func startupCanceled(sigCtx context.Context, err error) bool {
	if sigCtx.Err() == nil {
		return false
	}
	log.Printf("handler startup canceled: %v", err)
	return true
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	sockPath := flag.String("sock", "", "unix socket path Firecracker will connect to")
	backingPath := flag.String("backing", "", "local checkpoint memory file (local mode)")
	remoteURL := flag.String("remote", "", "HTTP(S) URL of the artifact memory file (remote mode)")
	cachePath := flag.String("cache", "", "sparse local cache file (remote mode)")
	chunkStorePath := flag.String("chunk-store", "",
		"content-addressed chunk store directory or http(s) object endpoint; a chunks.json next to the backing file switches fetches to per-chunk digest lookups")
	chunkLocalDir := flag.String("chunk-local", "",
		"local content-addressed cache directory fronting an http chunk-store: hits never touch the network, misses are verified and persisted here")
	chunkKB := flag.Uint("chunk-kb", 4, "remote fetch/cache chunk size in KiB (manifest may override)")
	workers := flag.Int("workers", 8, "concurrent UFFDIO_COPY workers")
	copyKB := flag.Int("copy-kb", 4, "forward UFFD population span in KiB (4..256, multiple of 4; experimental above 4)")
	zeroPage := flag.Bool("zero-page", false, "experimentally supply manifest-proven zero chunks with UFFDIO_ZEROPAGE")
	prefetch := flag.Int("prefetch", 4, "background chunk prefetch concurrency (legacy remote-memory path only; 0 = disabled)")
	prefetchBudgetMB := flag.Int("prefetch-budget-mb", 0, "cap background prefetch to this many MiB (legacy remote-memory path; 0 = walk the whole artifact)")
	chunkPrefetch := flag.Int("chunk-prefetch", 0,
		"background prefetch concurrency for the chunk-store path (0 = disabled, the default; this path is opt-in and never implicitly warms the whole artifact)")
	chunkPrefetchBudgetMB := flag.Int("chunk-prefetch-budget-mb", 0,
		"hard cap in MiB for chunk-store background prefetch; REQUIRED > 0 whenever -chunk-prefetch is set")
	persistWorkers := flag.Int("persist-workers", persistenceWorkers, "background persistent cache IO workers (1-64)")
	cacheHighMB := flag.Int64("chunk-cache-high-mb", 0, "node cache high watermark in MiB (0 keeps the historical unbounded cache)")
	cacheLowMB := flag.Int64("chunk-cache-low-mb", 0, "node cache low watermark in MiB; eviction (when enabled) stops here")
	flag.Parse()
	if *copyKB < 4 || *copyKB > 256 || *copyKB%4 != 0 {
		log.Fatal("-copy-kb must be a multiple of 4 between 4 and 256")
	}
	if *persistWorkers < 1 || *persistWorkers > 64 {
		log.Fatal("-persist-workers must be between 1 and 64")
	}
	if err := chunkcache.ValidWatermarkMiB(*cacheHighMB, *cacheLowMB); err != nil {
		log.Fatalf("-chunk-cache-high-mb/-chunk-cache-low-mb: %v", err)
	}
	if *prefetchBudgetMB < 0 {
		log.Fatal("-prefetch-budget-mb must not be negative (0 = whole artifact)")
	}
	if int64(*prefetchBudgetMB) > chunkcache.MaxWatermarkMiB {
		log.Fatalf("-prefetch-budget-mb exceeds the %d MiB bound", chunkcache.MaxWatermarkMiB)
	}
	if err := validateChunkPrefetchFlags(*chunkPrefetch, *chunkPrefetchBudgetMB); err != nil {
		log.Fatal(err)
	}
	if *sockPath == "" || (*backingPath == "" && *remoteURL == "") {
		log.Fatal("-sock plus -backing or -remote is required")
	}
	// Termination is part of the protocol with the runtime that owns this
	// handler: SIGTERM can arrive before the VMM ever connects (a cancelled
	// ownership handover) or at any point while serving. The notifier is
	// installed before the socket is published so no signal can beat it and
	// fall back to the default fatal disposition; every blocking wait below
	// is unblocked through sigCtx instead.
	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stopSignals()
	os.Remove(*sockPath)
	l, err := net.Listen("unix", *sockPath)
	if err != nil {
		log.Fatalf("bind %s: %v", *sockPath, err)
	}
	defer os.Remove(*sockPath)
	defer l.Close()

	// Remote mode stages chunks in a sparse local cache. The bulk download
	// runs after the handshake (below) concurrently with fault serving: a
	// single sequential stream keeps cache writes ordered, and resolveChunk
	// treats partially written chunks as misses so faults never race the
	// writer (see readCache).
	chunk := uint64(*chunkKB) << 10
	// The source context derives from the signal context so termination also
	// aborts in-flight artifact fetches, while the serving shutdown path
	// below still cancels the source on its own (VMM EOF, uffd hangup).
	sourceCtx, cancelSource := context.WithCancel(sigCtx)
	defer cancelSource()
	source := &pageSource{
		ctx:                    sourceCtx,
		persistenceWorkerCount: *persistWorkers,
		chunk:                  chunk,
		inflight:               make(map[uint64]chan struct{}),
		fetched:                make(map[uint64]struct{}),
	}
	if *remoteURL != "" {
		cacheFile, err := os.OpenFile(*cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			log.Fatalf("open cache file %s: %v", *cachePath, err)
		}
		source.cache = cacheFile
		source.cachePath = *cachePath
		source.remote = *remoteURL
		source.client = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
			MaxIdleConnsPerHost: 16,
		}}
		// Cache writes go through fetchChunk which serializes via inflight.
	} else if *chunkStorePath != "" {
		local, err := openLocalMemoryBacking(sourceCtx, *backingPath)
		if err != nil {
			// The verification context derives from sigCtx, so termination
			// surfaces here as an ordinary canceled exit.
			if startupCanceled(sigCtx, err) {
				return
			}
			log.Fatalf("verify local backing: %v", err)
		}
		if local != nil {
			source.file = local
			log.Printf("complete local memory image; serving backing file directly")
		} else {
			manifest, err := checkpointchunks.LoadTransport(filepath.Dir(*backingPath))
			if err != nil {
				log.Fatalf("remote placeholder manifest unusable: %v", err)
			}
			cacheFile, cerr := os.OpenFile(*cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
			if cerr != nil {
				log.Fatalf("open cache file %s: %v", *cachePath, cerr)
			}
			source.cache = cacheFile
			source.cachePath = *cachePath
			source.chunkManifest = manifest
			source.chunkStore = *chunkStorePath
			source.chunkLocal = *chunkLocalDir
			// M2 node cache: only when -chunk-local is CONFIGURED does the
			// manager front it — an http store with an empty -chunk-local
			// keeps the historical no-local-persistent-cache behavior (D:
			// opening a manager on an empty root would fatal and break
			// those restores).
			if nodeCacheEnabled(*chunkStorePath, *chunkLocalDir) {
				manager, err := chunkcache.Open(chunkcache.Config{
					Root:          *chunkLocalDir,
					HighWatermark: *cacheHighMB << 20,
					LowWatermark:  *cacheLowMB << 20,
					StoreDomain:   *chunkStorePath,
					Logger:        log.New(os.Stderr, "uffd-chunkcache ", log.LstdFlags|log.Lmicroseconds),
				})
				if err != nil {
					log.Fatalf("open node chunk cache %s: %v", *chunkLocalDir, err)
				}
				defer manager.Close()
				source.chunkCache = manager
				// Runtime pin: this handler's whole working set stays
				// eviction-protected for the process lifetime; process exit
				// (crash included) drops the flock, so the pin never leaks.
				if release, err := manager.PinContext(sourceCtx, fmt.Sprintf("uffd-%d", os.Getpid()), runtimePinDigests(manifest)); err != nil {
					if manager.WatermarksArmed() {
						// With eviction armed, serving unpinned would silently
						// drop the pin gate: fail closed.
						log.Fatalf("node cache runtime pin failed (eviction armed): %v", err)
					}
					log.Printf("node cache runtime pin failed (eviction disabled, continuing): %v", err)
				} else {
					defer release()
				}
			}
			if uint64(manifest.ChunkBytes) != chunk {
				log.Printf("chunk size %dKiB from manifest overrides flag (%dKiB)",
					manifest.ChunkBytes>>10, chunk>>10)
				source.chunk = uint64(manifest.ChunkBytes)
			}
			log.Printf("chunk source: %d chunks from store %s", manifest.ChunkCount, *chunkStorePath)
		}
	} else {
		file, err := openLocalMemoryBacking(sourceCtx, *backingPath)
		if err != nil {
			if startupCanceled(sigCtx, err) {
				return
			}
			log.Fatalf("verify local backing: %v", err)
		}
		if file == nil {
			log.Fatal("remote placeholder requires a chunk store")
		}
		source.file = file
	}
	regions, fd, vmmConn, err := recvHandshake(sigCtx, l)
	// The handshake connection is the protocol's only client; stop accepting.
	// The close is idempotent with the cancellation hook inside recvHandshake.
	_ = l.Close()
	if err != nil {
		if startupCanceled(sigCtx, err) {
			return
		}
		log.Fatalf("handshake: %v", err)
	}
	defer vmmConn.Close()
	defer unix.Close(fd)
	s := &faultServer{
		regions:   regions,
		copyBytes: uint64(*copyKB) << 10,
		zeroPage:  *zeroPage,
		chunk:     chunk,
		uffdFd:    fd,
		source:    source,
	}
	log.Printf("handler ready: %d regions, chunk=%dKiB, workers=%d",
		len(regions), *chunkKB, *workers)
	if os.Getenv("UFFD_TRACE") != "" {
		for i, r := range regions {
			log.Printf("TRACE region[%d] base=%#x size=%#x offset=%#x", i,
				r.BaseHostVirtAddr, r.Size, r.Offset)
		}
	}

	faults := make(chan uint64, 4096)
	var wg sync.WaitGroup
	var background sync.WaitGroup
	stop := make(chan struct{})
	// Explicit cancellation wake: the fault loop below polls the uffd
	// together with this descriptor so shutdown interrupts a blocked wait
	// immediately instead of sleeping out uffdPollTimeoutMs after VMM EOF.
	wake, err := newCancelWake()
	if err != nil {
		log.Fatalf("create cancel wake: %v", err)
	}
	defer wake.close()
	var stopOnce sync.Once
	shutdown := func() {
		runShutdown(&stopOnce, stop, wake, cancelSource, source)
	}

	// The VMM never writes after the handshake, so a read-side EOF on the
	// handshake connection means the Firecracker process is gone (stopped,
	// crashed, or the sandbox was deleted) and this handler must exit
	// instead of lingering as an orphan. The uffd descriptor cannot signal
	// this: after the VMM exits this handler holds the last reference, and
	// userfaultfd never reports HUP to its own holder.
	background.Add(1)
	go func() {
		defer background.Done()
		buf := make([]byte, 1)
		for {
			if _, err := vmmConn.Read(buf); err != nil {
				log.Printf("vmm connection closed (%v); exiting", err)
				shutdown()
				return
			}
			// Any unexpected inbound byte is ignored; the protocol has no
			// further messages.
		}
	}()

	// Termination after the handshake takes the same shutdown path as the VMM
	// EOF above — stop, wake, cancel the source, stop persistence — so the
	// joins below still run instead of the default signal fatality. The
	// watcher shares the background group but also exits on stop, which an
	// EOF-triggered shutdown closes: the exit must never wait on a signal
	// that never arrives, and shutdown itself only signals and never joins,
	// so the watcher cannot deadlock against the exit it triggers.
	background.Add(1)
	go func() {
		defer background.Done()
		select {
		case <-sigCtx.Done():
			log.Printf("termination signal received; shutting down")
			shutdown()
		case <-stop:
		}
	}()

	// Background bulk download: sequentially fetchChunk every chunk. This
	// runs concurrently with fault serving — the inflight dedup in
	// Background prefetch warms the artifact with a bounded worker pool.
	// The two source regimes are deliberately different (P1-D):
	//   - legacy remote-memory URL: -prefetch keeps its historical default
	//     (4 workers, budget 0 = whole artifact);
	//   - chunk-store CAS: prefetch is OPT-IN via -chunk-prefetch and MUST
	//     carry a finite -chunk-prefetch-budget-mb — the default is lazy
	//     restore with ZERO background GETs, so a chunk-store deployment
	//     never implicitly downloads an entire artifact's memory.
	// fetchChunk's inflight tracking makes concurrent prefetch with fault
	// serving safe: each chunk moves at most once, faults wait on the same
	// cancelable completion channel, and yieldingFetch keeps foreground
	// faults ahead of queued speculative work.
	pfWorkers, pfBudgetBytes := prefetchPlan(source.remote, source.chunkStore,
		*prefetch, *prefetchBudgetMB, *chunkPrefetch, *chunkPrefetchBudgetMB)
	if pfWorkers > 0 && os.Getenv("UFFD_NO_BULK") == "" {
		background.Add(1)
		go func() {
			defer background.Done()
			// Walk at the granularity the artifact actually uses: a chunk
			// manifest overrides the flag's chunk size, and counting with
			// the stale flag would over- or under-fetch at non-default
			// sizes (F7).
			walk := chunk
			if source.chunkManifest != nil && source.chunkManifest.ChunkBytes > 0 {
				walk = uint64(source.chunkManifest.ChunkBytes)
			}
			budgetBytes := pfBudgetBytes
			totalChunks := uint64(0)
			for _, r := range regions {
				totalChunks += (r.Size + walk - 1) / walk
			}
			log.Printf("prefetch: starting walk=%dKiB totalChunks=%d workers=%d manifest=%v",
				walk>>10, totalChunks, pfWorkers, source.chunkManifest != nil)
			if budgetBytes > 0 {
				maxByBudget := budgetBytes / walk
				if maxByBudget < totalChunks {
					totalChunks = maxByBudget
					log.Printf("prefetch: budget %dMiB caps walk at %d chunks", budgetBytes>>20, totalChunks)
				}
			}
			workers := pfWorkers
			if workers > maxPrefetchWorkers {
				workers = maxPrefetchWorkers
			}
			if workers > int(totalChunks) {
				workers = int(totalChunks)
			}
			startT := time.Now()
			completed, err := runPrefetch(stop, totalChunks, workers, s.yieldingFetch(stop))
			if err != nil {
				log.Printf("prefetch stopped after %d/%d chunks: %v", completed, totalChunks, err)
				return
			}
			log.Printf("prefetch: %d chunks in %.2fs (concurrency %d)",
				completed, time.Since(startT).Seconds(), workers)
		}()
	}

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range faults {
				if err := s.resolve(addr); err != nil {
					log.Printf("resolve %x: %v", addr, err)
					// Wake anyway so the guest does not spin forever on a
					// single unrecoverable page.
					s.wake(addr&^0xFFF, 0x1000)
				}
			}
		}()
	}

	// Fault counters for observability; printed on exit and every 10s while
	// faults are in flight.
	tick := time.NewTicker(10 * time.Second)
	background.Add(1)
	go func() {
		defer background.Done()
		var last uint64
		for {
			select {
			case <-tick.C:
				s.mu.Lock()
				now := s.served
				s.mu.Unlock()
				if now != last {
					log.Printf("served=%d (+%d)", now, now-last)
					last = now
				}
			case <-stop:
				tick.Stop()
				return
			}
		}
	}()

	msg := make([]byte, uffdMsgSize)
	for {
		woke, ready, hungUp, perr := pollUffdOrCancel(fd, wake, uffdPollTimeoutMs)
		if perr != nil {
			if perr == unix.EINTR {
				continue
			}
			log.Fatalf("poll uffd: %v", perr)
		}
		select {
		case <-stop:
			goto done
		default:
		}
		if hungUp {
			break // Firecracker is gone.
		}
		if woke || !ready {
			// Cancel wake (stop is closed — handled above, and the helper
			// drained the descriptor) or the timeout fallback: wait again.
			continue
		}
		for {
			got, err := unix.Read(fd, msg)
			if err != nil {
				if err == unix.EAGAIN {
					break
				}
				if err == unix.EINTR {
					continue
				}
				log.Fatalf("read uffd msg: %v", err)
			}
			if got < uffdMsgSize {
				continue
			}
			switch msg[0] {
			case uffdEventPagefault:
				addr := binary.LittleEndian.Uint64(msg[16:24])
				select {
				case faults <- addr &^ 0xFFF:
				case <-stop:
				}
			case uffdEventRemove:
				start := binary.LittleEndian.Uint64(msg[8:16])
				end := binary.LittleEndian.Uint64(msg[16:24])
				// Ballooning is not configured for our guests; acknowledge the
				// event so later ioctls do not stall behind it.
				s.wake(start, end-start)
			default:
				// Events we do not act on (fork/remap/unmap do not occur with
				// this VMM configuration).
			}
		}
	}
done:
	shutdown()
	// Unblock the EOF watcher even when shutdown came from the uffd.
	_ = vmmConn.Close()
	close(faults)
	wg.Wait()
	background.Wait()
	// Pending cache entries are disposable; already-started writes must
	// finish before the process claims that all its work has stopped.
	source.waitPersistence()
	s.mu.Lock()
	total := s.served
	s.mu.Unlock()
	if source.chunkCache != nil {
		// One summary line per handler LIFETIME (never per fault: the hot
		// path stays log-free). Observers diff this across restores to
		// prove memory chunks were served from the node cache.
		cs := source.chunkCache.Status()
		log.Printf("handler exiting, total faults served=%d chunk_cache hits=%d misses=%d hit_bytes=%d miss_bytes=%d evictions=%d pinned=%d",
			total, cs.Hits, cs.Misses, cs.HitBytes, cs.MissBytes, cs.Evictions, cs.PinnedEntries)
	} else {
		log.Printf("handler exiting, total faults served=%d", total)
	}
}
