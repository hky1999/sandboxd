// Command firecracker-uffd-handler serves guest memory pages to a Firecracker
// microVM restored with the UFFD memory backend.
//
// Protocol (see firecracker src/vmm/src/persist.rs guest_memory_from_uffd):
// the handler binds the UDS path first; on /snapshot/load Firecracker connects
// and sends a JSON array of guest region mappings together with the userfaultfd
// descriptor via SCM_RIGHTS. Each pagefault event is resolved by copying
// chunk bytes from the backing file into the guest memory with UFFDIO_COPY.
//
// The handler exits when Firecracker disconnects (VM stopped) or the uffd
// descriptor is hung up.
package main

import (
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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
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

// pageSource resolves a chunk of guest memory content: either directly from
// a local backing file, or through a sparse local cache filled from a remote
// HTTP range source on miss.
type pageSource struct {
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

	inflightMu sync.Mutex
	inflight   map[uint64]*sync.WaitGroup // chunk index -> waiters' group
	// fetched records the chunks whose cache bytes are fully written. A
	// sparse hole inside the cache reads back as a full-length run of
	// zeros once the file has been extended past it by ANY other chunk's
	// write, so length cannot distinguish "written" from "hole": only the
	// bitmap can. Guarded by inflightMu.
	fetched map[uint64]struct{}
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
	// A chunk is readable only once its fetch completed (bitmap). Reading
	// before that can return a hole: another worker's write to a higher
	// chunk extends the sparse file, and ReadAt then returns a full-length
	// zero buffer for this chunk's unwritten extent — indistinguishable
	// from real data by length alone.
	src.inflightMu.Lock()
	_, ready := src.fetched[chunkIdx]
	src.inflightMu.Unlock()
	if !ready {
		if err := s.fetchChunk(chunkIdx); err != nil {
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
// enclosing chunk's bytes are fully written: a sparse hole reads back as a
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
	const attempts = 3
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 50 * time.Millisecond)
		}
		src.inflightMu.Lock()
		if wg, ok := src.inflight[chunkIdx]; ok {
			src.inflightMu.Unlock()
			wg.Wait()
			return nil // someone fetched it; caller re-reads the cache
		}
		wg := &sync.WaitGroup{}
		wg.Add(1)
		src.inflight[chunkIdx] = wg
		src.inflightMu.Unlock()
		err := func() error {
			defer wg.Done()
			defer func() {
				src.inflightMu.Lock()
				delete(src.inflight, chunkIdx)
				src.inflightMu.Unlock()
			}()
			if src.chunkManifest != nil {
				return s.fetchChunkFromStore(chunkIdx)
			}
			start := chunkIdx * src.chunk
			req, err := http.NewRequest(http.MethodGet, src.remote, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, start+src.chunk-1))
			resp, err := src.client.Do(req)
			if err != nil {
				return fmt.Errorf("range fetch %s [%d,+%d): %w", src.remote, start, src.chunk, err)
			}
			defer resp.Body.Close()
			log.Printf("DEBUG fetch chunk=%d status=%s contentLen=%s", chunkIdx, resp.Status, resp.Header.Get("Content-Length"))
			if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
				return fmt.Errorf("range fetch %s: status %s", src.remote, resp.Status)
			}
			// The body must deliver the whole chunk. A server that
			// advertises a shorter Content-Length is describing the
			// artifact tail; anything less than that is a truncated
			// transfer and must be retried, not cached.
			expected := int64(src.chunk)
			if resp.ContentLength >= 0 && resp.ContentLength < expected {
				expected = resp.ContentLength
			}
			// Copy straight into the sparse cache at the chunk offset.
			written, err := io.Copy(newOffsetWriter(src.cache, int64(start)), resp.Body)
			if err != nil {
				return fmt.Errorf("cache chunk %d: %w", chunkIdx, err)
			}
			if written < expected {
				return fmt.Errorf("chunk %d: truncated body %d bytes, want %d",
					chunkIdx, written, expected)
			}
			if written == 0 {
				// Zero-length chunk past the artifact end: touch the cache so
				// readers see zeros instead of retrying forever.
				_, _ = src.cache.WriteAt(make([]byte, 1), int64(start))
			}
			// Publish the chunk before the deferred inflight cleanup wakes
			// any waiter: from here on ReadAt cannot observe a hole for it.
			src.inflightMu.Lock()
			src.fetched[chunkIdx] = struct{}{}
			src.inflightMu.Unlock()
			return nil
		}()
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
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

	// The chunk store is either a local directory tree or an HTTP object
	// endpoint (S3 REST anonymous subset); both speak the same <aa>/<digest>
	// key layout and both are verified by the digest below. An http store
	// fronted by -chunk-local consults the persistent local cache first:
	// hits never touch the network, misses stream once and land in both the
	// per-sandbox sparse cache and the persistent local cache. A persistent
	// copy that fails verification is evicted so the retry refetches from
	// the store instead of poisoning every attempt.
	var body io.Reader
	localHitPath := ""
	httpSource := strings.HasPrefix(src.chunkStore, "http://") || strings.HasPrefix(src.chunkStore, "https://")
	if httpSource && src.chunkLocal != "" {
		if localPath := filepath.Join(src.chunkLocal, entry.Digest[:2], entry.Digest); fileExists(localPath) {
			f, err := os.Open(localPath)
			if err != nil {
				return fmt.Errorf("open local chunk %s: %w", entry.Digest, err)
			}
			defer f.Close()
			log.Printf("DEBUG local-hit chunk=%d digest=%s", chunkIdx, entry.Digest[:12])
			body = io.LimitReader(f, int64(length))
			localHitPath = localPath
			httpSource = false // served locally; skip the persist step
		}
	}
	if body == nil {
		if strings.HasPrefix(src.chunkStore, "http://") || strings.HasPrefix(src.chunkStore, "https://") {
			resp, err := storeHTTPClient.Get(strings.TrimRight(src.chunkStore, "/") +
				"/" + entry.Digest[:2] + "/" + entry.Digest)
			if err != nil {
				return fmt.Errorf("fetch store chunk %s: %w", entry.Digest, err)
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return fmt.Errorf("fetch store chunk %s: status %d", entry.Digest, resp.StatusCode)
			}
			defer resp.Body.Close()
			body = io.LimitReader(resp.Body, int64(length))
		} else {
			objectPath := filepath.Join(src.chunkStore, entry.Digest[:2], entry.Digest)
			f, err := os.Open(objectPath)
			if err != nil {
				return fmt.Errorf("open store chunk %s: %w", entry.Digest, err)
			}
			defer f.Close()
			body = io.LimitReader(f, int64(length))
			httpSource = false // a directory store needs no local persist
		}
	}

	hash := sha256.New()
	var persist *os.File
	var persistPath string
	if httpSource && src.chunkLocal != "" {
		// Persist this fetch for the next sandbox on the node. The temp
		// file is renamed in only after the digest verifies, so the local
		// cache never holds a partial or corrupt object.
		persistPath = filepath.Join(src.chunkLocal, entry.Digest[:2], entry.Digest)
		if err := os.MkdirAll(filepath.Dir(persistPath), 0o755); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(persistPath), ".put-*")
		if err != nil {
			return err
		}
		persist = tmp
	}
	sink := io.Writer(newOffsetWriter(src.cache, int64(start)))
	if persist != nil {
		sink = io.MultiWriter(sink, persist)
	}
	written, err := io.Copy(sink, io.TeeReader(body, hash))
	if err != nil {
		if persist != nil {
			persist.Close()
			os.Remove(persist.Name())
		}
		return fmt.Errorf("cache chunk %d from store: %w", chunkIdx, err)
	}
	if uint64(written) != length {
		if persist != nil {
			persist.Close()
			os.Remove(persist.Name())
		}
		return fmt.Errorf("store chunk %s short: %d bytes, want %d", entry.Digest, written, length)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != entry.Digest {
		if persist != nil {
			persist.Close()
			os.Remove(persist.Name())
		}
		if localHitPath != "" {
			// Evict the poisoned persistent copy; fetchChunk's retry then
			// refetches from the store instead of hitting the same bad
			// bytes again.
			os.Remove(localHitPath)
			return fmt.Errorf("persistent chunk %s failed verification (hashed %s); evicted, retrying from store",
				entry.Digest, got)
		}
		return fmt.Errorf("store chunk %s digest mismatch: hashed %s", entry.Digest, got)
	}
	if persist != nil {
		// The bytes are already in the per-sandbox cache and verified, so
		// the fault can be served now; the persistent copy is rebuildable
		// state, and its fsync+rename moves off the fault's critical path
		// (P4: a per-chunk fsync blocked every faulting vCPU on cache
		// persistence the store can always redo).
		pending := persist
		go func() {
			defer pending.Close()
			if err := pending.Sync(); err != nil {
				os.Remove(pending.Name())
				log.Printf("persist chunk %s: sync: %v (cache copy remains valid)", entry.Digest[:12], err)
				return
			}
			if err := os.Rename(pending.Name(), persistPath); err != nil {
				os.Remove(pending.Name())
				log.Printf("persist chunk %s: rename: %v (cache copy remains valid)", entry.Digest[:12], err)
			}
		}()
	}
	// Publish the fetched bitmap exactly like the remote path does: the
	// bitmap is the only discriminator against sparse-hole reads, and
	// without it every fault on this chunk re-fetches, re-hashes, and
	// re-writes (F1).
	src.inflightMu.Lock()
	src.fetched[chunkIdx] = struct{}{}
	src.inflightMu.Unlock()
	log.Printf("DEBUG store chunk=%d digest=%s bytes=%d", chunkIdx, entry.Digest[:12], length)
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
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
	regions []regionMapping
	chunk   uint64
	uffdFd  int
	source  *pageSource

	mu     sync.Mutex
	served uint64
}

func (s *faultServer) resolve(addr uint64) error {
	for _, r := range s.regions {
		if addr < r.BaseHostVirtAddr || addr >= r.BaseHostVirtAddr+r.Size {
			continue
		}
		fileOff := addr - r.BaseHostVirtAddr + r.Offset
		// UFFDIO_COPY must use page granularity (4KiB): larger copies stall
		// the KVM vCPU (256KiB copies freeze the guest after ~6 pages).
		// The fetch/cache chunk size (s.chunk) is independent and larger
		// for bulk transfer efficiency.
		const copyLen = 4096
		off := fileOff &^ (copyLen - 1)
		buf, err := s.resolveChunk(off, copyLen)
		if err != nil {
			return err
		}
		if len(buf) == 0 {
			buf = make([]byte, copyLen) // past EOF: zero fill
		}
		if uint64(len(buf)) > copyLen {
			buf = buf[:copyLen] // trim fetched chunk to page size
		}
		dst := r.BaseHostVirtAddr + (off - r.Offset)
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
			if errno == 0 {
				break
			}
			if errno == unix.EEXIST {
				// Another thread already resolved this fault.
				return nil
			}
			if errno == unix.EAGAIN {
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
// table plus the uffd descriptor passed via SCM_RIGHTS.
// recvHandshake accepts Firecracker's connection and decodes the JSON mapping
// table plus the uffd descriptor passed via SCM_RIGHTS. The connection is
// returned OPEN: Firecracker never sends more data on it, so a read-side EOF
// is the reliable signal that the VMM process is gone — the uffd descriptor
// itself cannot provide one, because this handler holds the last reference
// after the VMM exits and userfaultfd never polls HUP for its holder.
func recvHandshake(l net.Listener) ([]regionMapping, int, *net.UnixConn, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, -1, nil, fmt.Errorf("accept: %w", err)
	}
	c, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, -1, nil, errors.New("unexpected connection type")
	}
	buf := make([]byte, 4096)
	oob := make([]byte, 128)
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, -1, nil, fmt.Errorf("read handshake: %w", err)
	}
	var regions []regionMapping
	if err := json.Unmarshal(buf[:n], &regions); err != nil {
		return nil, -1, nil, fmt.Errorf("decode mappings %q: %w", string(buf[:n]), err)
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, -1, nil, fmt.Errorf("parse control message: %w", err)
	}
	for _, cm := range cmsgs {
		if cm.Header.Type == unix.SCM_RIGHTS {
			fds, err := unix.ParseUnixRights(&cm)
			if err != nil || len(fds) == 0 {
				return nil, -1, nil, fmt.Errorf("parse SCM_RIGHTS: %v", err)
			}
			return regions, fds[0], c, nil
		}
	}
	return nil, -1, nil, errors.New("handshake carried no file descriptor")
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
	chunkKB := flag.Uint("chunk-kb", 4, "bytes copied per fault, in KiB")
	workers := flag.Int("workers", 8, "concurrent UFFDIO_COPY workers")
	prefetch := flag.Int("prefetch", 4, "background chunk prefetch concurrency (0 = disabled)")
	flag.Parse()
	if *sockPath == "" || (*backingPath == "" && *remoteURL == "") {
		log.Fatal("-sock plus -backing or -remote is required")
	}
	os.Remove(*sockPath)
	l, err := net.Listen("unix", *sockPath)
	if err != nil {
		log.Fatalf("bind %s: %v", *sockPath, err)
	}
	defer os.Remove(*sockPath)

	// Remote mode stages chunks in a sparse local cache. The bulk download
	// runs after the handshake (below) concurrently with fault serving: a
	// single sequential stream keeps cache writes ordered, and resolveChunk
	// treats partially written chunks as misses so faults never race the
	// writer (see readCache).
	chunk := uint64(*chunkKB) << 10
	source := &pageSource{
		chunk:    chunk,
		inflight: make(map[uint64]*sync.WaitGroup),
		fetched:  make(map[uint64]struct{}),
	}
	if *remoteURL != "" {
		cacheFile, err := os.OpenFile(*cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			log.Fatalf("open cache file %s: %v", *cachePath, err)
		}
		source.cache = cacheFile
		source.cachePath = *cachePath
		source.remote = *remoteURL
		source.client = &http.Client{Transport: &http.Transport{
			MaxIdleConnsPerHost: 16,
		}}
		// Cache writes go through fetchChunk which serializes via inflight.
	} else if *chunkStorePath != "" {
		// Chunk mode picks the source by artifact shape, not by manifest
		// presence alone:
		//
		//   - complete local image  -> serve the backing file directly; the
		//     chunk store is a distribution channel, not a dependency, and a
		//     store outage must not block restoring artifacts this node
		//     already holds in full (fail-open to local).
		//   - sparse placeholder    -> real bytes live in the store; serve
		//     chunks (persistent cache first, remote on miss).
		//   - broken manifest + complete image -> serve the bytes we have.
		//   - broken manifest + sparse placeholder -> refuse: serving the
		//     backing would feed zeros for every unfetched chunk, which is
		//     silent memory corruption rather than a failure.
		backingComplete := fileFullyAllocated(*backingPath)
		manifest, err := checkpointchunks.Load(filepath.Dir(*backingPath))
		switch {
		case err == nil && backingComplete:
			file, ferr := os.Open(*backingPath)
			if ferr != nil {
				log.Fatalf("open backing file: %v", ferr)
			}
			source.file = file
			log.Printf("complete local memory image; serving backing file directly (chunk store not on the critical path)")
		case err == nil:
			cacheFile, cerr := os.OpenFile(*cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
			if cerr != nil {
				log.Fatalf("open cache file %s: %v", *cachePath, cerr)
			}
			source.cache = cacheFile
			source.cachePath = *cachePath
			source.chunkManifest = manifest
			source.chunkStore = *chunkStorePath
			source.chunkLocal = *chunkLocalDir
			if uint64(manifest.ChunkBytes) != chunk {
				log.Printf("chunk size %dKiB from manifest overrides flag (%dKiB)",
					manifest.ChunkBytes>>10, chunk>>10)
				source.chunk = uint64(manifest.ChunkBytes)
			}
			log.Printf("chunk source: %d chunks from store %s", manifest.ChunkCount, *chunkStorePath)
		case backingComplete:
			log.Printf("no usable chunk manifest next to %s (%v); backing image is complete, serving it", *backingPath, err)
			file, ferr := os.Open(*backingPath)
			if ferr != nil {
				log.Fatalf("open backing file: %v", ferr)
			}
			source.file = file
		default:
			log.Fatalf("chunk manifest unusable (%v) and backing %s is a sparse placeholder; refusing to serve zeros — repair the manifest or re-materialize the artifact",
				err, *backingPath)
		}
	} else {
		file, err := os.Open(*backingPath)
		if err != nil {
			log.Fatalf("open backing file: %v", err)
		}
		source.file = file
	}
	regions, fd, vmmConn, err := recvHandshake(l)
	if err != nil {
		log.Fatalf("handshake: %v", err)
	}
	defer vmmConn.Close()
	s := &faultServer{
		regions: regions,
		chunk:   chunk,
		uffdFd:  fd,
		source:  source,
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
	stop := make(chan struct{})
	var stopOnce sync.Once
	shutdown := func() { stopOnce.Do(func() { close(stop) }) }

	// The VMM never writes after the handshake, so a read-side EOF on the
	// handshake connection means the Firecracker process is gone (stopped,
	// crashed, or the sandbox was deleted) and this handler must exit
	// instead of lingering as an orphan. The uffd descriptor cannot signal
	// this: after the VMM exits this handler holds the last reference, and
	// userfaultfd never reports HUP to its own holder.
	go func() {
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

	// Background bulk download: sequentially fetchChunk every chunk. This
	// runs concurrently with fault serving — the inflight dedup in
	// Background prefetch warms the whole artifact with a bounded worker
	// pool; -prefetch is the concurrency, and it now covers the S3 chunk
	// path too (the old remote-only gate silently disabled prefetch for
	// exactly the deployments that needed it). fetchChunk's inflight
	// tracking makes concurrent prefetch with fault serving safe: each
	// chunk moves at most once, faults wait on the same WaitGroup.
	if *prefetch > 0 && (source.remote != "" || source.chunkStore != "") &&
		os.Getenv("UFFD_NO_BULK") == "" {
		go func() {
			totalChunks := uint64(0)
			for _, r := range regions {
				totalChunks += (r.Size + chunk - 1) / chunk
			}
			workers := *prefetch
			if workers > 16 {
				workers = 16
			}
			if workers > int(totalChunks) {
				workers = int(totalChunks)
			}
			queue := make(chan uint64)
			var pwg sync.WaitGroup
			for w := 0; w < workers; w++ {
				pwg.Add(1)
				go func() {
					defer pwg.Done()
					for idx := range queue {
						select {
						case <-stop:
							return
						default:
						}
						if err := s.fetchChunk(idx); err != nil {
							log.Printf("prefetch chunk %d: %v", idx, err)
							return
						}
					}
				}()
			}
			startT := time.Now()
			for idx := uint64(0); idx < totalChunks; idx++ {
				select {
				case <-stop:
					close(queue)
					pwg.Wait()
					return
				case queue <- idx:
				}
			}
			close(queue)
			pwg.Wait()
			log.Printf("prefetch: %d chunks in %.2fs (concurrency %d)",
				totalChunks, time.Since(startT).Seconds(), workers)
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
	go func() {
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
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 500)
		if err != nil && err != unix.EINTR {
			log.Fatalf("poll uffd: %v", err)
		}
		select {
		case <-stop:
			goto done
		default:
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
			break // Firecracker is gone.
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
	close(faults)
	wg.Wait()
	s.mu.Lock()
	total := s.served
	s.mu.Unlock()
	log.Printf("handler exiting, total faults served=%d", total)
}
