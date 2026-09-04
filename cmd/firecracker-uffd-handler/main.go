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

	inflightMu sync.Mutex
	inflight   map[uint64]*sync.WaitGroup // chunk index -> waiters' group
	// fetched records the chunks whose cache bytes are fully written. A
	// sparse hole inside the cache reads back as a full-length run of
	// zeros once the file has been extended past it by ANY other chunk's
	// write, so length cannot distinguish "written" from "hole": only the
	// bitmap can. Guarded by inflightMu.
	fetched map[uint64]struct{}
}

func (s *faultServer) resolveChunk(fileOff uint64) ([]byte, error) {
	if s.source.file != nil {
		buf := make([]byte, s.source.chunk)
		n, err := s.source.file.ReadAt(buf, int64(fileOff))
		if err != nil && !errors.Is(err, io.EOF) {
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
	sliceAt := func(buf []byte) []byte {
		if subOff >= uint64(len(buf)) {
			return nil
		}
		return buf[subOff:]
	}
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
	buf, ok := s.readCache(cacheOff)
	if !ok {
		return nil, fmt.Errorf("chunk %d missing from cache after fetch", chunkIdx)
	}
	if out := sliceAt(buf); out != nil {
		return out, nil
	}
	return nil, fmt.Errorf("offset %d beyond fetched chunk %d", fileOff, chunkIdx)
}

// readCache reads the chunk at cacheOff back from the sparse cache. The
// caller must have established (via the fetched bitmap) that the chunk's
// bytes are fully written: a sparse hole reads back as a full-length run
// of zeros once the file has been extended past it, so this function
// deliberately does not try to validate completeness by length.
func (s *faultServer) readCache(cacheOff uint64) ([]byte, bool) {
	buf := make([]byte, s.source.chunk)
	n, err := s.source.cache.ReadAt(buf, int64(cacheOff))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false
	}
	if n == 0 {
		return nil, false
	}
	return buf[:n], true
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
	// key layout and both are verified by the digest below.
	var body io.Reader
	if strings.HasPrefix(src.chunkStore, "http://") || strings.HasPrefix(src.chunkStore, "https://") {
		resp, err := http.Get(strings.TrimRight(src.chunkStore, "/") +
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
	}

	hash := sha256.New()
	written, err := io.Copy(newOffsetWriter(src.cache, int64(start)), io.TeeReader(body, hash))
	if err != nil {
		return fmt.Errorf("cache chunk %d from store: %w", chunkIdx, err)
	}
	if uint64(written) != length {
		return fmt.Errorf("store chunk %s short: %d bytes, want %d", entry.Digest, written, length)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != entry.Digest {
		return fmt.Errorf("store chunk %s digest mismatch: hashed %s", entry.Digest, got)
	}
	log.Printf("DEBUG store chunk=%d digest=%s bytes=%d", chunkIdx, entry.Digest[:12], length)
	return nil
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
		buf, err := s.resolveChunk(off)
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	sockPath := flag.String("sock", "", "unix socket path Firecracker will connect to")
	backingPath := flag.String("backing", "", "local checkpoint memory file (local mode)")
	remoteURL := flag.String("remote", "", "HTTP(S) URL of the artifact memory file (remote mode)")
	cachePath := flag.String("cache", "", "sparse local cache file (remote mode)")
	chunkStorePath := flag.String("chunk-store", "",
		"content-addressed chunk store directory; a chunks.json next to the backing file switches fetches to per-chunk digest lookups")
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
		// Chunk mode: serve from a content-addressed store when the
		// artifact carries a chunk manifest; without one, degrade to the
		// plain backing-file path below (full mode, backward compatible).
		manifest, err := checkpointchunks.Load(filepath.Dir(*backingPath))
		if err == nil {
			cacheFile, cerr := os.OpenFile(*cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
			if cerr != nil {
				log.Fatalf("open cache file %s: %v", *cachePath, cerr)
			}
			source.cache = cacheFile
			source.cachePath = *cachePath
			source.chunkManifest = manifest
			source.chunkStore = *chunkStorePath
			if uint64(manifest.ChunkBytes) != chunk {
				log.Printf("chunk size %dKiB from manifest overrides flag (%dKiB)",
					manifest.ChunkBytes>>10, chunk>>10)
				source.chunk = uint64(manifest.ChunkBytes)
			}
			log.Printf("chunk source: %d chunks from store %s", manifest.ChunkCount, *chunkStorePath)
		} else {
			log.Printf("no usable chunk manifest next to %s (%v); falling back to the backing file", *backingPath, err)
			file, ferr := os.Open(*backingPath)
			if ferr != nil {
				log.Fatalf("open backing file: %v", ferr)
			}
			source.file = file
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
	// fetchChunk ensures a chunk is fetched at most once, and the writes
	// are serialized by the sequential iteration (one fetchChunk at a time
	// in this goroutine). Fault-serving workers may also call fetchChunk
	// for the same chunk concurrently, which the inflight WaitGroup handles.
	if *prefetch > 0 && source.remote != "" && os.Getenv("UFFD_NO_BULK") == "" {
		go func() {
			totalChunks := uint64(0)
			for _, r := range regions {
				totalChunks += (r.Size + chunk - 1) / chunk
			}
			startT := time.Now()
			for idx := uint64(0); idx < totalChunks; idx++ {
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
			log.Printf("prefetch: %d chunks in %.2fs",
				totalChunks, time.Since(startT).Seconds())
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
