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
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
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

	inflightMu sync.Mutex
	inflight   map[uint64]*sync.WaitGroup // chunk index -> waiters' group
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
	// Remote mode: the chunk granularity is fixed, so the cache offset is
	// the file offset rounded down and the URL range matches exactly.
	chunkIdx := fileOff / s.source.chunk
	cacheOff := chunkIdx * s.source.chunk
	if buf, ok := s.readCache(cacheOff); ok {
		return buf, nil
	}
	if err := s.fetchChunk(chunkIdx); err != nil {
		return nil, err
	}
	buf, ok := s.readCache(cacheOff)
	if !ok {
		return nil, fmt.Errorf("chunk %d missing from cache after fetch", chunkIdx)
	}
	return buf, nil
}

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
// misses of the same chunk into a single request.
func (s *faultServer) fetchChunk(chunkIdx uint64) error {
	src := s.source
	for {
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
			// Copy straight into the sparse cache at the chunk offset.
			written, err := io.Copy(newOffsetWriter(src.cache, int64(start)), resp.Body)
			if err != nil {
				return fmt.Errorf("cache chunk %d: %w", chunkIdx, err)
			}
			if written == 0 {
				// Zero-length chunk past the artifact end: touch the cache so
				// readers see zeros instead of retrying forever.
				_, _ = src.cache.WriteAt(make([]byte, 1), int64(start))
			}
			return nil
		}()
		if err == nil {
			return nil
		}
		return err
	}
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
		// Serve a chunk-aligned window covering the faulting page: the copy
		// resolves every page inside it, suppressing their future faults.
		off := fileOff &^ (s.chunk - 1)
		buf, err := s.resolveChunk(off)
		if err != nil {
			return err
		}
		if len(buf) == 0 {
			buf = make([]byte, s.chunk) // past EOF: zero fill
		}
		dst := r.BaseHostVirtAddr + (off - r.Offset)
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
func recvHandshake(l net.Listener) ([]regionMapping, int, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, -1, fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, -1, errors.New("unexpected connection type")
	}
	buf := make([]byte, 4096)
	oob := make([]byte, 128)
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, -1, fmt.Errorf("read handshake: %w", err)
	}
	var regions []regionMapping
	if err := json.Unmarshal(buf[:n], &regions); err != nil {
		return nil, -1, fmt.Errorf("decode mappings %q: %w", string(buf[:n]), err)
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, -1, fmt.Errorf("parse control message: %w", err)
	}
	for _, cm := range cmsgs {
		if cm.Header.Type == unix.SCM_RIGHTS {
			fds, err := unix.ParseUnixRights(&cm)
			if err != nil || len(fds) == 0 {
				return nil, -1, fmt.Errorf("parse SCM_RIGHTS: %v", err)
			}
			return regions, fds[0], nil
		}
	}
	return nil, -1, errors.New("handshake carried no file descriptor")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	sockPath := flag.String("sock", "", "unix socket path Firecracker will connect to")
	backingPath := flag.String("backing", "", "local checkpoint memory file (local mode)")
	remoteURL := flag.String("remote", "", "HTTP(S) URL of the artifact memory file (remote mode)")
	cachePath := flag.String("cache", "", "sparse local cache file (remote mode)")
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

	// Bulk download BEFORE accepting the handshake: a single sequential
	// stream eliminates the concurrent-write corruption; FC's connect+send
	// buffers in the kernel while we download, so delaying accept() is safe.
	chunk := uint64(*chunkKB) << 10
	source := &pageSource{chunk: chunk, inflight: make(map[uint64]*sync.WaitGroup)}
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
		// Bulk download before the handshake: a single sequential stream
		// eliminates the concurrent-write corruption (interleaved WriteAt
		// from multiple goroutines produced zeros at scattered offsets).
		// FC's connect+send buffers in the kernel, so delaying accept()
		// while downloading is safe.
		if *prefetch > 0 {
			info, err := os.Stat(*backingPath)
			if err != nil {
				log.Fatalf("prefetch: stat backing %s: %v", *backingPath, err)
			}
			total := info.Size()
			log.Printf("prefetch: bulk downloading %d bytes from %s", total, source.remote)
			startT := time.Now()
			req, _ := http.NewRequest(http.MethodGet, source.remote, nil)
			resp, err := source.client.Do(req)
			if err != nil {
				log.Fatalf("prefetch: fetch: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				log.Fatalf("prefetch: status %s", resp.Status)
			}
			written, err := io.Copy(source.cache, resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Fatalf("prefetch: copy: %v", err)
			}
			if written != total {
				log.Fatalf("prefetch: wrote %d bytes, expected %d", written, total)
			}
			_ = source.cache.Sync()
			log.Printf("prefetch: %d bytes in %.2fs (%.0f MiB/s)",
				written, time.Since(startT).Seconds(),
				float64(written)/time.Since(startT).Seconds()/(1<<20))
		}
	} else {
		file, err := os.Open(*backingPath)
		if err != nil {
			log.Fatalf("open backing file: %v", err)
		}
		source.file = file
	}
	regions, fd, err := recvHandshake(l)
	if err != nil {
		log.Fatalf("handshake: %v", err)
	}
	s := &faultServer{
		regions: regions,
		chunk:   chunk,
		uffdFd:  fd,
		source:  source,
	}
	log.Printf("handler ready: %d regions, chunk=%dKiB, workers=%d",
		len(regions), *chunkKB, *workers)

	faults := make(chan uint64, 4096)
	var wg sync.WaitGroup
	stop := make(chan struct{})

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
	close(stop)
	close(faults)
	wg.Wait()
	s.mu.Lock()
	total := s.served
	s.mu.Unlock()
	log.Printf("handler exiting, total faults served=%d", total)
}
