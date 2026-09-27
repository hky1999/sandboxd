// Observation fault control: a DEFAULT-OFF test facility scoped strictly
// to the /resource observation response. It exists so the scheduler
// baseline can physically exercise "unknown/stale observation -> admission
// rejection -> recovery -> fresh-sample admission" without touching the
// Stats/Resize physical planes.
//
// Double gate (both required):
//  1. the sandboxd config enables the facility (enable_observation_fault,
//     default false — production configs never set it);
//  2. a small regular control file (default
//     /home/akernel/sandboxd/observation-fault.json) carries a complete
//     lease {case, ttl_ms, armed_at, deadline} written by the enabler.
//     The ABSOLUTE deadline is persistent across daemon restarts (a
//     restart never resets the term); an expired or stale file is
//     permanently inert; deleting the file is the explicit release.
//
// Every real HTTP hit under an ACTIVE fault is logged with case tag,
// remaining budget and hit count ONLY — never headers, query strings or
// credentials. The control-file read is bounded: regular file, <=4KiB.
package resourcemanager

import (
	"encoding/json"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	faultMaxTTL      = 10 * time.Minute
	faultMinTTL      = 1 * time.Second
	faultMaxFileSize = 4096
	faultDefaultPath = "/home/akernel/sandboxd/observation-fault.json"
)

// FaultControlFile is the on-disk shape. The ENABLER writes all four
// fields; the daemon only validates. ArmedAt/Deadline make the lease
// PERSISTENT across daemon restarts: a restart can never reset the term,
// and an expired file is permanently inert because the deadline is
// absolute and arming requires it to be strictly in the future.
type FaultControlFile struct {
	Case           string `json:"case"`
	TTLMs          int64  `json:"ttl_ms"`
	ArmedAtUnixMs  int64  `json:"armed_at_unix_ms"`
	DeadlineUnixMs int64  `json:"deadline_unix_ms"`
}

// ObservationFault is the in-memory state. Re-reading the (bounded) control
// file per request keeps enable/release runtime-live without a watcher.
type ObservationFault struct {
	// Enabled is the config gate (default false). Immutable after start.
	Enabled bool
	// Path is the control file path (config-overridable for tests).
	Path string

	hits atomic.Int64
}

// Active reports whether an observation fault is in force. The FILE is the
// lease: valid only when every clause holds —
//
//	case non-empty; TTL within [1s,10m];
//	deadline == armed_at + ttl (1s tolerance);
//	armed_at is recent (now-armed_at <= 10m: a stale leftover cannot arm);
//	deadline strictly in the future (an expired file is permanently inert).
//
// Daemon restart changes nothing: the same absolute deadline governs.
func (f *ObservationFault) Active() (tag string, remaining time.Duration, ok bool) {
	if f == nil || !f.Enabled {
		return "", 0, false
	}
	cf := f.readControlFile()
	if cf == nil {
		return "", 0, false
	}
	// Raw-range check BEFORE any duration conversion (overflow safety).
	if cf.TTLMs < int64(faultMinTTL/time.Millisecond) || cf.TTLMs > int64(faultMaxTTL/time.Millisecond) {
		return "", 0, false
	}
	if cf.ArmedAtUnixMs <= 0 || cf.DeadlineUnixMs <= 0 {
		return "", 0, false
	}
	now := time.Now()
	armedAt := time.UnixMilli(cf.ArmedAtUnixMs)
	// A FUTURE armed_at is malformed: without this check a lease written
	// "tomorrow + 30s" would activate immediately and outlive the bound.
	if now.Before(armedAt) {
		return "", 0, false
	}
	// Stale leftover beyond the maximum term is permanently inert.
	if now.Sub(armedAt) > faultMaxTTL {
		return "", 0, false
	}
	// Deadline must EXACTLY equal armed_at + ttl. Millisecond int64
	// addition cannot overflow (armed_at <= now < 2^48; ttl <= 6e5).
	if cf.DeadlineUnixMs != cf.ArmedAtUnixMs+cf.TTLMs {
		return "", 0, false
	}
	deadline := time.UnixMilli(cf.DeadlineUnixMs)
	if !now.Before(deadline) {
		return "", 0, false // expired: permanently inert (absolute)
	}
	remaining = time.Until(deadline)
	if remaining > faultMaxTTL {
		return "", 0, false // invariant guard: never exceed the max term
	}
	return cf.Case, remaining, true
}

// readControlFile performs a TOCTOU-safe BOUNDED read: the path is opened
// NON-BLOCKING first (a FIFO substituted after any stat can never block),
// the SAME fd is fstat'ed and must be a regular file of at most 4KiB, and
// the read is capped at 4097 bytes so an in-flight grower is refused
// rather than read unboundedly.
func (f *ObservationFault) readControlFile() *FaultControlFile {
	fd, err := syscall.Open(f.Path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	// SINGLE OWNERSHIP from here: only the os.File closes this fd. The
	// earlier defer syscall.Close alongside os.NewFile let the finalizer
	// close a REUSED descriptor after GC (independent negative
	// observation-fault-e24972f-descriptor-negative).
	file := os.NewFile(uintptr(fd), f.Path)
	if file == nil {
		syscall.Close(fd)
		return nil
	}
	defer file.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &st); err != nil {
		return nil
	}
	if !isRegular(st) || st.Size > faultMaxFileSize {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(file, faultMaxFileSize+1))
	if err != nil || len(raw) > faultMaxFileSize {
		return nil
	}
	var cf FaultControlFile
	if json.Unmarshal(raw, &cf) != nil || cf.Case == "" || cf.TTLMs <= 0 {
		return nil
	}
	return &cf
}

func isRegular(st syscall.Stat_t) bool { return st.Mode&syscall.S_IFMT == syscall.S_IFREG }

// RecordHit logs one real HTTP hit under an active fault: tag, remaining
// budget, cumulative hit count — nothing else.
func (f *ObservationFault) RecordHit(tag string, remaining time.Duration) {
	n := f.hits.Add(1)
	logrus.Warnf("resourcemanager: observation fault HIT case=%s remaining=%s hits=%d "+
		"(observation response only; stats/resize untouched)", tag,
		remaining.Round(time.Millisecond), n)
}
