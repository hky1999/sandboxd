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
	"os"
	"sync"
	"sync/atomic"
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
	Case          string `json:"case"`
	TTLMs         int64  `json:"ttl_ms"`
	ArmedAtUnixMs int64  `json:"armed_at_unix_ms"`
	DeadlineUnixMs int64 `json:"deadline_unix_ms"`
}

// ObservationFault is the in-memory state. Re-reading the (bounded) control
// file per request keeps enable/release runtime-live without a watcher.
type ObservationFault struct {
	// Enabled is the config gate (default false). Immutable after start.
	Enabled bool
	// Path is the control file path (config-overridable for tests).
	Path string

	mu   sync.Mutex
	hits atomic.Int64
}

// Active reports whether an observation fault is in force. The FILE is the
// lease: valid only when every clause holds —
//   case non-empty; TTL within [1s,10m];
//   deadline == armed_at + ttl (1s tolerance);
//   armed_at is recent (now-armed_at <= 10m: a stale leftover cannot arm);
//   deadline strictly in the future (an expired file is permanently inert).
// Daemon restart changes nothing: the same absolute deadline governs.
func (f *ObservationFault) Active() (tag string, remaining time.Duration, ok bool) {
	if f == nil || !f.Enabled {
		return "", 0, false
	}
	cf := f.readControlFile()
	if cf == nil {
		return "", 0, false
	}
	now := time.Now()
	ttl := time.Duration(cf.TTLMs) * time.Millisecond
	if ttl < faultMinTTL || ttl > faultMaxTTL {
		return "", 0, false
	}
	if cf.ArmedAtUnixMs <= 0 || cf.DeadlineUnixMs <= 0 {
		return "", 0, false
	}
	armedAt := time.UnixMilli(cf.ArmedAtUnixMs)
	deadline := time.UnixMilli(cf.DeadlineUnixMs)
	if deadline.Sub(armedAt) > ttl+time.Second {
		return "", 0, false // inconsistent lease
	}
	if now.Sub(armedAt) > faultMaxTTL {
		return "", 0, false // stale leftover: permanently inert
	}
	if !now.Before(deadline) {
		return "", 0, false // expired: permanently inert (absolute)
	}
	return cf.Case, time.Until(deadline), true
}

// readControlFile performs the BOUNDED read: the path must be a regular
// file of at most 4KiB; anything else (missing, FIFO, huge, malformed,
// empty case) yields nil.
func (f *ObservationFault) readControlFile() *FaultControlFile {
	st, err := os.Stat(f.Path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > faultMaxFileSize {
		return nil
	}
	raw, err := os.ReadFile(f.Path)
	if err != nil || len(raw) > faultMaxFileSize {
		return nil
	}
	var cf FaultControlFile
	if json.Unmarshal(raw, &cf) != nil || cf.Case == "" || cf.TTLMs <= 0 {
		return nil
	}
	return &cf
}

// RecordHit logs one real HTTP hit under an active fault: tag, remaining
// budget, cumulative hit count — nothing else.
func (f *ObservationFault) RecordHit(tag string, remaining time.Duration) {
	n := f.hits.Add(1)
	logrus.Warnf("resourcemanager: observation fault HIT case=%s remaining=%s hits=%d "+
		"(observation response only; stats/resize untouched)", tag,
		remaining.Round(time.Millisecond), n)
}
