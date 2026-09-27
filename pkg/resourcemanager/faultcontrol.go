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
//     /home/akernel/sandboxd/observation-fault.json) names a non-empty case
//     tag and a bounded TTL. Arming happens ONLY at a validated read: the
//     effective deadline is arm-time + TTL (clamped to [1s, 10m]) — a file
//     can never "become valid later" the way a far-future absolute deadline
//     would. Expiry auto-recovers with no second step; deleting the file
//     is the explicit release. A case tag is armed AT MOST ONCE per
//     process: an expired or released case cannot silently re-arm.
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

// FaultControlFile is the on-disk shape: {"case": "...", "ttl_ms": 45000}.
// The deadline is NOT taken from the file — arming computes it locally.
type FaultControlFile struct {
	Case  string `json:"case"`
	TTLMs int64  `json:"ttl_ms"`
}

type faultLease struct {
	caseTag  string
	deadline time.Time
}

// ObservationFault is the in-memory state. Re-reading the (bounded) control
// file per request keeps enable/release runtime-live without a watcher.
type ObservationFault struct {
	// Enabled is the config gate (default false). Immutable after start.
	Enabled bool
	// Path is the control file path (config-overridable for tests).
	Path string

	mu       sync.Mutex
	lease    *faultLease
	armed    map[string]bool // cases already armed (or expired) this process
	hits     atomic.Int64
}

// Active reports whether an observation fault is in force. Arming rules:
// a well-formed file (non-empty case, TTL within [1s, 10m]) whose case has
// not been armed before arms a lease for case-local deadline = now + TTL.
// An armed lease stays active until its deadline (auto-recovery) or until
// the control file no longer matches the armed case (explicit release —
// delete the file or change the tag). Expired cases never re-arm.
func (f *ObservationFault) Active() (tag string, remaining time.Duration, ok bool) {
	if f == nil || !f.Enabled {
		return "", 0, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	// lease bookkeeping first: expiry auto-recovers
	if f.lease != nil {
		if !now.Before(f.lease.deadline) {
			logrus.Warnf("resourcemanager: observation fault EXPIRED case=%s (auto-recovered)",
				f.lease.caseTag)
			f.armed[f.lease.caseTag] = true
			f.lease = nil
		} else if !f.fileMatchesCase(f.lease.caseTag) {
			logrus.Warnf("resourcemanager: observation fault RELEASED case=%s (control file gone/changed)",
				f.lease.caseTag)
			f.lease = nil
		}
	}
	if f.lease == nil {
		cf := f.readControlFile()
		if cf == nil {
			return "", 0, false
		}
		if f.armed == nil {
			f.armed = map[string]bool{}
		}
		if f.armed[cf.Case] {
			return "", 0, false // one-shot per case: no silent re-arm
		}
		ttl := time.Duration(cf.TTLMs) * time.Millisecond
		if ttl < faultMinTTL || ttl > faultMaxTTL {
			return "", 0, false // out-of-bound TTL is malformed, never arms
		}
		f.lease = &faultLease{caseTag: cf.Case, deadline: now.Add(ttl)}
		f.armed[cf.Case] = true
		logrus.Warnf("resourcemanager: observation fault ARMED case=%s ttl=%s (observation only)",
			cf.Case, ttl)
	}
	return f.lease.caseTag, time.Until(f.lease.deadline), true
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

// fileMatchesCase reports whether the control file currently on disk names
// exactly the armed case (release detection).
func (f *ObservationFault) fileMatchesCase(caseTag string) bool {
	cf := f.readControlFile()
	return cf != nil && cf.Case == caseTag
}

// RecordHit logs one real HTTP hit under an active fault: tag, remaining
// budget, cumulative hit count — nothing else.
func (f *ObservationFault) RecordHit(tag string, remaining time.Duration) {
	n := f.hits.Add(1)
	logrus.Warnf("resourcemanager: observation fault HIT case=%s remaining=%s hits=%d "+
		"(observation response only; stats/resize untouched)", tag,
		remaining.Round(time.Millisecond), n)
}
