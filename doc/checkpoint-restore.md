# Checkpoint and restore

sandboxd supports checkpointing a running sandbox into a caller-owned
directory and starting a new sandbox from that checkpoint.

## Design

The API has two operations:

1. `SandboxService.Checkpoint` checkpoints an existing sandbox.
2. The existing `Start` RPC restores a sandbox when `checkpoint_info` is set.

There is no separate restore RPC. Restore is a form of sandbox creation, so it
uses the normal `Start` path to allocate the target sandbox's filesystem,
network, cgroup, and other resources.

sandboxd coordinates the runtime operation and cleans partial output. It does
not manage checkpoint names, catalogs, storage, transfer, retention, or
compatibility negotiation. The caller chooses the checkpoint directory and
owns a successful artifact.

`ListAvailableRuntimes` reports checkpoint/restore support for each initialized
runtime handler. A supporting runtime may also advertise guest-visible
checkpoint handoff and restore-environment paths. Callers can use this metadata
to configure cooperative workloads and reject unsupported requests early, but
the `Checkpoint` and restore `Start` RPCs remain authoritative and validate the
runtime again when they execute.

## Checkpoint API

`CheckpointRequest` contains:

| Field | Meaning |
| --- | --- |
| `id` | ID of the running source sandbox |
| `checkpoint_dir` | Absolute local directory for the checkpoint artifact |
| `timeout_seconds` | Maximum time sandboxd waits for checkpoint completion |
| `compress` | Ask the runtime to compress the checkpoint image |
| `leave_running` | Keep the source running after a successful checkpoint |
| `snapshot_type` | Checkpoint flavor: empty (automatic), `Full`, `Incremental`, or `SoftDirty` |

`timeout_seconds` must be greater than zero and is enforced by sandboxd.
Caller cancellation may end the operation earlier. Only one checkpoint may be
in progress for a source sandbox at a time.

`checkpoint_dir` must be absolute, must not be `/`, and must not contain
symbolic links. Its parent must already exist. The leaf may be absent, in which
case sandboxd creates it, or it may be an existing empty directory. sandboxd
never overwrites a non-empty directory.

The directory is the artifact boundary. Its contents are opaque and specific
to the runtime that created them.

### Output persistence barrier (`runtime.checkpoint_sync.sync_output`)

Deployment profiles whose checkpoint directories live on a shared filesystem
used for cross-node recovery can enable the final persistence barrier:

```toml
[runtime.checkpoint_sync]
sync_output = true
```

When enabled, sandboxd walks the checkpoint output after the runtime reports
success and fsyncs every regular file and directory bottom-up before
acknowledging the `Checkpoint` RPC. A barrier failure fails the checkpoint and
cleans the output directory: READY is never acknowledged over output sandboxd
cannot persist. Symbolic links and special entries are rejected rather than
synced. The default `false` preserves the historical local-only contract that
does not force writeback; callers that keep checkpoints on node-local
directories should leave it off.

## Firecracker artifacts and incremental checkpoints

The Firecracker runtime writes *uncompressed* checkpoint directories (layout
version 2): `manifest.json` plus the `vmstate`, `memory`, and `overlay.ext4`
components. A VM with virtio-fs also carries `virtiofs.state`. The manifest is
written last as the logical commit marker: under
normal same-boot operation, a directory that shows a manifest is complete; a
directory without one is partial output that sandboxd cleans up. The memory
file stays a plain file that Firecracker
patches in place — the layout deliberately avoids archiving or compression so
reflink sharing and incremental writes survive. `compress` has no effect on
this layout (it only applies to legacy artifacts). Legacy single-file
`checkpoint.img` archives can still be restored but are no longer written.

With `checkpoint_mode = "incremental"`, repeated checkpoints of the same
running sandbox clone the previous generation's memory (a copy-on-write
reflink when both directories share a reflink-capable filesystem) and
Firecracker rewrites only the pages that changed, both into the artifact and
on disk. The default `checkpoint_mode = "full"` writes the complete memory
file for every generation. Each generation is still a complete, independently
restorable artifact; incremental mode affects only how much host work and disk
space a generation costs.

For the low-latency path, put the live Firecracker writable layer and the
checkpoint root on the same native XFS filesystem with reflink enabled. A
cross-filesystem or non-reflink layout falls back to copying large files. A
`Full` baseline also dirties one guest-memory-sized file. After committing a
generation, sandboxd asynchronously asks Linux to start writeback for its
memory file without waiting for completion. Normal periodic checkpointing lets
that I/O overlap the interval between generations, so a later XFS reflink does
not usually inherit the previous checkpoint's buffered-I/O debt. An immediately
following generation can still catch writeback in progress and wait. Do not add
an fsync to the checkpoint RPC to hide this cost, because that only moves the
same wait into the request path.

Consecutive generations must use distinct `checkpoint_dir` values — sandboxd
refuses to overwrite a directory that already holds a checkpoint. The
incremental chain references the latest artifact's memory file directly, so a
caller that deletes or mutates the most recent checkpoint directory invalidates
the lineage: the next checkpoint takes a `Full` snapshot (see the lineage-loss
rules below); deleting older generations is always safe.

Checkpoint completion deliberately uses host page-cache semantics. Every
Firecracker snapshot request carries `deferred_sync: true`: Firecracker returns
after buffered writes, and sandboxd does not fsync the memory, state, overlay,
manifest, or checkpoint directory. After the manifest is committed and the
incremental base is adopted, a bounded sandboxd worker issues
`sync_file_range(SYNC_FILE_RANGE_WRITE)` for the memory file. This starts Linux
writeback but does not wait for I/O completion and does not strengthen the
artifact's durability contract.

On cgroup v2, sandboxd keeps snapshot page-cache charges out of the sandbox
cgroup without changing its memory limit. A container's cgroup namespace root
can still be a non-root domain cgroup in the host hierarchy, so moving a process
there can fail the no-internal-process constraint. Instead, sandboxd creates a
persistent, unbounded `sandboxd-firecracker-checkpoint` leaf directly below the
namespace root. After pausing the guest and cloning the overlay, sandboxd moves
the whole Firecracker process to that leaf only for the native snapshot request,
moves it back to the original sandbox cgroup, and only then resumes the guest.
Existing guest anonymous memory keeps its original sandbox charge while new
snapshot page cache is charged to the shared leaf. The leaf accepts concurrent
checkpoint writers and remains available across operations; its page cache is
reclaimable under normal host memory pressure. If the move back fails, sandboxd
leaves the guest paused and terminates the VMM rather than running workload
threads outside the sandbox cgroup.

Restore does not use that paused-snapshot window and still reserves transient
node memory, raises the target VMM cgroup limit, and retains the raised limit
for the sandbox lifetime. cgroup v1 and hybrid deployments also retain the
headroom fallback for checkpoint. None of these host accounting choices
changes the guest memory size, which remains fixed by the microVM
configuration. Operators must leave enough host capacity for VMM overhead,
restores, and reclaimable checkpoint page cache.

A successful checkpoint therefore means the generation is logically complete
and available for restore; it does **not** promise immediate power-loss
durability. `close(2)` does not surface delayed writeback failures, so an abrupt
host loss or a later `ENOSPC`/`EIO` can make the newest generation incomplete
even though the RPC succeeded. A caller that requires a durable external
artifact must establish that durability outside the checkpoint RPC.

Inside the pause window the overlay reflink clone happens **before** the
snapshot request: cloning first runs with a page cache that does not yet hold
the snapshot's dirty writeback (an overlay clone after the snapshot was
measured stalling for seconds behind that writeback). The clone deliberately
carries no fsync because it can wait behind dirty writeback on the same
filesystem. On cgroup v2 the pause window is therefore pause → overlay clone →
move VMM to the shared checkpoint leaf → snapshot writes → move VMM back →
resume, with no fsync on the path. The manifest remains the logical commit
point: a generation without a manifest is partial output.

A sandboxd crash between resume and manifest publication discards the newest
generation and restores from the previous one. This is sound because every
generation writes into a fresh clone and never mutates its base. Firecracker
re-arms its soft-dirty window before manifest publication, so writes the guest
performed during that gap belong to the generation discarded with the
artifact; checkpoint success is reported only after the manifest is published.

`snapshot_type` is a Firecracker-specific control, gated by
`checkpoint_mode` (`plugin.runtime.firecracker`):

- **`checkpoint_mode = "full"` (default, and the meaning of an unset value):**
  every generation is a `Full` snapshot. An empty `snapshot_type` selects
  `Full`; an explicit `Full` is allowed; an explicit `SoftDirty` or
  `Incremental` is rejected with a configuration error rather than silently
  reinterpreted. An unknown `checkpoint_mode` value fails sandboxd startup.
- **`checkpoint_mode = "incremental"`** (requires a fork VMM with the
  incremental snapshot API): an empty `snapshot_type` keeps the automatic
  tier selection (a pagemap `Incremental` generation against the memory file
  a restore loaded, `SoftDirty` windows against a previous checkpoint
  afterwards, and a `Full` baseline on a sandbox that never checkpointed).
  An explicit `Full` drops the lineage for one generation and
  has Firecracker write the whole memory file. An explicit `Incremental`
  requires the restore-established pagemap base and fails otherwise. An
  explicit `SoftDirty` requires a usable base.

Runtimes without incremental checkpoints (runsc) ignore the field.

Lineage-loss rules: the VMM keeps its soft-dirty ledger in process memory, and
an armed ledger writes only the window delta regardless of which base sandboxd
holds. Whenever sandboxd can no longer prove that its base is the one the
ledger tracks — a checkpoint failed after the VMM wrote and re-armed (snapshot
or seal error), the recorded base drifted or was
deleted, or the sandboxd daemon restarted — the lineage is marked lost and the
next checkpoint takes a `Full` snapshot. `Full` ignores the ledger and writes
the complete memory image; the window re-opens only after that write, so
subsequent deltas patch onto the `Full` artifact as a safe superset. Explicit
`SoftDirty`/`Incremental` requests fail while the lineage is lost (take a
`Full` checkpoint first); automatic selection picks `Full` on its own. A daemon
restart always marks the lineage lost for surviving sandboxes: the restart
cannot tell which generation the surviving VMM is armed against, so the
cheapest provably-safe recovery is one `Full` checkpoint per sandbox.

The manifest digests the small VM state and optional virtiofsd state
components. Hashing the memory file
or `overlay.ext4` is skipped because it costs seconds of CPU and page-cache
reads per GiB and would dominate checkpoint latency. Their local integrity
rests on reflink copy-on-write and Firecracker's own writes. Restores skip
components without a recorded digest. Digests are computed from the
page-cache-visible contents before manifest publication, so the manifest
attests the logical generation rather than stable-storage durability. On
restore the verification is memoized per sandboxd process: a component whose
size and mtime are unchanged since a previous successful verification is not re-hashed,
so warm starts from a stable template directory skip the cost. The tradeoff is
that a content swap which preserves both size and mtime within the filesystem's
timestamp granularity goes undetected — the same granularity the nydus
bootstrap cache accepts.

The manifest also records a `compat` tuple — sha256 digests of the Firecracker
binary, guest kernel, and initrd, plus architecture and kernel arguments. A
virtio-fs checkpoint additionally records the virtiofsd digest. Values are
computed once per sandboxd process. A restore compares the tuple against its
own stack and refuses on a mismatch, naming the conflicting field. Manifests
without a tuple (artifacts from before the tuple existed) restore without stack
verification.

### Storage layout for high-performance Firecracker checkpoints

Firecracker memory and the writable block image are separate checkpoint
components. Firecracker writes or patches `memory`; sandboxd snapshots the
live `overlay.ext4` into the artifact. A conventional restore maps the
artifact's `memory` file privately. A virtio-fs restore first reflink-clones it
to a sandbox-owned `memory.live` file (or copies it when reflink is unavailable)
and maps only that live file writable and shared, because virtiofsd must write
guest buffers directly. The committed checkpoint memory is never mapped
writable. Restore also clones `overlay.ext4` into a new sandbox-owned writable
image. Checkpoint components must not become live writable state: the source
may keep running, and concurrent restores require independent layers.

For a virtio-fs checkpoint, Firecracker keeps `VHOST_F_LOG_ALL` armed for the
device lifetime. While the VM is paused it stops and drains both queues,
serializes virtiofsd into `virtiofs.state`, collects the shared vhost dirty
bitmap, and includes those guest-memory ranges in every snapshot flavor before
re-enabling the queues. Restore requires the same virtio-fs/non-virtio-fs
storage layout, starts a replacement virtiofsd over the newly prepared
exports with their requested access modes, loads its sidecar before enabling queues, and resumes the
guest only after the device and memory state agree.

Writable host directory mounts are external, caller-owned state. Local restore requires the same mount layout and access modes and the original backing directories and referenced files. The checkpoint does not copy, roll back, or retain their contents; sandbox deletion only tears down the export and does not delete the source. Keep those files available for as long as checkpoints may need them. Restoring into an empty replacement directory, automatically creating new log segments, and cross-node migration of writable host directories are not supported. For append logs, use `O_APPEND`; ordinary writes retain the saved offset and can overwrite data written after the checkpoint. Replayed application execution can produce duplicate logs even with append mode. The virtiofsd export uses its default write-through policy, not `--writeback`.

Firecracker native writable mounts do not add checkpoint components. Their
directories reside in the same `overlay.ext4` as the root overlay's upper and
work directories, while the VM snapshot preserves the guest bind mounts. A
checkpoint and restore therefore carries their data and mount state through
the existing `overlay.ext4`, `memory`, and `vmstate` artifacts and applies the
same quota, clone, durability, and storage-placement behavior.

sandboxd uses `FICLONE` for these copies when possible:

- the live writable image under
  `plugin.runtime.filestore_dir/.firecracker` to the checkpoint overlay;
- one checkpoint memory generation to the next incremental generation; and
- the checkpoint overlay to the restored sandbox's writable image.

All source and destination paths must therefore be on the **same
reflink-capable filesystem** for the complete fast path. XFS with reflink
enabled and Btrfs are supported examples. Sharing a block device is not
sufficient if the paths are in different mounted filesystems: `FICLONE`
returns `EXDEV` across filesystem boundaries. The caller should allocate
`checkpoint_dir` below the same filesystem as `filestore_dir`, but outside
the runtime-owned `.firecracker` directory. For example:

```toml
[plugin.runtime]
filestore_dir = "/var/lib/sandboxd-storage/filestore"
filestore_xfs_enabled = true
filestore_dir_size = "200G"

[plugin.runtime.firecracker]
checkpoint_mode = "incremental"
```

The caller can then allocate checkpoint directories below a separately
managed path such as
`/var/lib/sandboxd-storage/filestore/checkpoints/<checkpoint-id>`. The
checkpoint manager remains responsible for retention, quotas, and reserving
enough capacity so artifacts cannot exhaust the writable-storage filestore.
Do not place caller-owned artifacts below `.firecracker`, which sandboxd owns
as live runtime state.

Verify the deployed paths, not just the configuration text: check that the
live overlay and checkpoint root report the same filesystem/device, and run a
small `FICLONE` probe between them. A loop-mounted ext4 filestore and a
checkpoint directory on the host filesystem do not qualify, even when both
are backed by the same physical disk.

If reflink is unavailable, sandboxd preserves correctness by falling back to
a full file copy. That path is not a performance configuration. In
particular, the current fallback is not sparse-extent-aware and may
materialize holes in a sparse ext4 image, turning a cheap writable-layer
snapshot into I/O and disk usage proportional to its virtual size. The
restored writable image is live runtime state rather than a durable artifact,
so neither the reflink nor fallback path fsyncs it before starting the VM.
FICLONE or copy completion makes the contents available immediately; normal
writeback handles persistence outside restore latency. Operators should treat
an unexpected fallback as a deployment problem and monitor checkpoint
latency and physical artifact usage for evidence of it.

`checkpoint_mode = "incremental"` is the other half of the fast path. It
allows later generations to reflink the previous memory image and patch only
changed pages. A first checkpoint, an explicit `Full`, or recovery after
lineage loss still writes all guest memory. Consequently, even a correctly
configured reflink filesystem cannot make a Full memory snapshot independent
of VM memory size or backing-device throughput.

These performance settings do not change durability semantics. Checkpoint
completion remains logical and does not fsync the artifact. A caller that
needs power-loss durability or remote persistence must establish it after the
checkpoint RPC, without adding archive, compression, hashing, or synchronous
copy work back to sandboxd's pause path.

The caller should also avoid synchronously fsyncing the checkpoint root as
part of an otherwise local metadata commit. Firecracker uses
`deferred_sync=true`; on filesystems with outstanding snapshot writes, a
directory fsync immediately after renaming the staging directory can wait for
that writeback and reintroduce a memory-size-dependent tail. Keep the rename
and logical metadata commit on the request path, and perform any stronger
durability work asynchronously or in the remote publication layer.

### Guest flush before pause

Before pausing the source for a checkpoint, sandboxd asks the guest agent (over
the existing vsock control channel, protocol message type 8) to `sync()` its
writable layer, so the cloned `overlay.ext4` captures guest-buffered writes
instead of a crash-consistent mix. The request is best-effort with a bounded
budget (2 seconds): on timeout, transport error, or a guest agent that
predates the message, the checkpoint proceeds without the flush and stays
crash-consistent. The flush happens while the guest is still running, so a
successful flush adds to the checkpoint's wall time but not to the pause
window. The message never fails a checkpoint.

After the flush, sandboxd also asks the guest agent to drop its page caches
(protocol message type 9) with the same best-effort contract: cached file
pages are re-materialized by block DMA on every re-read, which re-dirties
them in the host ledger and drags them into each snapshot window, so dropping
the caches right before the pause shrinks the set a checkpoint carries. A
guest agent that predates the message declines it and the checkpoint
proceeds.

## Source and failure semantics

`leave_running` defines only the successful result:

| Result | Source sandbox |
| --- | --- |
| Success with `leave_running=true` | Continues running |
| Success with `leave_running=false` | Is stopped by the runtime |
| Error, timeout, or cancellation | State is not guaranteed |

After a successful checkpoint with `leave_running=false`, the caller still
deletes the source through the normal sandbox API to release its metadata and
resources.

On failure, sandboxd returns an error and does not force-delete, stop, or
resume the source. The caller decides how to handle the source sandbox.
sandboxd only cleans partial checkpoint output: it removes a leaf directory it
created, or empties a caller-provided leaf directory while preserving it.

## Restore through Start

### Background restore (`runtime.runsc.background_restore`)

```toml
[runtime.runsc]
background_restore = true
```

When enabled, runsc restores load the pages needed to resume first and load
the remaining pages in the background with fault priority, so the restore
completes earlier while cold pages fault in on demand. The default `false`
keeps fully synchronous restores. Callers that need to know when background
loading has finished can use `runsc wait --restore`. Firecracker ignores this
option.

To restore, the caller sends a normal `StartRequest` for the target sandbox and
sets:

```text
checkpoint_info: {
  checkpoint_dir: "/absolute/path/to/checkpoint"
}
```

The caller must still provide the normal `Start` configuration, including the
runtime, root filesystem, resources, mounts, and network settings. The target
should use a new sandbox ID and receives newly allocated sandboxd resources.

If restore fails, sandboxd rolls back the partially created target. It does not
modify the source or delete the checkpoint input.

After `Start` succeeds, the target no longer depends on the checkpoint
directory — with one exception: a Firecracker v2 restore keeps the artifact's
`memory` file as its tier-2 incremental base. A conventional restore also maps
that file privately; a virtio-fs restore maps an independent shared live clone.
The caller must keep the checkpoint directory intact until the restored
sandbox exits or establishes a later complete checkpoint generation.

## Runtime support and compatibility

| Runtime | Checkpoint and restore |
| --- | --- |
| runsc with systrap | Supported |
| runsc with KVM | Supported |
| Firecracker | Supported |
| Kata Containers | Not supported |
| runc | Not supported |

runsc advertises `/proc/gvisor/checkpoint` as its checkpoint handoff and
`/proc/gvisor/spec_environ` as its restore environment. Firecracker provides
the equivalent guest-agent endpoints at `/run/sandboxd/checkpoint` and
`/run/sandboxd/restore-environ`. These paths are runtime-neutral transport
metadata: sandboxd does not inject or interpret application-specific
environment variables.

Unsupported runtimes return `Unimplemented`.

A checkpoint must be restored with the same runtime and a compatible runtime
binary, machine architecture, host or guest kernel, and runtime configuration.
Compression changes only the runtime-specific artifact encoding; it does not
make an artifact portable.

Incremental checkpoint scheduling (which generations a caller takes and when),
deterministic replay, migration orchestration, and automatic recovery of a
source after checkpoint failure are outside this design.

## Writable block I/O policy

New sandboxes default to `writable_io_engine = "AsyncDirect"` and `writable_cache_type = "Writeback"` in `plugin.runtime.firecracker`. The pinned Firecracker runtime bundle includes direct-I/O alignment support. Operators using an older VMM must explicitly select `Async` or `Sync`. The writable policy applies to the private ext4 disk, including native writable mounts. It does not change EROFS root disks, virtio-fs exports, or checkpoint memory-file I/O.

The VMM persists the engine and cache policy in device state and reopens the writable disk with the saved policy on restore. Changing sandboxd's defaults affects newly created VMs; it does not override the policy captured in an existing checkpoint. Checkpoint compatibility still requires matching runtime digests. Direct-I/O alignment requirements are queried again for the restored image on its destination filesystem. Request-owned alignment buffers and in-flight I/O are completed before snapshotting; completed reads reach guest memory and dirty tracking before the device state is saved. Alignment buffers are not separate checkpoint artifacts.

The destination host must support the saved I/O engine. In particular, direct engines require the destination kernel and backing filesystem to report `STATX_DIOALIGN`, normally available for ext4 and XFS on upstream Linux 6.1 or newer; asynchronous engines also require usable `io_uring`. Restore fails when those capabilities are unavailable and never automatically changes the saved engine to buffered I/O. Operators using hosts without Direct I/O alignment-query support must explicitly configure `Async` or `Sync` before creating new sandboxes; this setting cannot make an existing Direct I/O checkpoint compatible with such a host. See [host I/O compatibility and configuration](runtime.md) for details.

## Firecracker deletion: confirmed reader exit

Deleting a Firecracker instance now requires a kernel exit notification for its recorded VMM and, when present, its virtiofsd before removing the instance's persisted state, runtime directory, writable layer, or virtio-fs exports. The implementation reuses the newer sandboxd pidfd retirement algorithm. An invalid recorded PID or a live process whose native identity cannot be verified is not exit evidence; it is never signalled, and deletion fails while retaining the instance and its artifacts for retry. Sending SIGKILL or observing unavailable argv/exe is not a successful exit confirmation. Artifact cleanup after confirmation does not re-signal a numerically reused PID.

This is the runtime deletion gate, not a durable cross-process reader-retirement receipt. The legacy Delete RPC still cannot prove that an older in-flight Start will not appear later. Durable start-operation fencing, daemon-assigned incarnation identity, restore content-root verification, and the ADX authenticated reader-release acknowledgement remain required before the control plane may use a backend receipt to release checkpoint protection. This change does not advertise that capability or change the public protocol, and it does not change gVisor's current deletion contract. Failed-start rollback paths that still use best-effort stop must not be treated as proven cleanup.

## ADX A1 identified start and retirement (2026-10-17, source candidate)

The node-local start-operation journal is retained across process restarts,
sandbox deletion, and pod identity reset. Admission is durable before the
runtime is called. An admitted operation whose completion cannot be proven
after a restart becomes unknown and is never blindly executed again.

RetireStartOperation is separate from GetStartOperation: NotFound is NOT an
exit proof. Retirement first persists a no-future-admission fence under the
same journal lock used by admission, including an operation that has not yet
arrived. It waits for any admitted executor to actually return. Timeout ends
the wait only and leaves the fence and reader protection in place. Success
requires either never-admitted proof, a fully confirmed rollback, or strict
generation-checked runtime deletion with durable completed retirement.

The wire format keeps StartResponse.sandbox_ip at field 4. New fields are
additive. Start-operation success is a historical fact, not current liveness;
retirement_requested forbids using that fact as permission to activate.

RestoreWithOperation requires the sealed artifact identity and a runtime
that verifies it at consumption. Unsupported verification or strict deletion
fails closed; legacy idempotent Delete/empty List is never an exit receipt.
The existing runtimes have not yet completed those capability adapters in
this candidate. This source change is not production or SDK acceptance.

Pending start intents preserve their sandbox directory, filesystem ownership,
network lease, OCI mounts, and bounded filestore in recovery and shutdown.
Unknown outcomes need reconciliation; no timed journal eviction may reopen
late admission. The journal is node-local, not a cross-node writer lease or
a replacement for ADX Coordinator reader-reference authority.


## ADX A1 Firecracker runtime identity candidate (2026-10-17)

StartConfig.ResourceGeneration is persisted in Firecracker runtime state for
both fresh starts and restores. It identifies this target incarnation, not the
source checkpoint's instance. Existing state without a generation remains
usable by legacy Delete but never constitutes strict retirement evidence.

DeleteStrict uses a PASSIVE persisted-state lookup before its generation gate:
legacy recovery can signal processes and clean artifacts and must not run
before that gate. Missing, empty, or mismatched identity refuses retirement
without signalling or mutating the instance. After a match the existing kernel
exit gates cover the VMM and virtiofsd before instance artifacts are removed.
State writes are serialized and sync their containing directory.

The StartWithOperation restore branch (there is no separate RestoreWithOperation
RPC) requires the admission-pinned checkpoint root. Firecracker checks this
against the exact bounded manifest view it parsed, before OCI/storage/VMM
creation, using the common checkpointroot algorithm. Legacy archive restores
cannot silently ignore a supplied root. The caller must preserve immutable
artifacts through the reader lifetime; this does not defend against concurrent
malicious writers. Legacy restore without a supplied root stays supported.

This candidate does NOT advertise StartFailureCleanupProven: failed-start
rollback has not yet completed its separate proof contract. The service keeps
unknown failed starts protected. No new memory-distribution backend, device,
public catalog API, deployment, VM or SDK acceptance is implied.


## ADX generation-bound runsc restore and retirement (2026-10-17)

New runsc checkpoints carry a version-2 `manifest.json` sealing exactly
`checkpoint.img` and, when present, the paired `pages_meta.img` / `pages.img`.
The handler hashes and fsyncs the actual regular artifact descriptors before
atomically writing the manifest and syncing its directory. Unknown output,
incomplete pairs, symlinks, and incomplete digest coverage cannot be sealed.
This seal does not add an independent checkpoint catalog or public SDK API.

An identified restore must carry `StartConfig.ExpectedCheckpointRoot`.
The handler checks the bounded manifest before OCI allocation; the concrete
runsc client checks that same root algorithm again over its own parsed manifest
view, hashes the actual opened artifact descriptors, and transfers those same
descriptors to the restore RPC. Hashing uses positioned reads, preserving the
initial offsets. Missing seals are allowed only for legacy restores without an
expected root. A custom runsc client which cannot enforce this contract is not
advertised as a root verifier. The immutable directory and artifact lifetime
remains a caller obligation; arbitrary concurrent in-place writes are not made
safe by a one-time digest check.

This first implementation deliberately uses whole-file SHA-256 verification.
It pre-reads cold pages and may duplicate the server persistence barrier; leaving
background restore enabled does not make that pre-read lazy. It is a correctness
baseline, not evidence of low restore read volume or SOTA performance. Per-chunk
verification at actual lazy reads and pause/read-byte measurements remain work.
The old best-effort runsc chunk sidecar is not copied because its incomplete
logical geometry does not satisfy the shared content-root contract.

`StrictDeleteHandler.DeleteStrict` calls only a client's generation-aware delete.
The concrete client executes `delete --force --expected-generation=<token> --
<full-id>` against a pinned compatible runsc binary. It never retries legacy
`delete`, and neither missing state nor an unsupported flag counts as success.
The compatible gVisor candidate records creation generation, boot identity,
creator PID namespace and procfs PID view, and original sentry/gofer birth
identities; it confirms pidfd exit before reusing the existing resource cleanup.
Different boot or PID views fail closed. Reader references stay retained when
retirement is unproven. The handler does not advertise failed-start cleanup proof.

A runtime deletion followed by a crash before a durable upper-layer retirement
receipt can still leave references conservatively retained; missing runtime
state alone is not replay evidence. Persistent proof/replay, real ADX process
restart SDK acceptance, public shared volumes, and production/performance gates
are not established by these component tests. New binaries must be pinned and
accepted in task-owned deployment before enabling this path; old binaries are
not silently treated as compatible. Shared services and deployed templates are
not modified by the source change.

### A1 internal checkpoint identity discovery (2026-10-17, source candidate)

- `DescribeCheckpointArtifacts` is a node-local read-only RPC. It returns the
  normalized absolute checkpoint directory and the content-root pin already
  defined by `pkg/checkpointroot`; it does not create a catalog entry, publish
  data, acquire/release a reader, or add a public SDK checkpoint API.
- The ADX caller must first durably protect the selected checkpoint through its
  existing Coordinator reader reservation, then query while that protection is
  held. It must use the returned directory in both
  `start.checkpoint_info.checkpoint_dir` and
  `restore_artifacts.checkpoint_dir`, and pass the returned
  `expected_root_digest` to `StartWithOperation`. Keep reader protection until
  the operation and its runtime have positive retirement proof.
- Discovery reuses identified admission's bounded sealed-manifest/sidecar root.
  It deliberately does not read/hash memory or writable-disk payload bytes.
  Successful discovery is therefore neither payload integrity verification nor
  a durability/immutability guarantee. Runtime restore must still verify its
  opened content against the pin. Metadata changing between discovery and
  admission/consumption must be rejected there, not silently repinned.
- Missing/malformed/uncovered seals fail closed. Canceled queries return the
  context error. An older node returns `UNIMPLEMENTED`; a caller must not
  substitute a path-only legacy restore, locally invented digest, or raw
  `manifest.json` hash.
- This RPC shares sandboxd's existing node-local administrative trust boundary.
  It is not a shared-volume authorization mechanism; that chain remains in ADX.
- Source integration is not a deployment or complete ADX SDK acceptance claim.


## Firecracker v2 portable content seals (ADX shared storage, 2026-10-17)

New Firecracker v2 checkpoints digest every payload in the immutable generation, including guest memory and the private writable overlay, before publishing manifest.json. The same existing manifest digest map is consumed by checkpointroot admission and by the runtime's opened-view and component-digest checks. Local reflink ownership alone is not a cross-node content proof. Legacy artifacts without a verifiable memory/overlay identity are still refused by identified restore; recreate or explicitly republish them through a trusted producer rather than inventing a digest in the readonly identity query.

The finalizer runs after the VMM resume/handoff for leave-running snapshots. Computing large payload digests therefore remains outside that snapshot's pause window, but adds CPU/cache traffic to sealing and can increase checkpoint RPC time. An explicitly paused environment remains intentionally stopped until resume. This is a correctness baseline, not a claim of lazy verification or SOTA performance. The existing publication durability barrier remains required; a logical manifest by itself does not promise power-loss durability. Any payload hashing failure or cancellation must prevent manifest publication.

### Runtime invocation and Firecracker restore admission

The start dispatcher records runtime invocation only immediately before entering `Handler.Start` or `CheckpointHandler.Restore`. Firecracker restore admission checks, including the serialized checkpoint-memory slot, managed cgroup requirements, node memory reservation, and temporary headroom preparation, run before `Restore`. If one of these checks returns an error without entering the runtime handler, the management plane may perform its pre-runtime rollback without requiring a runtime failed-start cleanup proof. Resource, network, filesystem, and durable-intent rollback must still complete successfully before the start is considered fully rolled back.

Firecracker restore requires the node-resource module configured through `[plugin.node_resource]`, including its provider and socket path, in addition to managed sandbox cgroups and persisted guest resources. Guest memory in the restore request alone does not initialize this module or reserve the temporary host-memory budget. A missing module or a failed reservation must reject restoration; neither the cgroup limit nor the reservation check may be bypassed.

Once `Start` or `Restore` is entered, its error is still a runtime invocation and the original error chain is preserved. Runtime cleanup-pending errors, missing failure-cleanup proofs, and unproven process exit continue to retain the start's ID, filesystem ownership, and checkpoint readers. Panics remain subject to the outer conservative runtime-disposition path. Correcting the dispatch flag does not reinterpret historical unknown start records, prove their retirement, or authorize deleting them based on an error message or a momentarily empty process list.

### Separate Firecracker private storage

The optional `plugin.runtime.firecracker.storage_dir` selects the root for Firecracker-owned writable overlays, virtio-fs staging, and shared live-memory files. When absent, the exact historical default remains `filepath.Join(plugin.runtime.filestore_dir, ".firecracker")`: a hidden child, not a string suffix. The option does not change gVisor's filestore, the checkpoint publication directory, shared-volume authorization, disk formats, or memory-restore mechanisms. Sandbox metadata and sockets keep their existing locations.

An explicit value must be an absolute dedicated directory, not a filesystem root or a lexical overlap with sandbox metadata, runtime sockets, or the generic filestore (the exact historical hidden child is allowed). This is administrator-controlled configuration, not validation of untrusted user paths; bind-mount and symlink aliases still require operator ownership and deployment checks. Before recovery or directory creation, explicit configuration passively checks existing Firecracker identities and rejects incompatible overlay or virtio-fs staging paths. It must not silently migrate state, signal processes, or turn missing runtime state into a retirement proof.

Changing this setting is not a storage migration. Keep the paths and backing mounts of live or retained instances available; a matching configuration does not retire historical unknown starts. A deployment may keep Firecracker private data on local XFS while leaving gVisor's filestore on JuiceFS and publishing checkpoints through the configured shared checkpoint store. Separate-device capacity accounting, quotas, safe migration, lazy disk reads, and performance acceptance remain separate deployment obligations; this setting does not implement them. In particular, it does not make live-memory writes to a remote filesystem free or durable checkpoint publication unnecessary.
