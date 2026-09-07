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

## Firecracker artifacts and incremental checkpoints

The Firecracker runtime writes *uncompressed* checkpoint directories (layout
version 2): `manifest.json` plus the `vmstate`, `memory`, and `overlay.ext4`
components. The manifest is written last as the logical commit marker: under
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

For stop-and-copy, the best-effort memory writeback is queued after stopping the source VMM and attempting to persist its terminal runtime state, so explicit bulk writeback does not start ahead of that small state-file sync. Leave-running checkpoints retain their post-seal scheduling. Stop errors still propagate; queue saturation remains best effort, and this ordering does not prevent the kernel from independently writing dirty pages or strengthen power-loss durability.

Stop-and-copy requires Linux pidfd support to confirm source process exit. A disappearing command line or executable is insufficient: these can disappear during exit teardown. Signals target the captured pidfd only while the source identity matches; an unrecognized process is never signalled. An existing process with unavailable identity must still reach pidfd exit readiness, otherwise checkpoint returns an error. pidfd open/poll failures also return errors rather than falling back to the weaker identity check. This confirms process exit, not immediate removal of a zombie's `/proc` directory, and does not strengthen the separate migration ownership protocol.

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

Checkpoint continuation lineage is process-local authority. A successful checkpoint does not rewrite the runtime state file when only `base_memory_path`, `base_memory_incremental`, or `base_memory_lineage_lost` changed. Values incidentally present in an older state file are neither a current baseline nor a GC retention reference; consumers must not use them to authorize incremental reuse. Recovery still invalidates lineage and forces Full, including repeated daemon restarts. Create/configure/restore, recovery reset and exit-state persistence keep their existing atomic-write and synchronization behavior. If another lifecycle field changed during checkpoint, that state is still persisted. Stop-and-copy persists the terminal state even if the stop helper had already marked a vanished source finished. Checkpoint artifact sealing, publication and their durability boundaries are unchanged.

The manifest digests the small VM state component and — unless opted out —
the memory artifact. Hashing guest memory costs roughly a second of CPU per
GiB and runs in the post-resume tail (outside the pause window), so it can be
disabled per deployment with `digest_memory = false` under
`[plugin.runtime.firecracker]` (an absent key means enabled); checkpoints
sealed while the knob is off — including all manifests from before the knob
existed — simply carry no memory digest and restores keep skipping that
component. Hashing `overlay.ext4` stays skipped in every mode because it costs
seconds of CPU and page-cache reads per GiB and would dominate checkpoint
latency; its local integrity rests on reflink copy-on-write and Firecracker's
own writes. Restores skip components without a recorded digest. Digests are
computed from the page-cache-visible contents before manifest publication, so
the manifest attests the logical generation rather than stable-storage
durability. On restore the verification is memoized per sandboxd process: a
component whose size and mtime are unchanged since a previous successful
verification is not re-hashed,
so warm starts from a stable template directory skip the cost. The tradeoff is
that a content swap which preserves both size and mtime within the filesystem's
timestamp granularity goes undetected — the same granularity the nydus
bootstrap cache accepts.

The manifest also records a `compat` tuple — sha256 digests of the Firecracker
binary, guest kernel, and initrd, plus architecture and kernel arguments —
computed once per sandboxd process. A restore compares the tuple against its
own stack and refuses on a mismatch, naming the conflicting field. Manifests
without a tuple (artifacts from before the tuple existed) restore without
stack verification.

### Storage layout for high-performance Firecracker checkpoints

Firecracker memory and the writable block image are separate checkpoint
components. Firecracker writes or patches `memory`; sandboxd snapshots the
live `overlay.ext4` into the artifact. Restore maps the artifact's `memory`
file in place and clones `overlay.ext4` into a new sandbox-owned writable
image. The artifact overlay must not be used as the restored VM's writable
image: checkpoint generations are immutable, the source may keep running, and
concurrent restores require independent writable layers.

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
directory — with one exception: restoring a Firecracker v2 directory keeps the
artifact's `memory` file mapped into the restored VM, so the caller must keep
the checkpoint directory intact until the restored sandbox exits. The next
checkpoint of the restored sandbox also diffs against that memory file
(the tier-2 base below).

### On-demand memory restore (uffd backend)

`mem_backend` under `[plugin.runtime.firecracker]` selects how the memory
artifact reaches the restored guest (`"file"`, the default, maps the artifact
directly; `"uffd"` hands page population to an external handler):

- With `"uffd"`, sandboxd spawns the `uffd-handler` binary (found via
  `uffd_handler_bin`, or next to the sandboxd executable), passes it the
  Firecracker uffd socket, and serves guest page faults with 4 KiB
  `UFFDIO_COPY`s. The handler fetches in larger chunks (`uffd_chunk_kb`,
  default 256) and backgrounds a sequential prefetch after the handshake.
- `uffd_remote_url` (a template whose `%s` is replaced with the artifact
  memory file path, e.g. `http://source:8080/%s`) switches the handler from
  reading the local backing file to HTTP range fetches against the node that
  holds the artifact, staging fetched chunks in `uffd_cache_dir`. This is
  the cross-node restore path: the memory artifact never has to be copied
  in full before the VM resumes.
- The handler serves pages from its own staging, so the restored VM does not
  map the artifact's `memory` file; the source directory may be reclaimed
  once the handler has fetched what it needs (or left in place for
  background prefetch). Restores through the file backend keep the
  mapped-directory exception above.
- `uffd_chunk_store` switches the handler to chunked serving for artifacts
  that carry a `chunks.json`: page faults resolve through the same sparse
  cache, but each chunk is fetched from the content-addressed store by
  digest and verified while copying — a corrupted or missing object is
  retried, never served. Artifacts without a chunk manifest transparently
  fall back to the plain backing file. Each sandbox stages in its own
  cache file (`uffd-cache-<sandbox-id>`), so concurrent restores never
  share sparse caches.

## Node-local checkpoint catalog

`[plugin.checkpoint_catalog]` optionally exposes a read-only inventory of the
node's Firecracker v2 checkpoint directories over a Unix socket:

```toml
[plugin.checkpoint_catalog]
sock_path = "/var/run/checkpoint-catalog.sock"
dirs = ["/mnt/cn/ck/nodeA"]
```

Each configured `dirs` root is scanned one level deep; an immediate
subdirectory carrying a `manifest.json` is listed as a checkpoint. The
catalog is a live view, not a database: every request re-reads the manifests,
so entries appear and disappear with the artifacts and nothing drifts.

- `GET /api/v1/checkpoints` returns `{id, dir, snapshot_type, memory_mib,
  created_at, compat, digests}` per entry. The `compat` tuple is what a
  cross-node consumer matches against a target node before placing a restore.
- `GET /api/v1/checkpoints/{id}/verify` recomputes the sha256 of every
  component with a recorded digest (memory included unless it was sealed with
  `digest_memory = false`; the overlay is never digested by policy) and
  reports per-component outcomes plus a single `digest_ok`.

Unsealed directories (no manifest, or a manifest version other than 2) are
skipped rather than reported as broken: a restore never sees a half-written
checkpoint, and neither does the catalog.

`listen` optionally serves the same endpoints over TCP for off-node
consumers, and the node additionally advertises itself at
`GET /api/v1/node`: its ID (or hostname), the software stack each enabled
runtime restores with (the same digests the compatibility tuple seals,
served by `pkg/checkpointlocator`'s record shape), and informational CPU
and kernel facts that do not gate placement today.

`templates` adds the template-manufacture roots (deploy/fc-template.sh
layout: content-addressed directories plus a `templates.json` registry) to
the same view:

- `GET /api/v1/templates` lists registered templates whose directory still
  exists, with the compat tuple a placer matches against.
- `GET /api/v1/templates/{id}/verify` re-derives the content address — the
  same ordered concatenation the manufacture pipeline hashed — and re-checks
  the recorded component digests. A template whose bytes drifted from its
  registered id must not be derived from.

Template placement (`checkpointlocator.DecideTemplate`, `cn-locator
-template-id`) requires a node to both hold the template and pass the
compatibility matrix; derivation itself is the ordinary restore path with
the template directory as `checkpoint_dir`.

### Chunked distribution (checkpointchunks / chunkstore / checkpointpublish)

A checkpoint's memory file can be distributed as fixed-size content-addressed
chunks (default 256 KiB, matching the uffd handler's fetch granularity).
`chunks.json`, a sidecar written after the artifact is sealed, lists every
chunk's offset and sha256 plus the whole-file digest as a cross-check; it
never participates in the seal or the template content address.

`cn-publish -checkpoint-dir DIR -store DIR` drives the publish state machine
(persisted at `<root>/.publish/<id>.json`, beside — never inside — the
artifact): `local_ready -> publishing -> published | publish_failed`.
Publishing is external orchestration: the checkpoint RPC has already
returned, local restores are unaffected by its outcome, and a failed or
interrupted run resumes and re-puts only the chunks the store is missing.
State files are written to a temp file and atomically renamed, and publish
requests are deduplicated by digest first — repeated chunks (the all-zero
chunk above all) cost one Has/Put, not one per entry. Published objects are
immutable and content-addressed in the store (`root/<aa>/<sha256>`), so
generations sharing page ranges share objects and no consumer can fetch
wrong bytes.

`cn-publishd` treats a `publishing` record older than `-stale` (default
10m) as a crash leftover and re-queues it: publishing is idempotent, so the
rerun only puts objects the store still lacks. Younger `publishing`
records may belong to a live concurrent publisher and are skipped.

`Run` and `RunWithOptions` acquire a nonblocking local `flock` before reading or changing publication state or issuing store requests. The lock covers memory, packed and overlay publication through the final state write. An overlapping attempt returns `ErrPublishBusy` without changing the active owner's state. The lock is keyed by the canonical checkpoint directory and stored beside its publication state; the file remains after release and must not be unlinked while publishers may use it. Closing the descriptor or process exit releases ownership, including after a crash. `StartedAt` remains a scheduling hint, not proof that an owner is dead. This coordinates cooperating publishers on the same filesystem, not independent checkpoint copies or a distributed object-store lease. Older publishers that do not acquire this lock must not overlap with the new version when relying on this guarantee.

The writable layer ships the same way when its sidecar
(`overlay.ext4.chunks.json`) exists: overlay chunks live in a global
content-addressed namespace (`overlay-chunks/<aa>/<sha256>`, no checkpoint
id in the key), so unchanged overlay blocks are shared across generations
and nodes. Materialization recognizes the all-zero chunk digests by length
and synthesizes those blocks as sparse holes — no GET, no write. Each reference must match the exact object length, including the final short chunk; a digest cannot be reused for different reference lengths. Materialization rejects both short and oversized objects before writing them, and the zero shortcut applies only to the digest of that reference’s exact length.

`Materialize` (cn-fetch) rebuilds a restorable directory on a node that
never saw the source. Every file is digest-verified against the INDEX, the
INDEX's memory root is cross-checked against the chunk sidecar, and the
whole rebuild lands in a staging directory committed by one rename — a
crash leaves either nothing or a complete artifact, never a half-built
directory, and a non-empty target is refused rather than overwritten.

Materialization stages under `<target-parent>/.materialize/staging-*`, independently of the `.publish` control-state directory. Keep `.materialize` on the target filesystem so the final rename remains atomic; do not relocate that staging directory to the control-state filesystem. Relocating `.publish` therefore does not move fetched artifacts across filesystems. Scanners ignore the hidden staging namespace, and each materialization removes only its own temporary directory on completion or failure. Existing `.publish/staging-*` leftovers from older versions are not migrated or removed automatically. This separation does not itself configure or migrate the publication state directory.

Only `published` unlocks cross-node placement: `cn-locator
-require-published` gates the cross-node branch of the placement tree on the
persisted state (the origin is exempt — it holds the local artifact), and
the catalog reports each entry's `publish_state`.

A remote-restore caveat shapes later checkpoints: the materialized memory
file is a sparse placeholder whose real bytes live in the chunk store.
Until every page has been faulted in, that file is not a complete image, so
it is never adopted as an incremental base — the next checkpoint takes a
Full snapshot (which pulls any unfetched pages through the handler inside
the pause window) rather than silently emitting zeros for unfaulted pages
in later incremental generations. Correspondingly, the uffd handler serves
a complete local memory image directly from the backing file even when a
chunk store is configured (fail-open to local); a broken chunk manifest
over a sparse placeholder is a hard failure, never a silent fall-back to
zeros.

### Placement (checkpointlocator)

`pkg/checkpointlocator` decides which node may restore a checkpoint. Its
matrix mirrors the restore-side verification exactly: equality on every
tuple field the checkpoint recorded, unrecorded fields never gate, and a
pre-tuple artifact verifies anywhere. Its placement tree runs
origin-first — the node a checkpoint was created on wins whenever it is
registered — then the earliest compatible candidate in stable node order,
and an unsatisfiable request fails closed with per-node reasons instead of
degrading. `PinToOrigin` models checkpoints that cannot leave their origin
(for example, host-local mounts). The `cn-locator` command federates the
node records over the catalogs' TCP endpoints and prints the decision.

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
deterministic replay, and automatic recovery of a
source after checkpoint failure are outside this design. `cn-migrate`
orchestrates stop-and-copy migration on top of these primitives: it
checkpoints with leave-running=false (the source freezes at the checkpoint
instant — no dual-writer window, no lost post-checkpoint writes), uses a
fresh immutable checkpoint id per attempt, verifies the target by parsing
the listing for the exact id in the RUNNING state, rolls the source back
from its local checkpoint directory if any post-checkpoint step fails, and
treats a failed source deletion as a hard failure rather than success.

### Sparse overlay chunk sealing

Sealing an immutable local overlay preserves the SHA-256 of every logical chunk and its existing root digest. Complete chunks proven to be holes by `SEEK_DATA`/`SEEK_HOLE` reuse the zero digest without reading; chunks overlapping data extents are read and verified normally. Allocated all-zero chunks reuse the same digest after reading. Unsupported extent queries fall back to reads; physical allocation size is never used as proof of artifact completeness. This optimization does not authorize a remote memory placeholder as a local incremental base. Overlay and memory sealing durations are logged separately.

### Zero memory chunks during remote restore

For chunk-manifest restores, a chunk whose recorded digest equals the SHA-256 of the correctly sized zero buffer is served from locally generated zero bytes. Fault handling allocates only the requested page/span, including short-tail bounds; prefetch does not GET or persist the redundant zero object. Nonzero chunks retain download length and digest checks before becoming readable. Sparse backing allocation is never evidence for this fast path. The fetched bitmap therefore records either verified cache bytes or digest-derived zero content. Plain HTTP Range and complete local backing reads retain their existing behavior.

### Publisher memory-upload concurrency

`cn-publish -workers N` selects 1–64 concurrent memory chunk jobs; `0` preserves the existing default of at most eight GOMAXPROCS workers. Library callers can use `checkpointpublish.RunWithOptions` with `Options.Workers`; `Run` keeps its defaults. Invalid values fail before touching publish state. Each worker processes one unique digest at a time, so this bounds worker buffers and concurrent HEAD/PUT requests; overlay workers remain independently capped at eight and run in their existing artifact phase. The selected memory worker count is included in the result and CLI output. Higher concurrency should be chosen using backend measurements, not assumed to improve throughput.

### Repeated nonzero memory chunks

Within one UFFD restore, nonzero references with the same digest and exact length share a download and verification. Once the first cache extent is verified, later positions copy its immutable bytes into their own logical offsets and only then become readable. Failed downloads never publish a reusable extent. The handler retains only offsets and in-flight notifications, not a permanent in-memory payload copy; the persistent digest cache is populated by the first successful download. Zero chunks and HTTP Range sources keep their existing paths.

### Bounded persistent chunk cache writes

UFFD persistent cache writes default to sixteen background workers; `-persist-workers N` explicitly selects 1–64. Invalid values fail before any socket is removed or opened. `plugin.runtime.firecracker.uffd_persist_workers` forwards an explicit 1–64 budget from sandboxd; `0` inherits the handler default and does not pass the new flag to older handlers. Invalid configuration values fail before runtime setup. Pending work retains only a digest and its verified sandbox-cache extent, with at most one task per unique digest and a metadata queue bounded by the manifest entry count. Each worker reads one chunk when it starts writing, so pending fsync operations no longer retain all downloaded payloads or create a goroutine per chunk. Normal queueing does not block faults or discard warm-cache work. VMM shutdown stops submissions and drops unstarted rebuildable cache tasks; at most the configured number of writes already in progress remain, and fault handling does not wait for them. Persistence still uses temporary files, fsync and atomic rename.

### Packed-object range transport prerequisite

The optional `chunkstore.RangeReader` interface reads an explicit `(offset, length, object_size)` from an immutable keyed object. It bounds each allocation to 8MiB, rejects invalid or overflowing ranges before IO, and returns bytes only after exact length validation. HTTP requires `206 Partial Content`, an exact `Content-Range` including total object size, and identity encoding; a server that ignores Range and returns the entire object is rejected. Local reads require a regular file with the expected total size. Context cancellation propagates through HTTP reads; local reads check cancellation before and after file IO. Callers must still verify the chunk's content digest before making it visible. This interface alone does not enable packed publication or change the version-1 checkpoint layout.

### Version-2 memory transport sidecars

Pack-aware materialization and UFFD readers accept version-2 memory chunk sidecars. The logical entries and file digest retain their version-1 meaning; `packs` optionally maps a chunk digest to an immutable pack digest, byte offset, chunk length, and total object size. Unmapped entries still use the existing digest-addressed single objects. Pack keys are derived as `memory-packs/<digest>`. References must name existing chunks of the exact length, stay within an object of at most 8MiB, agree on each pack's total size, and not overlap references for distinct chunks. Repeated logical positions with the same chunk digest reuse one mapping and the existing verified-digest cache. The INDEX checksum binds the entire sidecar including transport mappings.

UFFD packed reads use strict local/HTTP range validation followed by the chunk SHA check before publishing cache availability. A persistent verified chunk remains reusable across transport formats. Packed requests have a 60-second deadline and are cancelled when the VMM handshake disconnects. Cancellation of the legacy standalone/HTTP-memory paths and all retry/prefetch waiters is separate outstanding work. Complete local memory images continue to be checked against logical chunk digests without fetching packs. Legacy `checkpointchunks.Load` and `LoadNamed` reject transport versions 2 and 3; only explicitly pack-aware `LoadTransport` consumers accept them. Republish still requires a complete version-1 source image; transport placeholders are not eligible sources.

### Opt-in packed memory publication

`cn-publish -pack-mib 4` publishes missing memory chunks in deterministic digest order into packs of at most 4MiB. `-workers` also caps pack concurrency; an additional active pack payload budget (16MiB by default) bounds the pack worker count. This budget excludes manifests, transport/network overhead, and later overlay publication. Single-chunk CAS hits remain reusable, and zero chunks need no object. Each newly packed chunk is read at its exact sealed length and SHA-verified before any pack is uploaded; by default pack keys derive from the entire pack hash. Retry checks these deterministic keys and skips completed packs. CLI/result pack counts are separate from unique chunk counts.

Packing requires a sealed `memory` artifact in chunks digest mode whose size and root agree with the Firecracker manifest; materialized placeholders are rejected. The source `chunks.json` remains unchanged. The publisher constructs a version-2 transport sidecar in memory, uploads all referenced objects first, and writes the remote artifact INDEX last. Consumers verify the INDEX-bound sidecar and each fetched chunk. Local keyed writes now use a synced temporary file, atomic rename, and parent directory sync, so an in-progress pack or INDEX never becomes visible as a partially written object. This is not a distributed ownership or concurrent checkpoint-ID reuse protocol.

`-base-id ID` optionally reuses pack references from a published baseline in the same store. Its INDEX, memory sidecar, and Firecracker memory identity must agree before reuse; each distinct referenced pack is checked for existence once. Missing baseline packs are rebuilt from the complete source, while malformed baseline metadata fails publication. A baseline ID is an explicit lookup hint, not global discovery of every pack containing a digest. Legacy single-object CAS lookup remains global, but arbitrary pack discovery and pack garbage collection are still outstanding. `-pack-mib 0` retains legacy publication; a baseline argument is invalid when packing is disabled or names the checkpoint being published.

Packed publication exposes `pack_timings` with nanosecond wall times for preparation, existence classification, pack construction/upload, and artifact publication. `build_total_ns` and `upload_total_ns` sum overlapping worker elapsed times and must not be read as CPU time or added to wall phases. `cn-publish -cpu-profile NEW_FILE` optionally records a Go CPU profile; the output file must not already exist. Profiled runs are diagnostic samples, separate from latency comparisons. CLI output distinguishes logical chunk entries, unique digest counts, and physical pack objects. Packed publication requires nonempty memory; an empty artifact cannot represent a restorable VM.

### Versioned chunk-root pack identity (opt-in)

`cn-publish -pack-mib 4 -pack-identity chunks-v1` uses version-3 memory transport sidecars. Each new pack reference carries `identity: "chunks-v1"`; its key is `memory-chunk-packs-v1/<digest>`. The digest is SHA256 over the ASCII domain `akernel.memory-chunk-pack`, NUL, `v1`, NUL, the part count as an unsigned 64-bit big-endian integer, then each part's unsigned 64-bit big-endian byte length and raw 32-byte SHA256 digest in payload order. Parts must have positive lengths, valid lowercase digests, and a combined size at most 8MiB. Empty packs are invalid. This identity is a hash of the canonical chunk sequence, not the whole payload SHA256. The publisher still reads and verifies each source chunk before publishing, removing only the additional whole-pack hash used for object naming. Storage authentication may independently hash the HTTP payload.

An absent reference identity retains the original whole-pack SHA256 namespace; unknown identities fail validation. Version 2 disallows nonempty identities. Version 3 may mix inherited legacy packs, chunk-root packs, and standalone CAS objects. Parent existence checks and reference overlap checks use the full object key, including its identity namespace. Even when the current command uses legacy pack identity, inheriting a chunk-root reference requires a version-3 envelope. Old version-2-only readers reject version 3; deploy a compatible materializer and UFFD reader together before using this option.

Range readers verify the exact response range, length, and each chunk SHA before making bytes available. A manifest that inherits only a subset of a parent pack cannot recompute the complete pack identity from those references; neither legacy whole-pack identity nor chunk-root identity is asserted to have been verified by a partial read. Actual fetched content is bound by the chunk digest and INDEX-bound sidecar. The sealed source sidecar, logical memory root, and Firecracker compatibility tuple remain unchanged. Packing and the new identity remain opt-in pending complete performance and real-VMM validation.

### Single-chunk upload buffering

Standalone remote chunk uploads retain the 8MiB size bound and verify a private stable copy against the claimed digest before issuing PUT. Standard in-memory readers are copied into a buffer sized to their remaining bytes, preserving the current offset and avoiding repeated growth. Arbitrary readers retain bounded streaming reads; custom length hints are not trusted. The publisher uses a standard bytes reader over its worker buffer and waits for Put to finish before reusing that buffer. This changes neither the object format nor the digest-before-upload contract.

### Remote object HTTP connection reuse

Remote object-store instances share a package-owned HTTP transport. On first use, the standard process default transport is cloned with at most 64 idle connections per host and 128 idle connections overall; proxy, TLS, HTTP/2, idle expiration and other inherited transport behavior are preserved. The process default is not mutated. A custom nonstandard RoundTripper installed before first use is retained without pool tuning. Clients retain their 120-second timeout. Idle retention is not an active-request concurrency limit; publisher and prefetch worker limits still apply. Legacy UFFD HTTP clients with their separate 16-idle-connection configuration are unchanged by this adjustment.

### Explicit pack payload budget

`cn-publish -pack-mib 4 -pack-identity chunks-v1 -pack-payload-mib 32` permits up to 32MiB of simultaneously active pack payload. Zero retains the 16MiB default; explicit budgets require packing, must fit at least one pack and cannot exceed 64MiB. Library `Options.PackPayloadBytes` follows the same rules. Invalid combinations fail before state or object publication. Worker count is the minimum of the requested workers and budget divided by pack size. CLI/result report the chosen budget and observed peak active payload, including build and upload phases until each worker job returns. This is not a limit on RSS, garbage-collector retained buffers, metadata or HTTP overhead. The object format, per-chunk verification, deterministic pack identity and INDEX-last semantics are unchanged. Standalone chunk publication is unaffected.

### Experimental UFFD forward population

The standalone `firecracker-uffd-handler` accepts `-copy-kb` (4–256, a multiple of 4). The default remains 4 KiB. Larger values opt into forward population beginning at the faulting page, bounded by the source chunk and guest region; this does not change remote fetch chunk size. Existing guest pages are never overwritten by COPY. A partial COPY resolves only its installed prefix; the handler does not mark the remaining guest range populated. This option is experimental and is not yet exposed through sandboxd runtime configuration. Userfaultfd kernel tests do not replace KVM cross-node acceptance.

### Local backing verification foundation

`checkpointchunks.VerifyMemoryBacking` provides a Linux process-local proof bound to an outer expected digest/mode, the exact memory bytes and file identities. It rejects `.materialized` even when the file is preallocated. Reopening or checking a proof revalidates content: filesystem timestamps can remain unchanged across rapid writes, so metadata alone cannot certify cached contents. Callers must keep artifacts immutable during use; this proof is not a writer lock or a serialized completeness certificate. The tier/adoption and UFFD source-selection paths do not yet consume this proof, so sparse bases remain subject to the existing Full fallback. `checkpointchunks.Verify` also rejects extra trailing bytes beyond the sidecar's declared size.

The verified clone helper opens the proven source descriptor once, creates the destination exclusively, clones/copies that descriptor, and rechecks the source proof before returning. A failed verified clone removes only its newly created destination. This helper is not yet wired into tier selection or adoption. Content verification still reads every logical byte; a block matching the known zero digest can use an actual all-zero byte comparison instead of recomputing SHA for that block. Nonzero blocks and the legacy whole-file SHA mode retain their digest checks.

A successful local checkpoint seal may now retain a process-local proof for a sparse memory image. Tier selection performs only association/shape/marker prechecks; incremental layout must use the proven fd and full pre/post clone validation. A failed layout drops lineage and follows the existing Full fallback before requesting a VM snapshot. Plain base assignment, clearing and lineage loss discard the proof, and persisted runtime state does not restore it. Restore adoption and UFFD source selection remain conservative; this change does not yet enable sparse Full output or trust remote placeholders. Dense base eligibility now also rechecks `.materialized`, including dangling marker symlinks.

The UFFD handler accepts an unmarked sparse local `memory` image only after verifying its actual bytes against `chunks.json` and the outer manifest's memory digest, digest mode, and size. It serves the verified descriptor directly with or without a configured chunk store. Missing or invalid local proof fails startup. A `.materialized` marker, including a dangling symlink or an inspection error, forbids local serving; such artifacts require a chunk store. Dense legacy backing selection remains compatible. This proof is a startup validation, not a lock against concurrent modifications: managed artifacts must remain immutable during page serving.

Experimental `plugin.runtime.firecracker.sparse_full = true` requests zero-skipping output only when the selected snapshot tier is Full. It requires a fork VMM accepting `sparse_full` and a handler supporting verified sparse local memory. The default is false and sends no new API field. Incremental tiers keep their existing base-patching behavior. The Full memory target must not exist: the VMM creates it exclusively, preserving existing files instead of truncating them. Failed or partial output is not a committed artifact. This option does not weaken synchronization, manifest sealing, or the remote-placeholder lineage guard; it is not enabled in deployed defaults.

After successful sealing, a stop-and-copy checkpoint (`leave_running=false`) invalidates the source's incremental lineage instead of scanning the new memory file to create a continuation proof. The sealed artifact, its validation, persistence and writeback policy remain unchanged. If stopping the source fails, its next checkpoint requires Full; it cannot reuse the prior base after the dirty ledger advanced. Leave-running checkpoints still adopt a verified continuation base.

In `chunks` memory digest mode, sealing a locally produced checkpoint uses file extent queries to synthesize the known digest only for complete hole chunks. Allocated chunks are read and checked; unsupported extent queries fall back to reading. The resulting sidecar has the same logical-byte digests and format. This does not establish remote placeholder completeness or bypass backing-proof validation. Sequential SHA-256 mode continues to hash all logical bytes.

A local backing proof in `chunks` mode may avoid reading a chunk only when its expected digest is the exact zero digest for its length and a fresh, same-identity file descriptor confirms the whole range is a hole. Extent state is rebuilt per validation; unsupported queries fall back to reading, and query errors fail validation. Nonzero expected chunks and sequential SHA-256 mode still read the contents. The existing outer digest/mode, identity, size and materialized-marker checks remain required; this does not authorize remote placeholder lineage or concurrent mutation.

Chunk-root content verification hashes independent chunks with at most eight workers, capped by GOMAXPROCS and an 8MiB chunk-buffer budget. Reading and verified-hole queries remain sequential, buffers are reused, and every return joins workers before the backing identity is rechecked or the fd is closed. Large chunks and single-CPU callers retain serial verification; sequential whole-file SHA-256 mode is unchanged. Every required chunk digest and the ordered root remain mandatory.

Local chunk-mode restore uses the same complete-file verification engine as backing checks, including actual-zero-hole handling, bounded workers, and joining on failure. Ordinary and transport sidecars are accepted for content verification, but transport sidecars do not authorize reusable incremental lineage. Sidecar memory size must match the outer manifest and its own root must be valid. Historical omitted outer digests remain optional; when present they must match. This does not relax materialized-placeholder handling or authenticate an omitted outer digest.

### Local verification scheduling

Local memory chunk verification uses a separate, cancellable single-scan gate per Firecracker handler. It retains full content verification and the existing one-scan CPU/buffer bound, while materialized remote checkpoints can verify their other components without waiting for that local memory scan. This does not increase local scan concurrency or change digest requirements, artifact representation, or the legacy component cache identity policy. Non-memory component cache access remains serialized; this change is not a general deadline guarantee for every restore phase.

### Node checkpoint/restore concurrency

`plugin.runtime.firecracker.checkpoint_concurrency` limits simultaneous Firecracker checkpoint and restore operations across the node. Omitted or `0` retains the historical limit of one; explicit values `1` through `8` are accepted. The gate is initialized once from the node configuration; changing the limit requires restarting the daemon. Invalid values fail C/R admission. Waiting requests honor context cancellation, and releasing a slot is idempotent. This is a concurrency bound, not a fair queue or a throughput guarantee.

Restore and the existing cgroup-v1 checkpoint path still reserve transient memory atomically and fail if node capacity is insufficient; increasing concurrency does not bypass that reservation or the managed cgroup checks. The cgroup-v2 checkpoint path retains its existing temporary cgroup behavior without an additional memory reservation, so operators must budget simultaneous snapshot/page-cache pressure before increasing the limit. The default is unchanged pending concurrent KVM validation. Local memory content scans retain their independent single-scan gate; runtime component verification and source ownership requirements are unchanged.

The standalone handler also accepts experimental `-zero-page` (default false). It uses UFFDIO_ZEROPAGE only for whole page spans contained in a manifest-proven zero chunk in remote mode; local backing files and hugepage mappings keep COPY. Unsupported range/kernel ioctls or no-progress interruptions fall back to COPY. Partial zero supply resolves only its installed prefix and never overwrites existing guest pages. This does not make unverified sparse placeholders valid data, change lineage eligibility, or remove the requirement for KVM acceptance before promotion.

Background UFFD prefetch stops dispatching on the first chunk fetch failure and waits for already-running workers before reporting its completed count. This stops only the prefetch walk; it does not cancel the page source shared with foreground faults. In-flight fetches retain their existing I/O timeout/cancellation behavior. Prefetch budget and concurrency defaults are unchanged.

The AKernel fork now establishes or reopens the soft-dirty window after a successful Full memory write and any required synchronization. A subsequent SoftDirty target must be based on that Full image; callers cannot continue patching an older baseline across Full. The continuing-sandbox path adopts the sealed Full image, while failure after the VMM advances its window invalidates lineage and requires another Full. If tracking setup is unavailable or fails, Full remains valid and later incremental requests retain the safe cumulative-baseline/failure behavior. This does not change artifact format, durability, or remote-placeholder eligibility. The behavior requires the corresponding fork candidate; deployed runtime pins are unchanged pending acceptance.

UFFD fetches bind legacy HTTP Range requests to the page-source lifecycle context, with a 60-second client timeout per request. Retry backoff and waits for an existing chunk or digest leader respond to source cancellation. Canceling a waiter does not close the leader completion channel or mark bytes fetched. This does not add a timeout to local filesystem I/O or change the prefetch budget/default policy.

UFFD source cancellation also applies to ordinary v1 digest-object HTTP GETs, including reads blocked after response headers. These requests retain the shared client and its 60-second timeout; cancellation does not publish an incomplete chunk into the verified cache. This complements legacy Range and packed-range cancellation and does not make local filesystem I/O interruptible.

### Firecracker VMM diagnostic logging

`plugin.runtime.firecracker.vmm_log_level` optionally sets the native VMM startup `--level` argument for both create and restore. An empty value preserves the VMM default; supported values are Off, Trace, Debug, Info, Warn/Warning and Error (case insensitive). Debug/Trace can affect measured timing and must be recorded with benchmark configuration. Configure the actual Firecracker executable, not a shell wrapper: runtime ownership checks require both argv[0] and /proc/PID/exe to match the configured binary. Log configuration does not change checkpoint format or relax those checks.

### Experimental incremental content filtering

Firecracker `skip_unchanged=true` is an opt-in for Incremental and SoftDirty memory snapshots only. The caller still supplies a complete, correctly sized base from the latest valid generation. The VMM must be paused, and the caller must keep the base immutable except for this snapshot operation. The target must be readable as well as writable. A fixed 256KiB comparison buffer compares current guest bytes with the target; equal 4KiB granules are skipped, and adjacent changed granules are written together. All bytes in the resulting image retain the ordinary incremental semantics, including true zero holes. Read failures are snapshot failures, never permission to skip data.

This option does not change flush/fsync, acknowledgement, or failed-generation lineage invalidation requirements. Full, Diff and state-only requests with the option are rejected. It is disabled by default because reading a cold base can add I/O and regress workloads where most bytes change. Diagnostic output records compared, written and skipped bytes. In sandboxd, `plugin.runtime.firecracker.skip_unchanged` enables the option only when the selected tier is Incremental or SoftDirty, and requires a matching experimental FC binary; Full fallback remains unchanged.

### Experimental incremental memory audit

`plugin.runtime.firecracker.verify_incremental_memory = true` requests a diagnostic comparison of the complete plugged guest RAM with the resulting memory image after incremental writes, while the guest is paused and before dirty-accounting acknowledgement/rearming. It requires a matching experimental Firecracker binary and a readable, complete base. The option is independent of `skip_unchanged`; it is omitted from default API requests and sent only for Incremental or SoftDirty. Full fallback does not send it. Direct VMM requests enabling it for Full, Diff or state-only are rejected.

A mismatch or read error fails the snapshot and disarms incremental tracking; sandboxd must invalidate the failed lineage under its existing failure contract. The partially modified target must not be published as a successful checkpoint. Diagnostic logs report at most 64 first differing addresses, their file offsets and whether they fall in the actual written ranges, followed by mismatched 4KiB-granule counts; guest byte contents are not logged. The comparison handles plugged regions and does not validate unplugged memory contents. It neither replaces artifact sealing/synchronization nor proves correctness of device state or the whole migration protocol.

This audit adds a complete RAM/file read to the pause window, with two 256KiB comparison buffers plus range metadata. It is disabled by default and is a diagnostic aid, not a repair for omitted pages or a performance optimization. Runs with it enabled must be labeled separately from performance measurements.

Optional `plugin.runtime.firecracker.verify_incremental_memory_stop_only = true` restricts an enabled audit to checkpoints with `leave_running=false`. It defaults to false and has no effect unless `verify_incremental_memory` is enabled. Continuing checkpoints then omit the audit field, avoiding extra diagnostic RAM reads in intermediate incremental windows; Full and Diff still never request it. This restriction helps investigate observation-sensitive failures and does not certify unaudited generations or change the snapshot failure contract.
