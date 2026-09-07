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
read-only exports, loads its sidecar before enabling queues, and resumes the
guest only after the device and memory state agree.

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

Firecracker `Delete` is exit-gated. For a sandbox whose recorded VMM process it can still identify (argv, executable, API socket, and ID all match), sandboxd first asks the guest agent to shut down as a best-effort graceful stop, then stops the process and waits for the kernel's exit notification through a pidfd — not the disappearance of `/proc` identity, which can precede the completion of exit teardown — before it removes the in-memory instance, the persisted state file, the writable layer, and the runtime socket directory. When the recorded PID cannot be identified, it may belong to another process after recycling or its identity may be unavailable while the exit is unconfirmed; sandboxd waits a bounded time for that process to exit on its own and never signals it. If the exit is not confirmed, `Delete` fails and leaves the instance, persisted state, and artifacts in place so the caller can retry.

A `Delete` that finds no in-memory instance and no persisted state still returns success for idempotency, but that legacy nil is an absence observation, not a retirement proof: it does not attest that any persistent generation of the sandbox stopped, and conditional deletion or receipt generation must not treat it as evidence that one did. Full fencing still requires authoritative generation and operation identity (ownership records, idempotency tokens, or an epoch protocol); this exit gate confirms only that the locally recorded process exited, and does not provide that protocol.

A failed fresh `Start` or `Restore` whose VMM process was already spawned rolls back through the same exit gate. Only a kernel-confirmed exit of the recorded process lets the runtime finish the instance, drop it from its instance map, and allow the deferred cleanup of the persisted state, writable layer, and runtime socket directory; the original failure is returned unchanged. When the exit cannot be confirmed — the recorded identity no longer matches the live process, the recorded PID is invalid, or the process survives the bounded signal sequence — nothing is finished, unmapped, or deleted: the instance stays mapped with all of its artifacts, the current incarnation identity (resource generation and PID) is persisted best effort — including when the failure happened before the first ordinary state persistence — and the returned error joins the original failure, the stop failure, and any persistence failure behind `runtime.ErrStartCleanupPending`, detectable with `errors.Is` by direct in-process callers of `runtime.Handler.Start` and `runtime.CheckpointHandler.Restore` (see below for what the sentinel does not cover). The instance is marked deleting before the stop attempt, as `Delete` does, so asynchronous exit persistence cannot race the artifact cleanup; on an unconfirmed exit that flag is not terminal — the instance stays mapped and unfinished and a retry still runs the full gate sequence. An identity mismatch never counts as an exit and never finishes the instance. Failures before the VMM is spawned keep the previous behavior: every artifact is cleaned up and the plain failure is returned.

`ErrStartCleanupPending` is a runtime-layer contract only, and the management plane does not protect the retained state today. On a runtime Start or Restore failure the server unconditionally cleans the sandbox root it allocated (`startSandboxRuntime` → `CleanSandboxRoot`) — erasing the very state file the runtime just retained — and then releases the sandbox ID, network, cgroup, and filesystem resources, so the retention above currently outlives the failed call only inside the runtime layer, not under the server's rollback. The public RPC path provides no sentinel detection either: crossing the gRPC boundary loses `errors.Is` semantics, so the sentinel is meaningful only on the direct runtime return value inside the daemon process. Until the management-plane integration lands (follow-up plan 0049) there is no promotion: a runtime-only fix must not be treated as closing the failure lifecycle. Nor is runtime-side retention a restart-safe quarantine: on daemon restart the loader moves a sandbox bundle without manager metadata (`meta.pb`) into `_recycle`, and housekeeping removes it, so a retained incarnation lives at most as long as the daemon that failed to start it.

One management-plane resource boundary is closed as a prerequisite slice of that plan: pooled cgroup leases are durable before handout. The cgroup manager persists its active set to the local store before `Allocate` returns a lease on both the cached and the freshly created path, the snapshot and the write of that store are serialized against the periodic flush so a background snapshot taken before a handout can never overwrite the confirmed lease afterwards, and shutdown closes `stopCh` before anything else so allocations waiting on a queued or delayed creation cancel exactly as they did before durable handoffs existed, then drains the short confirmation sections (stopped re-check, active-set mark, synchronous store, rollback — never the creation wait itself) so its final store is ordered after every already-confirmed in-flight handoff and cannot be overtaken by a later one, while handouts that had not confirmed fail closed without writing. The motivation is restart recovery: an existing cgroup that is absent from the persisted active set is recovered as idle, and recovering an idle cgroup drains it by killing whatever runs inside it, so a lease that reached the store only on the next periodic tick turned any daemon restart in that window into a kill of the sandbox that already started in the cgroup. A store failure now fails the allocation instead: the un-handed-out cgroup returns to the idle cache when there is room (nothing was started in it and `Allocate` itself applies no controls — `Prepare` runs only after the caller holds a confirmed lease) or is destroyed synchronously, and the pool reservation is released only after the physical removal succeeds so a concurrent allocation can never consume capacity that a failed delete must give back; a failed destroy keeps the lease active, quarantined inside the reservation it already holds — the pool ceiling is never exceeded — and never re-leased or handed through the GC queue. Residual gaps remain and are deliberate: a lease recycled close to a crash can still be recovered as active until the next flush (the safe direction — the cgroup is kept, not killed, but it leaks with no owner), a quarantined cgroup likewise survives restart as an unowned active lease, and this boundary covers only the resource lease itself — the sandbox-bundle reconciliation, retained-state protection, and ownership records of plan 0049 are still open, so a durable cgroup lease does not by itself make a failed or interrupted start recoverable.

Reconciliation of a retained sandbox must stay identity-based against the runtime's own record — a generation-matched strict retirement where that state still exists. A recorded process that is not a verified owned incarnation is never authorization to signal it, and the public `DeleteIfGeneration` additionally depends on server metadata that a failed start may never have written or that the server rollback above may already have erased, so it is not guaranteed to work for a retained sandbox; a foreign recorded process is an operator incident requiring out-of-band verification, not a documented self-service cleanup path.

On failure, sandboxd returns an error and does not force-delete, stop, or
resume the source. The caller decides how to handle the source sandbox.
sandboxd only cleans partial checkpoint output: it removes a leaf directory it
created, or empties a caller-provided leaf directory while preserving it.

## Conditional retirement (DeleteIfGeneration)

Every successful `Start` assigns a daemon-owned physical incarnation identity and returns it as `StartResponse.resource_generation` (field 5; field 4 stays unused to keep the scheduler-compatible numbering). The identity is also visible as the reserved `akernel.scheduler/resource-generation` sandbox label. A caller-supplied label under that key is replaced, never honored, so a client can neither choose nor reuse a sandbox's physical incarnation. The same value is passed to the runtime as `StartConfig.ResourceGeneration` on both fresh starts and restores; Firecracker binds it into its own persisted instance state and syncs the containing directory (plus the parent entries of a freshly created state directory) so the runtime record of the incarnation survives crashes.

`DeleteIfGeneration(id, expected_generation)` retires exactly that incarnation. It runs under the same per-ID physical lock as `Start` and `Checkpoint`, so creation, checkpoint, and deletion cannot interleave on one sandbox; `Start` holds the lock from ID reservation through its complete rollback, and the request timeout of a queued `Checkpoint` bounds its lock wait. Delete coalescing keys on `(id, expected_generation)`: a legacy `Delete` flight never joins a conditional one, and different expected generations do not share a flight.

Conditional retirement passes this gate sequence, in order, all under the physical lock. Failures at the gates before the runtime is invoked (receipt replay, identity recheck, capability, pending-journal write) leave the sandbox exactly as it was; once the runtime strict delete has begun, failures are unknown or partial — the runtime may already have stopped the sandbox and cleanup may be half-complete — and the receipt stays pending, with later retries reporting an unknown outcome rather than success.

1. A completed durable receipt for `(id, generation)` replays immediately as success — including across daemon restarts, because receipts live under `<root>/scheduler-retirements` in daemon-owned storage.
2. Otherwise the live sandbox must exist and still carry the expected generation. A missing sandbox without a receipt, a changed generation, or an unreadable/corrupt receipt is an error, never a retirement proof: absence and pending states attest nothing.
3. The runtime must provide strict conditional delete (`DeleteStrict`). Runtimes without it — currently every runtime except Firecracker — reject the RPC with `Unimplemented`.
4. A pending receipt is durably recorded before the runtime is invoked, so a crash mid-delete leaves an explicitly unfinished record. A journal write failure aborts the delete before any physical effect.
5. The runtime verifies the caller's expected generation against its own persisted incarnation identity — under the instance operation lock and before any state change, guest request, or signal — so the server's metadata label alone can never decide which physical state retires. A runtime record with no bound generation (written before this identity existed) is unsupported and rejected; a mismatch is rejected as a precondition failure without touching the recorded process or its artifacts; absent state is an error, because observing absence is not a retirement proof.
6. After the runtime strict delete confirms the exit and full resource cleanup completes, the sandbox state directory is confirmed absent — manager cleanup can fail silently — and only then is the receipt marked complete.

Network and resource side effects (including DNAT cleanup, for legacy and conditional deletes alike) happen only under the physical lock, and for conditional retirement only after the generation and strict-exit gates pass. Caller cancellation or timeout is an unknown outcome, not a failure verdict: cleanup continues detached from the caller's context, and the durable receipt decides later replays.

A pending receipt after an interrupted attempt means the outcome is unknown, not that retirement failed. Resolution requires identity-aware reconciliation that inspects the receipt and the recorded generation — for example reissuing the same `DeleteIfGeneration` while the incarnation still matches, or an operator reconciling the specific generation. An unconditional legacy `Delete` must not be used as the reconciliation fallback: it can destroy a replacement incarnation that reused the ID and it produces no retirement proof, so cross-node tooling (cn-migrate) must keep treating this state as unknown rather than falling back.

Not claimed by this mechanism: revoking a `Restore` that is already in flight under the same ID, complete ownership-transfer fencing, crash-cut power-loss durability of every intermediate artifact, or proving retirement of pre-generation sandboxes — sandboxes created before this identity exists carry no generation and are only deletable through legacy `Delete`.

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

If restore fails, sandboxd rolls back the partially created target. The
runtime side of that rollback is exit-gated like `Delete`: when the restored
VMM's exit cannot be confirmed, the target's runtime instance and artifacts
are retained and the returned error carries `runtime.ErrStartCleanupPending`
(see "Source and failure semantics"). It does not modify the source or delete
the checkpoint input.

After `Start` succeeds, the target no longer depends on the checkpoint
directory — with one exception: a Firecracker v2 restore keeps the artifact's
`memory` file as its tier-2 incremental base. A conventional restore also maps
that file privately; a virtio-fs restore maps an independent shared live clone.
The caller must keep the checkpoint directory intact until the restored
sandbox exits or establishes a later complete checkpoint generation.

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

For a new checkpoint root, `cn-state-layout -checkpoint-root ROOT -state-base BASE` explicitly initializes durable publication state outside the artifact root. Both directories must already exist; BASE must be outside ROOT. The command canonicalizes ROOT, creates a per-root SHA256-named directory under BASE with a versioned ownership record, and exposes it through ROOT/.publish. The owner file and prepared directory are synced before a no-replace rename, BASE is synced before linking, and ROOT is synced before success. Use a filesystem appropriate for durable control data; a different directory on the same filesystem is supported but has no promised performance benefit.

Initialization never migrates or overwrites an existing `.publish` directory, even if empty. A matching managed link can be retried without replacing the link, states, or publication lock files. A fully prepared owner-only target can be linked on retry; existing states with a missing root link, mismatched/corrupt ownership, a different link, or a dangling configured link are rejected and preserved. Temporary preparation directories left by a crash are not automatically removed. Canonical root paths are part of layout identity: moving a configured root requires explicit operational handling, not automatic retargeting.

Concurrent initializers use a persistent local flock; contention returns an error for retry. Competing state bases or a publisher that creates `.publish` first cannot be overwritten because link creation is exclusive. This lock coordinates initialization only; normal Run/Status/publishd/claim operations continue through the same StatePath. Initialization is an explicit provisioning step, not part of the checkpoint latency window. Receivers using an external `.publish` must run a cn-fetch version with the independent `.materialize` staging layout. The initializer requires Linux flock and no-replace rename support plus directory fsync; unsupported operations return errors rather than weakening the commit sequence. No distributed lease or existing-state migration is provided by this command.


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
deterministic replay, migration orchestration, and automatic recovery of a
source after checkpoint failure are outside this design.

## Writable block I/O policy

New sandboxes default to `writable_io_engine = "AsyncDirect"` and `writable_cache_type = "Writeback"` in `plugin.runtime.firecracker`. The pinned Firecracker runtime bundle includes direct-I/O alignment support. Operators using an older VMM must explicitly select `Async` or `Sync`. The writable policy applies to the private ext4 disk, including native writable mounts. It does not change EROFS root disks, virtio-fs exports, or checkpoint memory-file I/O.

The VMM persists the engine and cache policy in device state and reopens the writable disk with the saved policy on restore. Changing sandboxd's defaults affects newly created VMs; it does not override the policy captured in an existing checkpoint. Checkpoint compatibility still requires matching runtime digests. Direct-I/O alignment requirements are queried again for the restored image on its destination filesystem. Request-owned alignment buffers and in-flight I/O are completed before snapshotting; completed reads reach guest memory and dirty tracking before the device state is saved. Alignment buffers are not separate checkpoint artifacts.

The destination host must support the saved I/O engine. In particular, direct engines require the destination kernel and backing filesystem to report `STATX_DIOALIGN`, normally available for ext4 and XFS on upstream Linux 6.1 or newer; asynchronous engines also require usable `io_uring`. Restore fails when those capabilities are unavailable and never automatically changes the saved engine to buffered I/O. Operators using hosts without Direct I/O alignment-query support must explicitly configure `Async` or `Sync` before creating new sandboxes; this setting cannot make an existing Direct I/O checkpoint compatible with such a host. See [host I/O compatibility and configuration](runtime.md) for details.
