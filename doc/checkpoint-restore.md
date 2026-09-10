# Checkpoint and restore

sandboxd supports checkpointing a running sandbox into a caller-owned
directory and starting a new sandbox from that checkpoint.

## Design

The API has two operations:

1. `SandboxService.Checkpoint` checkpoints an existing sandbox; `CheckpointIfGeneration` additionally binds the operation to a server-assigned physical generation.
2. The existing `Start` RPC restores a sandbox when `checkpoint_info` is set.

There is no separate restore RPC. Restore is a form of sandbox creation, so it
uses the normal `Start` path to allocate the target sandbox's filesystem,
network, cgroup, and other resources.

sandboxd coordinates the runtime operation and cleans partial output produced before the runtime checkpoint call is entered; once that call is entered, a failed, timed-out, or cancelled checkpoint retains the output directory and reports an unknown outcome (see "Source and failure semantics"). It does not manage checkpoint names, catalogs, storage, transfer, retention, or compatibility negotiation. The caller chooses the checkpoint directory and owns a successful artifact.

`ListAvailableRuntimes` reports checkpoint/restore support for each initialized
runtime handler. A supporting runtime may also advertise guest-visible
checkpoint handoff and restore-environment paths. Callers can use this metadata
to configure cooperative workloads and reject unsupported requests early, but
the `Checkpoint` and restore `Start` RPCs remain authoritative and validate the
runtime again when they execute.

## Checkpoint API

`CheckpointIfGeneration` takes a nested `CheckpointRequest` and a nonempty `expected_generation` of at most 256 bytes, obtained from the original `StartResponse.resource_generation`. The daemon compares this value exactly with the current incarnation while holding the same per-ID physical lock used by Start and Delete. A missing or changed generation returns `FailedPrecondition` before allocating the checkpoint output directory or invoking the runtime. A request queued behind a replacement checks the replacement metadata after acquiring the lock. Pending start intents remain protected.

Firecracker also checks the expected generation against its own persisted instance identity. A cold lookup checks before recovering the instance, and the checkpoint checks again under the instance operation lock before layout, pause, or snapshot. A missing or different runtime generation is rejected without those runtime actions. This runtime check occurs after the service has allocated the output directory; an identified operation conservatively records UNKNOWN for an error returned after entering the runtime, even when the runtime rejected it before snapshotting. Legacy `Checkpoint` carries no expectation, and runtimes without a persisted generation retain their existing behavior. This is a node-local identity check, not cross-node fencing.

This is a separate RPC: older servers return `Unimplemented`, and callers requiring this precondition must not fall back to unconditional `Checkpoint`. Legacy `Checkpoint` retains its existing behavior. The conditional RPC does not provide durable operation replay, cross-node fencing, or proof that a timed-out checkpoint did not execute; a migration controller must still reconcile an unknown outcome.

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

### Retryable guest abort notification (protocol message type 11)

The legacy `MessageCheckpoint` lifecycle event (message type 10) carries no operation identity, so a repeated `error` outcome — for example a retry after the host lost the release reply — can release a cooperative handoff reader that registered after the first delivery. That legacy behavior is unchanged for legacy senders. A retryable abort instead uses the separate `MessageCheckpointAbort` message (type 11) whose `CheckpointAbortRequest` identifies the operation: a nonempty `operation_id` and `source_generation`, each at most 256 bytes, and a `request_digest` of exactly 64 hexadecimal characters. The message has no outcome field — the outcome is always the terminal `error` handoff. A guest agent that predates the message rejects it as an unknown type with an error response and no handoff side effect; the host MUST NOT fall back to the legacy message for a retryable abort, because the legacy message is exactly the non-idempotent path being replaced.

The guest agent answers from its receipt table and delivers under one lock. Keyed by `operation_id` and comparing the full binding (digest and source generation): a retry that matches a recorded receipt is acknowledged as success without any further handoff signal — including after a new reader has registered — while the same `operation_id` with a different binding is always a hard error. With no reader registered the outcome is dropped, never queued for a future reader, and the receipt is still recorded, so a delayed retry cannot wake a later reader. These receipt answers hold even after the sandbox's handoff is closed; an operation the agent never accepted is refused on a closed handoff instead of being silently acknowledged. The table holds at most 1024 receipts: when full, new operations are refused before any effect (no signal, no receipt), and recorded receipts are never evicted, because eviction would let a delayed duplicate of an evicted operation release a future reader. Each request is answered with the normal OK/error response on its own connection, so the host retries the identical request after a lost reply. Receipts live only for the guest agent process: they survive a host daemon restart while the same guest agent keeps running, but a guest restart or host power loss clears them, and durability against those is not claimed. The receipt-table bound (1024 entries plus the bounded field shapes) is the guest-side memory contract for this mechanism.

The runtime's explicit abort path sends `MessageCheckpointAbort` with the operation's full recorded binding (operation ID, request digest, source generation) and has no legacy fallback: a guest agent that rejects the message leaves the abort failed with its `aborting` evidence retained and retryable, never degraded to the non-idempotent legacy error outcome. The host side re-sends the identical request after a lost reply. Still pending: the guest/initrd carrying the new agent into the deployed Firecracker bundle, and the real-VM lost-reply and abort acceptance — until those land, this wiring is verified only against the protocol fakes, and the public service/CLI abort surface remains unexposed.

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

`ErrStartCleanupPending` is a runtime-layer sentinel, and the management plane now acts on it. The server's Start flow never converts or unwraps the runtime error before its retention decision has been made — `startSandboxRuntime` returns the raw chain (no `CleanSandboxRoot`, no gRPC mapping) plus a flag reporting whether the runtime call was reached at all, the rollback logic in `Start` tests `errors.Is(err, ErrStartCleanupPending)` in-process, and only the final RPC response converts the error. A failed start whose error carries the sentinel is not signalled again: the sandbox ID, network/cgroup leases, DNAT and ACL state, committed filesystem ownership, and the sandbox's runtime state and files all stay in place, and the durable start-intent record (next section) moves to its retained phase so a restart and reconciliation tooling can see why the ID is blocked. A failed start whose error does not carry the sentinel may only be unwound when the runtime explicitly declares the failed-start cleanup contract (`runtime.StartFailureCleanupProver`, implemented by Firecracker): such a runtime's plain error already confirms the exit of everything it spawned and the cleanup of its own state. The proof is scoped to what THIS call created: it authorizes releasing this start's own references (sandbox files, leases, filesystem ownership) but never a whole-directory wipe of `containers/<id>`, which may still hold a pre-existing same-ID incarnation's state — only a generation-checked strict delete that retires exactly this incarnation may remove the directory. Any other runtime's failure proves nothing — the sentinel's absence is not evidence, and a legacy `Delete`'s idempotent nil or NotFound is not an exit proof — so those starts are retained for reconciliation. Failures that never reached the runtime call (capability checks, cgroup preparation, the intent write itself) cannot have left a process behind and roll back normally. A start whose runtime already reported success and then failed a later step (DNAT setup, metadata persistence) may only be unwound through the generation-checked `DeleteStrict` proof against the daemon-assigned generation; runtimes without that capability force retention rather than an unproven release. Any later release step that itself fails (network deactivation, ACL removal, filesystem release, resource release, or durably clearing the intent record) also retains: the record keeps a reconciliation anchor and the ID stays out of the pool. Retention is not an atomic all-or-nothing snapshot of unreleased state: the rollback releases step by step, so a failure at step N keeps everything from step N onward while steps already completed before it stay released — there is no undo and no durable per-step cleanup progress journal, which is exactly why a later reconciliation pass must re-derive what is actually held (from the durable lease records and the intent record) instead of replaying a cleanup checklist.

One management-plane resource boundary is closed as a prerequisite slice of that plan: pooled cgroup leases are durable before handout. The cgroup manager persists its active set to the local store before `Allocate` returns a lease on both the cached and the freshly created path, the snapshot and the write of that store are serialized against the periodic flush so a background snapshot taken before a handout can never overwrite the confirmed lease afterwards, and shutdown closes `stopCh` before anything else so allocations waiting on a queued or delayed creation cancel exactly as they did before durable handoffs existed, then drains the short confirmation sections (stopped re-check, active-set mark, synchronous store, rollback — never the creation wait itself) so its final store is ordered after every already-confirmed in-flight handoff and cannot be overtaken by a later one, while handouts that had not confirmed fail closed without writing. The motivation is restart recovery: an existing cgroup that is absent from the persisted active set is recovered as idle, and recovering an idle cgroup drains it by killing whatever runs inside it, so a lease that reached the store only on the next periodic tick turned any daemon restart in that window into a kill of the sandbox that already started in the cgroup. A store failure now fails the allocation instead: the un-handed-out cgroup returns to the idle cache when there is room (nothing was started in it and `Allocate` itself applies no controls — `Prepare` runs only after the caller holds a confirmed lease) or is destroyed synchronously, and the pool reservation is released only after the physical removal succeeds so a concurrent allocation can never consume capacity that a failed delete must give back; a failed destroy keeps the lease active, quarantined inside the reservation it already holds — the pool ceiling is never exceeded — and never re-leased or handed through the GC queue. Residual gaps remain and are deliberate: a lease recycled close to a crash can still be recovered as active until the next flush (the safe direction — the cgroup is kept, not killed, but it leaks with no owner), a quarantined cgroup likewise survives restart as an unowned active lease, and this boundary covers only the resource lease itself — the sandbox-bundle reconciliation, retained-state protection, and ownership records of plan 0049 are still open, so a durable cgroup lease does not by itself make a failed or interrupted start recoverable.

Reconciliation of a retained sandbox must stay identity-based against the runtime's own record — a generation-matched strict retirement where that state still exists. A recorded process that is not a verified owned incarnation is never authorization to signal it, and the public `DeleteIfGeneration` additionally depends on server metadata that a failed start may never have written or that the server rollback above may already have erased, so it is not guaranteed to work for a retained sandbox; a foreign recorded process is an operator incident requiring out-of-band verification, not a documented self-service cleanup path.

On failure, sandboxd returns an error and does not independently stop, resume, or delete the source. Before the runtime checkpoint call is entered, sandboxd cleans the output allocated for the attempt: it removes a newly created leaf, or preserves a caller-provided leaf while clearing its contents. After entry, sandboxd preserves the output directory on every error, timeout, or cancellation and reports the outcome as unknown. The runtime may have sealed an artifact and stopped the source before a later step, such as UFFD exit confirmation, failed. This retention policy applies to the service layer; it does not undo partial-file cleanup performed inside the runtime. Retained files are not proof of a successful checkpoint. The caller must reconcile the operation, source identity, and artifact integrity before restoring or issuing another checkpoint; merely choosing a different output directory does not resolve the original operation.

## Start intents (durable in-flight start journal)

Every `Start` — fresh or restore — writes one durable start-intent record before the runtime is invoked. The journal lives in `<root>/scheduler-start-intents/<sandbox-id>.json`, deliberately outside the `containers/` tree that metadata recovery recycles and rollback cleans, so no sandbox-directory cleanup can destroy a record as a side effect. A record is written atomically (temporary file, `fsync`, `rename`, directory `fsync`, plus a sync of the daemon root so the journal directory entry itself is durable) and carries a strict schema: version, daemon-generated sandbox ID, resource generation, runtime name, a monotonic phase (`prepared`, then `retained`), the allocated resource lease identities (cgroup, interface), the committed filesystem ownership (rootfs descriptor plus S3/OCI references), timestamps, and — in the retained phase — the reason the start could not be unwound. Reads reject unknown fields, trailing content, size or identity mismatches, and invalid values; a corrupt or self-inconsistent record fails daemon startup explicitly instead of being silently dropped.

The write ordering is the contract: `fsMgr.Commit` first (the prepared filesystem references become durable in the fsManager's own store), then the intent record, then the runtime invocation. From the record's durable write onward the start owns the ID, the leases, and the filesystem references, and an unknown outcome keeps all of them. Success has an explicit durable linearization point: after the runtime, DNAT, and sandbox metadata persistence have ALL succeeded, the Start flow rewrites the record to the `committed` phase and then removes it. Recovery may take a record over only in the `committed` phase and only against fully matching identity — the metadata's ID, runtime handler, and daemon-assigned generation (the reserved `akernel.scheduler/resource-generation` label inside `meta.pb`) must all equal the record's. `prepared` and `retained` records are never promoted by metadata presence, however well it matches: a crash between metadata persistence and the committed write is indistinguishable on disk from a partially failed StoreMetadata, and a retained record was retained precisely because a later step failed, so the protection stays until reconciliation in both cases. A `committed` record contradicted by missing, unreadable, or mismatched metadata fails daemon startup explicitly rather than being resolved by guessing; a corrupt record fails startup explicitly as well. A committed write that itself fails never rolls the already-running sandbox back or auto-revokes it, and the `Start` RPC reports it as an explicit unknown completion rather than success: the sandbox keeps running with its monitor, the ID, resources, committed filesystem ownership, and the original prepared record all stay protected under the pending-intent rules until reconciliation. The unknown-completion report has two distinct audiences. A direct in-process caller of the service method receives both values of the `(response, error)` pair, and that response object carries the sandbox ID and `resource_generation`. A remote gRPC caller does not: when the error is non-nil, the gRPC wire protocol transmits only the error status — the response message, whatever the server-side method returned, is not serialized or delivered. Remote callers must therefore treat the error text (and the durable intent record the next recovery sees) as the only unknown-outcome evidence; the ID and generation on a failed `Start` are not available over the wire and no additional RPC protocol was added to change that. A committed record whose later journal removal fails is a different case and is NOT a failure — the handover already linearized, recovery takes the leftover committed record over against matching metadata, and the start reports success. A rollback that proves the runtime gone and releases everything removes the record durably before the ID returns to the pool; a record whose removal fails keeps the ID blocked, and after a restart it reappears as a pending intent (or, for a committed record, is taken over). An intent write whose outcome is unknown (the atomic write failed) never triggers an unsafe rollback: only a confirmed record removal lets the pre-runtime path release, otherwise the start is retained.

Restart recovery runs before anything that could destroy retained state: the journal is loaded before any resource module is constructed (a corrupt or contradictory record fails startup before construction rollbacks could tear existing state down), before the sandbox manager reads `containers/` (so a pending intent's directory without metadata is preserved instead of being moved to the recycle bin that housekeeping empties), and before the interface pool is constructed — an ephemeral (runc) lease whose sandbox metadata is missing is exactly the state a retained start leaves, so recovery keeps the pending intent's device, namespace, and durable lease instead of running the missing-metadata destruction. Pending IDs are reserved against the admission ceiling (exhausting it is a hard startup failure, and the same ID can never start a second incarnation while its retained one is unreconciled); an already-reserved ID — the ambiguous prepared-plus-metadata crash state, where the recovered sandbox holds the reservation — blocks reuse exactly as well and is not an error. `fsMgr.Restore` treats a pending intent's ID as existing so its committed filesystem references are re-acquired instead of being reclaimed as an orphan's. The pod-identity reset (`resetStateIfPodChanged`) is refused outright while any record file exists — corrupt content included, since the filename alone identifies the protected ID: a changed or missing stamp is not evidence that the previous pod's runtimes exited, so the wipe cannot clear retained protections or the state they reference; an empty journal keeps the historical reset behavior. Pending intents are never surfaced as Running sandboxes — they have no monitor of their own and do not appear in `List` beyond what stored metadata recovery itself does.

No public entry bypasses the protection: `Start` under a pending ID, legacy `Delete`, `DeleteIfGeneration`, and `Checkpoint` all refuse with a precondition error naming the pending intent, and the legacy delete refusal happens before its DNAT cleanup, which would otherwise mutate the retained sandbox's rules.

Graceful shutdown preserves a retained start's ownership layer by layer. The filesystem layer keeps the preserved IDs' state in the persisted store, their rootfs references, and their S3/OCI mounts. The interface layer neither destroys the preserved leased devices nor drops them from the persisted active set, and it also keeps the infrastructure those leases depend on — the SNAT rules and the owned bridge survive while any lease is preserved; an empty preserve set runs the original cleanup. The image layer stops the distillfs worker (whose mount records persist and reconcile on the next start) but no longer unmounts OCI images a pending intent still references. The volume layer skips the bounded-filestore teardown entirely while any intent is pending — the normal cleanup deletes the backing image that still holds pending writable layers — and the next daemon start adopts the kept mount. Cgroup shutdown already persists active leases. The ACL close keeps TC filters and pinned maps while any entry remains (its existing fail-closed design), which covers a retained start whose ACL entry was registered.

Restart recovery closes the same gap on the ACL side. Before the ACL manager reconciles orphans, recovery derives a second ownership set from the pending intents themselves: each retained record's durable network resource lease (interface name, IP, and recorded ifindex) becomes a protected owner. Protected owners are verified against the persisted ACL entry — the entry must exist, its IP, host veth, and ifindex must equal the recorded lease, and the live endpoint found by name must still carry that ifindex — and any contradiction (a missing entry from an ACL config switch or a lost store, a durable cleanup intent already recorded on the entry, mismatched identity, a foreign entry or another sandbox's active binding claiming the same IP, host veth, or ifindex) fails daemon startup explicitly before any destructive call: no orphan cleanup, rule deletion, or policy-map mutation runs on unproven ownership. A cleanup intent that was already durable when the daemon died is uncertainty, not a proof in either direction — how much kernel state survives the partial deletion is unknowable from the persisted record — so it refuses the protection and defers to reconciliation rather than guessing the entry alive or cleaned. A verified protected entry is retained exactly as the kernel still enforces it: not re-applied, its policy generation untouched, and excluded from the orphan pass for as long as the intent is pending — retention is ownership protection, it does not convert the unknown start into a normal running sandbox. When a pending intent's ID also holds recovered sandbox metadata (the ambiguous crash state between metadata persistence and the committed handover), the metadata-derived active binding and the intent's recorded lease must describe the very same IP and host endpoint — agreement keeps the protected semantics, disagreement fails startup. Retained runc starts own no ACL state (`Start` refuses a policy for runc) and are skipped. The record's resource generation and the ACL entry's policy generation are different namespaces and are never compared or conflated. This protection is verified by model tests over the real binding reconstruction and the real `Restore` implementation with injected endpoint lookups; the kernel dataplane behavior (TC filters and pinned maps surviving a restart with a protected entry, then being cleaned only after reconciliation) is additionally covered by the tagged network ACL integration tests, which must run in the isolated dataplane gate before any claim that real-network protection is validated.

Scope and known boundaries of this mechanism. It provides retention and restart-safe isolation, not automatic reclamation: reconciling a retained start (proving the runtime exit by generation, releasing the leases and filesystem references, and recording completion) is a deliberate follow-up, and until it exists a retained intent blocks its ID indefinitely — that is the safe direction, but it is not the end state of plan 0049. Retried cleanup must carry a resource-lease identity; a path alone cannot authorize release, because without a lease identity a persistent cleanup retry could free an object a newer start already reused. Resource and filesystem allocations that crashed before the intent write are bounded only by the resource managers' own durable leases (the cgroup active set, the network interface store) — the intent record lists exactly what one preparation secured and does not impersonate a complete resource transaction. The runtime-side shutdown of a retained Firecracker instance is untouched: the daemon's shutdown does not signal it, and its exit is observed by whatever reconciles the retained record.

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

## Start operations (persistent operation identity)

`StartWithOperation` and `GetStartOperation` add an explicit, persistent operation identity on top of the unchanged `Start` flow. They exist so a client that lost the reply, restarted, or found the target deleted can query the original creation fact and safely retry, instead of blindly re-creating the sandbox. The records are node-local idempotency state: this is per-node operation idempotency, NOT a cross-node writer lease or fencing token, and the cross-node coordinator (cn-migrate) does not consume it yet. Old servers that predate the RPCs return `Unimplemented`; callers must fail hard instead of falling back to plain `Start`.

`StartWithOperationRequest` wraps the legacy `StartRequest` unchanged and adds: a stable caller-chosen `operation_id` (1–128 characters, `[A-Za-z0-9][A-Za-z0-9._-]*`, path-free), an explicit required `sandbox_id` that must agree with `start.sandbox_id` when set, and `restore_artifacts` — required exactly when `start.checkpoint_info` is set, carrying the checkpoint directory and the caller-pinned `expected_root_digest`. `GetStartOperation` reads only the operation journal: it never creates anything and never re-executes a past operation.

The durable journal lives in `<root>/scheduler-start-operations/<operation-id>.json` with the same atomic write discipline as the intent journal (temp file, fsync, rename, directory fsync, daemon-root sync), a strict schema (version, operation ID, sandbox ID, daemon-assigned generation, runtime, request digest, phase, restore binding, timestamps, message), and fail-closed loads: unknown fields, trailing content, size/identity mismatches, and invalid phases all fail daemon startup. Tombstones are never expired automatically. They are also deliberately KEPT by the pod-identity reset: a historical start fact does not require the sandbox to exist, and deleting it would let an old operation ID be re-admitted after the reset.

Phases and their meaning. `admitted` is persisted before any start side effect, carrying the request digest and the restore binding; `succeeded` is the durable success fact; `failed` means a fully proven rollback; `unknown` means the outcome could not be proven (crash with the work in flight, a terminal write that failed, a retained start). Terminal phases are published in memory only after their durable write succeeds — an unpersisted success or failure fact is never observable through `GetStartOperation`. The one exception is `unknown`, which claims nothing and may lead the durable state briefly. On restart, every still-`admitted` record is durably rewritten to `unknown`: its executor is gone, metadata presence is never a success proof, and the ID is spent — re-execution is forbidden. A restart resolves success only through the committed-intent evidence: when recovery takes over a committed start-intent record against fully matching sandbox metadata, it first durably promotes the matching operation record (same sandbox ID and generation) to `succeeded` and only then removes the intent record; a promotion write failure keeps the committed intent record as proof and fails startup explicitly.

Replay semantics. Admission is keyed by operation ID under one lock: the same request (deterministic protobuf digest over the `StartRequest`, with only the trace ID and the reserved generation label excluded — any other field difference refuses reuse) either joins the running execution or is answered from the recorded terminal outcome; the runtime is invoked exactly once per operation, forever, including after the sandbox is deleted. A successful replay returns the original `resource_generation` and states that the fact is historical, not a liveness claim. Whether a NEW operation may create under the same sandbox ID is decided by the current physical ID and protection state, exactly as for plain `Start`. The daemon assigns the generation at admission and reuses it across the execution; a caller label can never choose it. A reply lost mid-flight is covered because the executor runs detached from the caller's context (`context.WithoutCancel` with an explicit deadline) inside the RPC handler goroutine — caller cancellation ends only the waiting of joined replays. Queries and replays of finished operations never re-read the checkpoint directory, so deleting the artifacts after success does not lose the creation fact.

Restore artifact identity. A path is not an artifact identity. The content root is derived by ONE shared algorithm — `pkg/checkpointroot`, free of runtime dependencies — that the server's admission and the runtime's restore boundary both call, so the two can never drift into hashing different views of one directory (scheme `v2:manifest+sidecar-roots`): the sha-256 of the sealed `manifest.json` bytes, each chunk sidecar's full logical geometry — file, file size, normalized digest mode, chunk bytes, chunk count, file digest, AND the independent sha-256 root over its entries — folded in for every sidecar present under its real seal name (the plain `chunks.json` memory sidecar, `overlay.ext4.chunks.json`, `pages.img.chunks.json` — generally `chunks.json` or `<artifact>.chunks.json`), and the size of uncovered regular files. The independent entries root is what makes a different read geometry (a changed chunk grid or offset layout) or a changed entry a different checkpoint even when the file digest still agrees — in chunks mode because the grid is bound directly, and in whole-file/sha256 mode because the file digest binds nothing about the entries. Pack references are deliberately outside the logical root: they name the physical placement of packed objects in an object store (identity, offset, length, object size), and relocating a pack does not change which bytes the checkpoint logically is; the local sidecar format is version 1 and never carries packs — the shared loader keeps rejecting a version-1 sidecar that tries, and keeps validating the packed transport format wherever it appears. Sidecar validation is strict and supports both real seal shapes: a chunks-mode sidecar must carry a root that binds its entries, and a whole-file-mode sidecar (`""`/`sha256`, the pre-chunks default) must agree with the manifest digest for the same artifact; structural validation (version, digest shapes, entry count, offset grid, tail size, artifact name, on-disk size) comes from the shared loader. Every metadata read is bounded BEFORE any byte is buffered: the manifest through the shared `checkpointroot.ReadManifestBounded` (an `Lstat` refuses a non-regular entry or a size over `checkpointroot.MaxManifestBytes`, 1 MiB, and the read itself is limit-bounded so growth between the stat and the read cannot force an unbounded buffer), and each sidecar through the loader's stat-bounded read (32 MiB). The Firecracker restore reads its manifest through the same shared bounded reader, and the bytes it parses are exactly the bytes its identity check recomputes the root from — one view, never two reads. The coverage closure is strict: the manifest must exist, decode, and digest at least one artifact; every regular file in the directory must be verifiable (digested by the manifest, or the Firecracker overlay with its chunk sidecar present, or a sidecar/materialization marker itself); symlinks and non-regular entries are rejected; a directory without a seal, an artifact with no verifiable root, or an overlay without its sidecar is an explicit admission error — a path-only fingerprint is never recorded as a restore identity. The caller pins `expected_root_digest` and the admission rejects a mismatch, so swapped content under the same path cannot ride an operation ID. Lazy restore is untouched: cold guest memory is never hashed for the fingerprint, and it stays UFFD-verified chunk-by-chunk at consumption.

Runtime consumption boundary. The admission-bound root reaches the runtime through `StartConfig.ExpectedCheckpointRoot`, set only by an admitted start operation — the legacy `Start` leaves it empty and no runtime enforces anything for it. A runtime that accepts identified restores must implement the `CheckpointRootVerifier` capability; runtimes without it are refused at admission with `Unimplemented` instead of silently ignoring the binding (currently only Firecracker implements it, so identified runsc restores are refused until runsc wires the check). The Firecracker `Restore` entry recomputes the content root with the shared package from the exact manifest bytes it just opened and is about to consume — never a second independent read — and refuses a mismatch (a wrong root, or a fully self-consistent replacement artifact under the same path) BEFORE any sandbox resource, storage directory, or VMM action. The v1 archive layout carries no sealed manifest and says so explicitly. The overlay's actual bytes are additionally verified against its sidecar at the same boundary; this binds the request to the artifact, while the directory's continued immutability through the restore and the VM's lifetime remains the caller-owned immutable-artifact contract — it is not a defense against a writer mutating the directory concurrently.

Success ordering with the intent journal. For an identified start, the operation's success fact is written between the intent journal's committed write and its record removal: while that write fails, the removal is refused, so no crash window exists in which the original success fact is lost — it is recoverable from the operation record or from the committed-intent takeover, whichever the crash leaves behind. A failed fact is recorded before the intent record is cleared after a confirmed rollback.

Shutdown lifecycle. `Shutdown` first closes admission atomically, cancels every in-flight execution's context to request convergence, and then BLOCKS until each executor has actually returned before enumerating sandboxes and tearing filesystem/network/runtime managers down. The wait is unbounded on purpose: a context deadline proves nothing about goroutine convergence, and tearing down resources an executor may still be using would break the rollback and retention invariants. An execution that ignores cancellation therefore holds shutdown until it exits; that is the contract, not an accident.

Not claimed by this mechanism (open gaps): the binding does not re-hash artifact bytes against the seal at admission — artifact content is verified at the runtime consumption boundary (manifest digests, the overlay's sidecar contents, and UFFD's chunk-by-chunk memory verification), not twice; the publish INDEX chain is not part of the binding and remains deferred to the reviewed cross-node design; identified restores are Firecracker-only until runsc implements the root-verification capability; cn-migrate and the cross-node coordinator do not yet record or consume target operation IDs; reconciliation tooling for `unknown` operations does not exist yet — an unknown operation blocks its ID until then.

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
- Launch synchronization: sandboxd waits up to five seconds for the handler's listening socket to appear and never dials it, because the handler treats its first and only connection as Firecracker's handshake. A single `cmd.Wait` reaps the process and reports completion through a channel, so a handler that dies before publishing its socket — whether it exits normally or is killed by a signal — fails the restore promptly with an `exited early` error instead of stalling until the readiness deadline; the loop never reads the process state concurrently with that `Wait`. This contract covers launch only: the handler's overall exit path and fault fencing remain open work.

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

The artifact set's small files — `manifest.json`, `chunks.json`, `vmstate`, and the overlay sidecar when the chunked path is taken — ship as one bundle object (`artifacts/<id>/BUNDLE`): each file is prefixed with an 8-byte big-endian length, and the INDEX records the bundle's whole-object sha256, size, and per-part spans alongside the unchanged per-file digests. Publication lands one PUT instead of one per file; materialization lands one GET whose parts are each digest-checked against the INDEX before being staged. The ID-named always-upload semantics that protect against checkpoint-ID reuse carry over to the bundle object. Artifacts published before bundles carry per-file objects and no INDEX bundle field; materialization and pack-baseline loads fall back to per-file fetches for them, while bundle-aware baseline loads verify the whole bundle digest and each part's span before trusting any byte.

### Compressed standalone chunk transport

`cn-publish -compress-chunks` (library `Options.CompressChunks`; requires unpacked publication, so `-pack-mib` combinations are rejected before any state or object changes) uploads each standalone memory chunk object as a zstd stream under the content key with a `.z` suffix (`<aa>/<sha256>.z`), and the INDEX's sidecar view carries a top-level `compression: "zstd"` marker. The sealed `chunks.json` is never rewritten; only the publisher-built transport sidecar (delivered through the artifact INDEX/bundle) learns the marker. Every digest still names the UNCOMPRESSED bytes: readers decode the stream and verify the decoded content against the digest exactly as before, so addressing, verification, and dedup semantics are unchanged. Decompression is bounded — a stream must decode to exactly the chunk's recorded length, the compressed body is size-capped at the zstd incompressibility bound, and short, oversized, or corrupt streams fail without serving any byte. A reader that finds no compressed object falls back to the plain `<aa>/<sha256>` object, so chunks shared with pre-compression generations (found by the publisher's plain-object probe and reused as-is) keep restoring; a present-but-corrupt compressed object fails loudly with no fallback. The persistent local chunk cache stores decoded plaintext, so warm hits never decompress twice. Packs are range-readable and are never compressed by this option; overlay chunk objects and artifact-set files are unchanged. The option is writer-side opt-in; readers detect it purely from the sidecar marker, so mixed artifacts in one store are fine, but a pre-marker reader cannot restore a compressed artifact — deploy readers before enabling the flag.

### Bucket sweep (cn-gcsweep)

Content-addressed chunk objects are shared across artifacts and generations, so they cannot expire by age. `cn-gcsweep -store URL` reference-counts instead: every surviving artifact's INDEX and the sidecars it names (bundle or per-file) contribute the exact live key set — plain and `.z` chunk objects, memory packs of both identities, overlay chunks — and only objects referenced by no surviving artifact become deletion candidates, additionally guarded by `-min-age` (default 24h) so chunks of an in-flight publication, whose objects land before their INDEX, are never caught mid-publish. Artifact sets (`artifacts/<id>/*`) are ID-named and exclusive, so they may age out wholesale: `-max-artifact-age` drops sets whose INDEX is older and `-drop ID,ID` names sets explicitly; a chunk dies only when its last referencing artifact is gone. The tool is fail-closed — one unfetchable or undecodable INDEX or sidecar aborts every deletion because the live set cannot be proven — and objects with unrecognized key shapes are never touched. Without `-delete` the run only reports. Sweep runs are operational tooling (cron or manual), not wired into publishers; concurrent sweeps are safe because deletions are idempotent and the reference scan is read-only, but a sweep racing a publisher relies on the min-age guard.

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
