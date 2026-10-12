# Checkpoint and restore

镜像管理模块关闭期间拒绝新的挂载、卸载、查询和元数据解析请求，已准入请求及后台维护退出前继续持有原根目录独占锁；关闭超时不能交出锁或声称物理清理完成，见 [镜像管理器所有权契约](scheduler-image-mount-release.md)。这只协调本地镜像管理器的生命周期，不证明检查点源执行已经退役，不改变恢复预算准入或未绑定操作的未知结果语义。

已经持久请求清理、仍在取得中且没有底层代际的文件系统步骤，可以显式请求原挂载生产者保存未分配屏障，并通过独立查询确认 `not_allocated`，随后保存该步骤释放完成；不取得引用或调用卸载。原生产者仍在工作、已有准备、旧协议、库存或持久记录未知时继续保留原归属。完成记录跨管理器与数据库重开后拒绝迟到分配，见 [文件系统归属](scheduler-filesystem-ownership.md) 和 [原挂载完成契约](scheduler-image-mount-release.md)。这一局部证明不授权检查点源沙箱预算归还或新的恢复执行；完整沙箱退役与独立 Restore 的持久操作整合仍待完成。

sandboxd supports checkpointing a running sandbox into a caller-owned
directory and starting a new sandbox from that checkpoint.

## Design

调度器的普通创建及通过 `checkpoint_info` 发起的创建可以使用 [持久创建操作](scheduler-start-operations.md) 的 `StartOperation`。它复用同一物理创建流程，并单独记录创建身份与结果；独立 `Restore` 的持久操作整合仍待完成。

共享 Start 或 Restore 从第一次尝试发布物理元数据起，失败保留原身份、预留 ID、现有文件和已记录资源。运行时调用错误、运行时成功后提交或发布失败，以及初始元数据 rename 后目录同步失败，都不授权内联删除运行时或释放租约。磁盘已提交的记录保留原状态，供原创建结果查询核对。部分资源准备失败也返回并登记已知租约，成功准备的文件系统来源继续保留。cgroup 条件租约和池化网络的独立租用身份保护旧清理重试，见 [资源租约契约](scheduler-resource-leases.md)。意图对账使用物理锁、完整磁盘元数据和运行时清理后的回读；确认运行时不存在后先断开已知网络租约并移除 ACL，错误会阻止资源回收。文件系统准备／提交错误保留调用前的来源登记，卸载错误不删除引用，并持久记录每项释放；schema 4 核验原来源、原底层挂载代际及整个日志的摘要，损坏或不明确的旧格式在任何重建前拒绝，见 [文件系统归属](scheduler-filesystem-ownership.md)。一般分配窗口、原挂载物理身份与卸载回读、其他资源的逐步清理、完成沙箱退役证明和真实故障验收仍待完成，不能依据资源池完成记录或意图清理日志归还调度器预算。

镜像挂载路由读写、daemon 清理及 OCI／Nydus／S3 卸载后的挂载回读错误会保留原登记，并阻止未完成来源的新挂载复用，见 [镜像挂载释放边界](scheduler-image-mount-release.md)。Nydus／S3 底层另持久保存启动意图、原进程与内核挂载身份及释放阶段，迟到事实不取消清理，完成发布失败不会回放成功。镜像入口与上层日志保存并传递原底层代际，已知绑定恢复只查询原记录；OCI 接口的 Nydus 路由完成历史可在重开及来源替换后回放。schema 5 每个原步骤的派发前挂载操作和独立查询已接通，共享缓存按原物理代际保存引用；确认原完成后可以恢复旧清理引用与活动替代代际，旧清理不减少新引用。未知取得不按 URL 重新挂载，释放待定继续阻止来源准入。普通 OCI 原身份、部分启动对账、旧登记迁移、有界调用和其他完成历史仍未完成；完整沙箱清理和预算结算须独立完成。

Nydus／S3 释放先保存原清理意图，并与最终进程启动共用状态锁，防止后台初始化在清理之后迟到执行。实际 `Start` 失败的未派发事实在释放失败和重开后保留；缺少出生确认仍为未知。原 `not_started` 通过镜像 API 返回 `release_pending`，只用于已经授权的原清理恢复；待清理或已释放的回复不会写挂载成功确认或激活来源引用。这些事实不表示源沙箱已经完整退役，也不授权预算归还或恢复新的执行；未绑定意图、独立部分启动对账与完整物理故障仍须单独验收。

新 Nydus／S3 启动身份保存 `birth_protocol=1` 和原 daemon 目录的设备号及 inode。观测到原进程或原内核挂载之后，先发布独立不可替换的身份文件，再提交主元数据；主元数据发布失败且旧有效快照存续时，显式原代际清理可以读取这些身份，先保存 releasing 屏障，再持久补交原身份后继续清理。读取不采用当前 PID 或当前挂载补造归属，不启动程序，不将清理改回运行。旧协议、缺失或损坏记录、目录替换、来源改变、PID 复用及挂载替换继续保持未知。它只覆盖首次身份已经观测并保存之后的主元数据失败窗口；成功 Start 到首次独立身份保存之间仍需要启动确认协议，不证明完整沙箱退役或授权预算归还。具体记录、兼容及持久边界见 [镜像挂载释放契约](scheduler-image-mount-release.md#独立原进程及挂载身份记录)。

The API has three operations:

1. `SandboxService.Checkpoint` checkpoints an existing sandbox.
2. The existing `Start` RPC restores a sandbox when `checkpoint_info` is set.
   This remains the compatibility restore entry.
3. `SandboxService.Restore` (`RestoreRequest` -> `StartResponse`) is the
   explicit managed-restore entry used by the scheduler line; it accepts a
   prepared checkpoint image and drives the same restore pipeline.

Restore is a form of sandbox creation: both entries allocate the target
sandbox's filesystem, network, cgroup, and other resources through the
shared `createSandbox` primitives. Beyond that shared creation core, the
explicit managed `Restore` entry adds checkpoint-artifact identity
verification, idempotent retry and ownership handling, and restoration-
result verification before a success is reported.

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

能力通告和 `Start` 的恢复准入同时识别 `ManagedCheckpointHandler` 与 `CheckpointHandler`。runsc 通过前者保存和恢复配对的进程状态与可写文件系统；不能因为它未实现后者，就把已注册的 runsc 标为不支持检查点。这里只说明守护进程的能力选择，实际平台暂停恢复仍须单独验收。

具有完整准备操作关联的新文件系统启动已接入直接子进程确认候选：派发前保存清单与摘要，继承原所有权句柄，严格读取生产端原事实并持久补交主元数据。清理先保存 releasing，持久补交原进程身份后才停止原初始化，并确认退出后继续原挂载清理。旧协议不升级，缺失第一条事实仍保持未知；本地两端非特权通信通过不等于真实挂载、完整预算结算或物理验收。见 [直接子进程启动契约](scheduler-image-mount-release.md#调度器管理的直接子进程启动确认候选)。

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

runsc restores are split-filesystem restores whenever Create donated
filesystem-restore files through `--fs-restore-image-path`. The
`containerManager.Restore` control RPC payload must then carry
`split_fsrestore: true`: runsc rejects a Restore whose donated-files fact and
this flag disagree, and both are derived from the same StartArgs so they
cannot drift. Restores without donated filesystem files send
`split_fsrestore: false` explicitly.

The matching checkpoint side is ONE combined `runsc checkpoint --fs-checkpoint-paths=/` invocation: runsc writes the filesystem artifact under `<image>/fs` (the exact layout restore consumes) and EXCLUDES the filesystem-checkpointed private memory files from the sentry state. Taking the two artifacts through separate subcommands duplicates the root private memory file into both inventories, and the restore-side duplicate guard correctly rejects that pair. The filesystem artifact itself is never deleted or bypassed; the restore-side consistency checks stay authoritative.

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

## agent-dx 调度器协议迁移

`scheduler/agent-dx-protocol-20261010` 分支采用上游 sandboxd 提交 `31d0749a85e269396cfc1c469c948345f9610906` 的公共 protobuf 字段，与 agent-dx 固定协议一致。StartResponse 的 `sandbox_ip`、`resource_generation`、调度器端口映射分别位于 4、5、6。CheckpointRequest 保留上游 1–6 号字段；调度器检查点身份、文件系统快照开关、trace 身份及内部 timeout 别名分别占用 7–10。该分支有意停止兼容旧 YuanRong 调度器的字段编号，不得部署到旧环境。

generation 条件删除及检查点 RPC、持久资源 revision、operation ID、deadline 和结果未知语义继续作为独立扩展保留。CheckpointResponse 的附加产物事实可由上游客户端忽略。`api/runtime/v1/testdata/` 中从固定上游原件独立生成的 descriptor 检查每个公共消息字段及 RPC。协议匹配不等于运行时或重启验收通过。

镜像服务另提供挂载操作的派发前登记、进程启动前原代际绑定及独立结果查询，见 [镜像挂载操作契约](scheduler-image-mount-release.md)。该接口不改变 protobuf，也不证明整个源沙箱已经退役。文件系统管理器已接通 schema 5 每个原步骤的稳定操作身份、共享所有者登记和原结果查询，能够在上层确认缺失时读取原绑定，见 [文件系统归属契约](scheduler-filesystem-ownership.md)。新建 S3／Nydus 镜像的准备阶段先保存原操作、请求指纹、物理代际及私有目录计划，再完成上层绑定，随后分配工作目录。未绑定原意图可以只读查询该准备记录，显式重试只恢复原清理归属；准备过程没有发布物理启动意图时，按原目录出生身份清理。相关契约见 [镜像挂载操作契约](scheduler-image-mount-release.md)。旧未绑定意图、明确未分配的持久结算、完整部分启动出生对账、完成历史、完整沙箱清理、独立 Restore 和节点最终预算结算仍未完成，不能据局部挂载确认宣称恢复故障已验收。

## 条件退役的持久进度候选

带有明确资源代际的条件删除先保存原元数据、原资源租约、原沙箱目录及其父目录的设备号和 inode，再记录运行时、网络断开、文件系统、ACL、设备、DNAT、资源归还及原目录移除的完成顺序。进度记录位于独立的 `scheduler-retirement-progress`，不能随沙箱目录一起删除。只有所有资源步骤完成且原目录移除意图已经持久保存，原目录随后确认不存在并完成父目录同步，才可以补写原代际完成回执。

当原目录已经删除但完成回执发布失败时，重试读取原持久进度；它不重复运行时删除，不借用同名替代沙箱，也不从空库存补造此前资源步骤。缺失、损坏、跳步、回退、原元数据或目录改变都保持未知。运行时 Delete 返回成功或 NotFound 后还需要新库存确认不存在，才进入后续资源清理。原 DNAT 清理使用持久事实并传播错误，不能仅打印警告后归还预算。

runsc 的新库存读取在 CLI 前后独立枚举本地原状态文件，并让 CLI 继承同一目录句柄；上游跳过损坏文件、列表遗漏、文件或目录改变均返回未知，不能用成功空列表推进退役。公开条件删除的受控用例确认这类未知会保留原意图和设备租约。该核对不证明尚未留下状态文件的初始化不存在，也不替代运行时原进程出生及条件删除；完整边界见 [运行时清单契约](scheduler-runtime-inventory.md)。

进度目录持有独立 flock，第二个所有者在接管前被拒绝；目录和锁替换在每次访问中核验。记录采用原目录句柄内的文件发布、文件 fsync、rename 和目录 fsync，权限 0600、单硬链接，最多 4 MiB，严格拒绝未知、重复和尾随字段。记录中的完成步骤是有序前缀，原快照及完成步骤不能改写或回退。目录移除前的完整原元数据也需重新核对，不能仅比较资源代际字符串。

失败创建的原 INTENT 元数据带有资源代际且原资源事实可读取时，也使用同一持久进度和完成回执。现有 DeleteIfGeneration 可以清理匹配原代际的未发布意图，复用已持有的物理锁，错误代际在任何清理前拒绝；不需要重启守护进程才能进入这条路径。清理前保存原快照及待完成回执，逐项确认后先保存目录移除意图，检查原目录删除结果并同步父目录，再发布完成回执。创建操作查询读取这份原代际回执才能返回 RETIRED。资源事实缺失、运行时库存不完整、DNAT 存在端口但缺少原网络身份、底层清理失败或进度发布失败都不能变成完成；旧无代际意图继续走原兼容路径，不生成新证明。

失败创建的目录移除不会提前删除内存中的原意图或释放其编号；完成回执持久保存后，只忘记仍然匹配完整原快照的意图。旧回执重放不能释放同名替代意图的编号。启动恢复通过原进度目录句柄枚举、严格校验内容及原身份对应的文件名，在原元数据目录已经消失时仍能发现原完成历史。只有完整资源步骤和原目录移除意图都已保存，才补交确认；缺失或不完整历史保持未知。目录及锁替换、损坏或改名的记录阻止恢复，不能借空库存补造原步骤。

本候选已接通失败创建的持久推进和回执消费，并补上元数据移除与完成回执之间的恢复窗口；全部底层资源的独立物理确认和节点最终预算结算仍未验收。设备分配日志现在绑定资源代际，条件释放后独立读取原完成；新退役进度以 `device_protocol=1` 要求该证明，原目录移除后的回执恢复也不能借用旧设备步骤或另一日志。CPU-only 请求同样在并行准备前保存空设备所有权，恢复创建共用这条创建路径；这不替代独立 Restore 的完整操作恢复。设备租约账本本地测试不证明 GPU 执行、驱动上下文、GPU 检查点或物理故障验收。运行时原出生身份、各资源步骤完成后进度尚未写入的独立核对、独立 Restore、有界调用、安全回收，以及匹配部署和物理故障矩阵仍需交付。第一条生产端进程事实缺失继续保持未知。旧无条件删除不使用新的完整历史证明；已发布完整退役回执保留既有重放语义。设备契约见 [资源代际和独立完成](scheduler-resource-leases.md#设备租约的资源代际与独立完成)。

## 调度器原运行时资源代际

创建与恢复的内部资源代际取自原物理元数据，受管理 OCI 注解在请求和设备字段之后写入。新创建显式要求配套 gVisor 的原生出生协议；开始运行或恢复前核对容器、sandbox、完整 bundle、代际及所需 Sentry／gofer 出生字段。未知创建或恢复不使用旧无条件删除回退。正常删除和失败创建对账保留只读代际拒绝条件，并通过原生条件删除接口传递原资源代际；只有只读验证的接口不能授权无条件删除。创建进程的独立物理专项不替代实际 Start、独立 Restore、部分启动、原资源清理及完整预算故障验收。完整契约见 [运行时资源代际的可信接线](scheduler-runtime-generation.md)。
# 调度器管理来源的状态提交

带资源代际的 runsc 恢复在原运行时生命周期锁内验证 created 状态、完整出生协议和原 bundle，控制连接及恢复完成后都重新核对原文件和目录。打开 TAP 和派发修改 RPC 前，取得生产端出生记录所指的原 Sentry 句柄，并以最多 5 秒的只读查询及每次响应读取的内核发送者凭据核验实际控制服务进程。缺失出生、原进程退出、发送者变化或连接不支持核验时拒绝，不借用监听 socket 初始化者的 PID 授权恢复。提交 running 状态使用原状态文件句柄，不通过同名路径采用替代执行；同步或身份回读失败仍是结果未知，不能授权退役或预算归还。锁等待最多 30 秒并尊重调用方期限，实际 Restore 调用仍使用调用方的 context；无期限修改调用、其他控制 RPC、辅助进程及独立恢复物理验收继续列为缺口。具体契约见 [资源代际的可信接线](scheduler-runtime-generation.md)。

新增独立原生恢复的永久专项使用生产配对检查点路径、完整运行时及固定根文件系统。它要求源执行先条件退役，新目标在公开 Restore 前核验新出生和实际响应发送者，并在恢复后检查进程内随机值、沙箱可写文件及检查点摘要。目标与源使用不同 sandbox ID／资源代际，原活动邻居贯穿测试；恢复的旧代际／误连邻居拒绝和最终独立句柄退出分别留证。显式启用须由目标 cgroup 外观察者完成两次进程核验，普通本地测试默认忽略，不能据此关闭物理恢复或节点预算缺口。完整说明见 [运行时资源代际的可信接线](scheduler-runtime-generation.md)。

配对根文件系统保存必须有可做检查点的根层。原只读根加独立 tmpfs 的物理尝试明确失败，未进入恢复。独立恢复专项使用受限可写根层，并同时检查该层文件及进程内存；保留原失败，不通过省略文件系统制品或降级成内存保存来改变验收范围。

本轮固定完整运行时的文件系统元数据是 `fscheckpoint.pb`，独立恢复专项按实际 protobuf 制品核验。原要求 `fscheckpoint.json` 的用例断言在物理保存成功后失败，原日志和实际文件摘要保留；修复断言后的恢复须另建物理用例。

创建入口携带 `CheckpointDir` 时也属于恢复，受管理执行必须在派发前回读原已准备 cgroup 的 CPU／内存上限、保存 phase 为 restore 的新出生资源，并初始化原代际的资源修订日志。未知数值、来源未绑定或保存失败时不调用恢复处理器，不能绕过独立恢复入口已有的资源核验。处理器返回失败时保留原错误链与公开 gRPC 状态，结果未知和清理未完成分类不能因错误转换而丢失；物理意图及已写的出生／修订记录继续保留。

永久用例 `TestRealNativeWorkloadRestoreLostReplyAndLivePeer` 在完整真实 Restore 请求及文件句柄送出后，关闭该连接的内核读端，使客户端收到 EOF，不能消费恢复成功回复。用例要求原 created 状态字节不变，再通过源退役后才触发的工作负载探针确认原内存和可写根文件是否已实际恢复，随后按新目标的原代际条件退役并核验独立句柄退出及活动邻居。私有派发后边界只由测试设置，正常连接没有启用开关。本专项须在指定隔离环境显式执行，默认忽略不代表物理通过；它不授权盲目重试、状态补写或节点预算归还，也不关闭全部恢复失败和持久对账边界。

创建和恢复的配套运行时可以分别持久记录 gofer 与 Sentry 的派发阶段。部分状态只允许进入原代际退役核验，不能取得控制或恢复权限；恢复仍要求完整原 Sentry 出生与发布阶段。派发中缺少出生、阶段矛盾或来源变更保持未知，不能把它改写成未创建或归还预算。新源码接线不等于新安装包、实际部分启动或节点结算通过，具体边界见 [运行时资源代际的可信接线](scheduler-runtime-generation.md)。

# 调度器管理的创建进程分组

原 cgroup 租约在交付前持久保存设备／inode、启动及观察环境，回收逐步复核后才结算；同名替代目录、旧缺少身份的活动记录和来源变化保留占用。该拒绝检查仍不是原目录句柄执行或完整关闭恢复，详见 [资源池代际所有权](scheduler-resource-leases.md)。

携带资源代际且配置了原 cgroup 的正常创建和独立恢复，均把原 CgroupPath 传给 runsc 适配器。适配器核对可信 OCI 路径，拒绝根目录、跳转、符号链接及未知目录类型；通过原 cgroup v2 目录句柄设置 clone3 的 CLONE_INTO_CGROUP，创建进程从出生开始属于原分组。内核不支持或操作失败时返回错误，不回退到普通启动或按后来发现的 PID 迁移。

受管理创建在任何输出文件修改、创建意图保存或运行时派发前拒绝 OCI 注解 `dev.gvisor.spec.cgroup-parent`。配套 gVisor 会把此注解作为独立父分组，不能仅凭 `linux.cgroupsPath` 相同证明运行时子进程属于原分组；空注解和相同路径也拒绝。未配置 cgroup 的受管理专项同样拒绝该注解；没有资源代际的旧输入保留原接口行为。此拒绝检查不替代完整子进程归属、原分组关闭、缺失出生恢复或节点预算验收。

配置了原分组的受管理创建显式要求运行时忽略独立 cgroup 管理，子进程继承调度器已经准备并在 clone3 时绑定的分组。配套原生运行时在派发任何子进程前，核对实际创建进程的 cgroup、必需控制入口和原目录，并把分组、父目录、挂载根及启动／namespace 身份写入首次 creating 状态；独立父分组、systemd cgroup 和外部 OCI 生命周期钩子不支持这一协议。没有配置分组的旧原生专项仍采用原出生协议，不得到离线分组清理权限。

`DeleteIfGenerationAfterCgroupOffline` 只把调用方持有的原目录句柄传给配套原生核验。原生运行时在原状态锁内再次核对完整来源、代际和首次保存的分组身份；原目录仍在线、普通空目录、字段缺失、来源替换或观察环境改变时拒绝。核对原目录的必需 `cgroup.procs` 和 `cgroup.events` 都已因目录删除而不可打开后，才允许清理原运行时状态，不补写进程出生或发送新的信号。依据是 [Linux 7.0 cgroup 删除实现](https://github.com/torvalds/linux/blob/v7.0/kernel/cgroup/cgroup.c) 和 [cgroup v2 的删除语义](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)：删除前排除成员和在线子分组，再阻止新成员进入。本入口尚未接通 daemon 的持久分组关闭、重启恢复、分组租约结算或节点预算；调用成功不能作为完整沙箱退役回执。

在派发前，适配器向持久运行时目录的 .scheduler-launches 保存独占的原创建意图，包含资源代际、独立操作编号、日志修订、有效期限、参数摘要、cgroup 设备／inode、启动环境及 namespace 身份。文件和目录同步成功后才允许派发，来源替换、日志冲突或保存失败拒绝。保留的 dispatching 不等于实际启动、停止或预算归还证明；日志没有自动回收，已确认退役后的安全回收与重启恢复仍待后续接线。该能力不关闭第一条 gofer／Sentry 出生缺失、其他资源效果或完整预算问题。显式不管理 cgroup 的原生专项继续使用原出生协议，不因此获得缺失出生时的清理授权。
