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
components. The manifest is written last, so a directory that shows a manifest
is a self-consistent artifact; a directory without one is partial output that
sandboxd cleans up. The memory file stays a plain file that Firecracker
patches in place — the layout deliberately avoids archiving or compression so
reflink sharing and incremental writes survive. `compress` has no effect on
this layout (it only applies to legacy artifacts). Legacy single-file
`checkpoint.img` archives can still be restored but are no longer written.

Repeated checkpoints of the same running sandbox are incremental: each
generation clones the previous generation's memory (a copy-on-write reflink
when both directories share a reflink-capable filesystem) and Firecracker
rewrites only the pages that changed, both into the artifact and on disk. Each
generation is still a complete, independently restorable artifact; incremental
behavior affects only how much host work and disk space a generation costs.
Consecutive generations must use distinct `checkpoint_dir` values — sandboxd
refuses to overwrite a directory that already holds a checkpoint. The
incremental chain references the latest artifact's memory file directly, so a
caller that deletes or mutates the most recent checkpoint directory drops the
sandbox back to a full first window on the next checkpoint; deleting older
generations is always safe.

`snapshot_type` is a Firecracker-specific control with a validated enum: an
empty value keeps the automatic tier selection above (a pagemap `Incremental`
generation against the memory file a restore loaded, `SoftDirty` windows
against a previous checkpoint afterwards, a `SoftDirty` first window with no
lineage). An explicit `Full` drops the lineage for one generation and has
Firecracker write the whole memory file. An explicit `Incremental` requires
the restore-established pagemap base and fails otherwise. An explicit
`SoftDirty` accepts whatever lineage is still usable. Independently of the
request, a generation whose Firecracker snapshot fails degrades to a `SoftDirty`
first window to keep the chain consistent — the sealed manifest records what
was actually taken. Runtimes without incremental checkpoints (runsc) ignore
the field.

The manifest digests the small components (`vmstate`, `overlay.ext4`); hashing
the memory file is skipped because it costs seconds of CPU per GiB and would
dominate an otherwise sub-second incremental checkpoint.

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

## Runtime support and compatibility

| Runtime | Checkpoint and restore |
| --- | --- |
| runsc with systrap | Supported |
| runsc with KVM | Supported |
| Firecracker | Supported |
| Kata Containers | Not supported |
| runc | Not supported |

Unsupported runtimes return `Unimplemented`.

A checkpoint must be restored with the same runtime and a compatible runtime
binary, machine architecture, host or guest kernel, and runtime configuration.
Compression changes only the runtime-specific artifact encoding; it does not
make an artifact portable.

Incremental checkpoint scheduling (which generations a caller takes and when),
deterministic replay, migration orchestration, and automatic recovery of a
source after checkpoint failure are outside this design.
