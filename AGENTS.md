# CI Checks

Before completing a change, run the checks relevant to it:

```sh
make check-fmt
make vet
make test
```

For protobuf changes, also run:

```sh
make check-protos
```

For changes under `bpf/bpfnat` or `pkg/networkmanager/bpfnat`, also run:

```sh
make check-bpf
make bpfnat-test
```

`make bpfnat-test` runs privileged dataplane, map, garbage-collection,
restart, and lifecycle tests in an isolated container network namespace and
bpffs mount. The default GitHub CI workflow runs it in the network dataplane
job.

When changing bpfnat behavior, extend the regular unit tests for pure parsing
and policy logic and add or update the tagged integration tests for
kernel-visible behavior and relevant boundary cases.

# Markdown and GitHub Text Formatting

Do not hard-wrap prose in Markdown documentation, GitHub pull request bodies, release descriptions, issue comments, or pull request review comments. Keep each paragraph and list item on a single logical line and let the renderer handle visual wrapping. Preserve line breaks that carry Markdown meaning, such as paragraph boundaries, lists, tables, blockquotes, and code blocks.

Git commit message bodies are the exception and should remain wrapped at approximately 72 characters as required by the repository commit rules.

# Runtime Artifact Pins

`third_party/runtime-versions.env` is the single source of truth for runtime
artifacts used by sandboxd E2E and packaged by AKernel. Keep each release,
download URL, and checksum synchronized. Do not duplicate runtime versions in
CI workflow environment variables or Dockerfiles.

gVisor is installed from the complete `gvisor.tar.bz2` release archive. Its SHA-512 pin covers the archive, not the individual runsc binary. Use `third_party/install-gvisor.sh` to validate and install runsc, the containerd shim and all `gvisor-bin/` sidecars together, preserving the adjacent directory layout. Do not mix sidecars from different releases or fall back to downloading them at runtime.

The local `RUNSC_BINARY=... make e2e` path also requires the complete adjacent installation. Keep its staging helper, Dockerfile and Docker context allowlist synchronized with the release bundle layout; validate missing helpers before compiling or invoking Docker.

The AKernel gVisor release is a temporary compatibility build based on an upstream release tag. It carries direct-TAP compatibility fixes, the KVM address-width fix for hosts without LA57, and Docker bridge checkpoint/restore support. When updating gVisor, check which fixes upstream already includes and remove downstream patches that are no longer required. Docker bridge support does not imply support for every Docker networking mode; retain the upstream Docker-in-gVisor constraints.

Build a gVisor candidate through the gated workflow in
`akernel-dev/gvisor`, then test that exact candidate with the complete
sandboxd runtime suite and the AKernel standalone E2E. Promote the candidate
without rebuilding it. Only after promotion should this repository pin the
published release URL and its verified SHA-512 digest.

The AKernel Firecracker release is a checksum-pinned runtime bundle from
`akernel-dev/firecracker`. It reuses the official VMM binary and packages the
tested guest kernel, resolved configuration, licenses, checksums, and
provenance. Build and test an expiring candidate with sandboxd and AKernel,
then promote those exact bytes without rebuilding them. Only after promotion
should this repository update the bundle release, URL, and SHA-256 pin. The
sandboxd-built `firecracker-agent` initrd deliberately remains outside that
bundle so its guest protocol always matches the consuming sandboxd revision.

Run the complete runtime compatibility suite on a nested-KVM host with:

```sh
make e2e-runtime-suite
```

The suite builds the project binaries once, assembles targeted runtime images, and tests runsc with systrap, runsc with KVM, Kata, Firecracker, and runc. CI passes those binaries to seven independent matrix jobs. Both runsc platforms run the shared writable host-mount C/R regression. The Firecracker virtio-fs job runs it with EROFS and directory roots, using the manifest-pinned virtiofsd source; the full and incremental non-virtio-fs jobs remain separate. Keep the gVisor TAP contract, network ACL cases, and AKernel's shared manifest consumer in sync when changing this path.

# Checkpoint and Restore Contract

When changing the checkpoint/restore API, runtime support, artifact ownership,
compatibility requirements, or failure semantics, update
`doc/checkpoint-restore.md` in the same change so the public design contract
stays synchronized with the implementation.

# Firecracker Storage Contract

The Firecracker adapter uses local or image-provider-backed regular EROFS files by default. An operator may enable virtio-fs with `plugin.runtime.firecracker.virtiofs_enabled`; that path accepts directory root filesystems and explicitly `ro` or `rw` host directory mounts through one sandbox-scoped virtiofsd. Root image exports always remain read-only, enforced recursively on host staging mounts with `mount_setattr` (Linux 5.12+). The staging root is read-only and virtiofsd writeback caching remains disabled. OCI and Nydus root filesystems require virtio-fs and are consumed directly from the image manager; never eagerly materialize them as EROFS. OCI image mounts remain unsupported.

Per-sandbox managed storage comprises the private ext4 writable layer, virtio-fs staging and restored live-memory files, and runtime state. Host directory binds remain caller-owned: deleting a sandbox never deletes their contents, and `storage_mb` does not bound them. Writable host mounts support local checkpoint/restore only while the original backing directories and referenced files remain available; their contents are not snapshotted or rolled back. Do not recreate missing files or imply cross-node portability or automatic new log segments. Bounded read-only regular-file injection remains a separate startup-metadata mechanism for files such as `resolv.conf`.

# ChunkDB Capacity Contract

The optional `[plugin.image].chunk_db_size` is node-wide and must reach every distill-fs mount, stats, and GC invocation, including daemon recovery. Sandboxd owns capacity consistency; distill-fs does not coordinate or validate agreement across processes. Empty configuration must omit the new flag for compatibility with older binaries. Existing databases cannot resize; Pod hostname changes clear the image-manager root, while same-Pod service restarts preserve it.

`make distillfs-test` runs real FUSE mount, read, stats, GC, and daemon recovery checks in a private mount namespace. It requires sudo, `/dev/fuse`, and `mkfs.erofs`; `DISTILL_FS_BINARY` selects the production executable (default `output/distill-fs/distill_fs`). The storage CI job downloads and verifies the formal release pinned in `third_party/runtime-versions.env` before running it. Explicitly enabled integration must fail when prerequisites are missing, never silently skip.

Per-sandbox Firecracker storage remains limited to the private writable layer, virtio-fs staging, restored live-memory files, and runtime state. Explicit writable host exports are an upstream runtime capability and are not part of this scheduler's checkpoint acceptance.


# Scheduler generation-conditional deletion

`DeleteIfGeneration` is a separate RPC requiring the current
`akernel.scheduler/resource-generation` value. It checks identity under the
physical resource lock and returns that generation only after successful cleanup.
Do not fall back to legacy `Delete` when this RPC is unavailable or rejected.
A missing sandbox without a matching completed durable receipt returns NotFound;
absence alone does not prove retirement. Completed receipts can be replayed even
if the ID now belongs to another generation, without touching that replacement.
Legacy Delete retains its existing unconditional semantics.

Keep `<RootDir>/scheduler-retirements` on persistent daemon-owned storage.
Pending records are not proof of completion; crash gaps require authoritative
reconciliation. The journal is capped at 65536 entries and has no automatic GC.
Do not delete receipts or release controller budgets merely because they aged out.

generation. Legacy Delete retains its existing unconditional semantics.

Successful Start and Restore responses include `resource_generation` from the
published physical metadata. Preserve this creation-time identity for subsequent
conditional deletion; querying an ID later must not silently adopt a replacement
sandbox's generation. Restore replay returns the existing physical generation.

# Scheduler generation-conditional checkpoint

`CheckpointIfGeneration` is a separate RPC wrapping CheckpointRequest and a
required original source generation. Never fall back to legacy Checkpoint when
it is unavailable. Conditional calls reject mismatching committed artifacts or
live generations before rootfs/runtime work; a missing source can replay only a
matching completed artifact. A live replacement is conservatively rejected even
when an old matching artifact remains. The physical resource lock rechecks the
captured generation before publication. In-flight fingerprints include source
generation, and completion verifies the committed source identity again.
The scheduler must preserve the original monitor identity across every async
handoff and verify reply identity; this daemon API alone does not close F7.

# Scheduler identity resolver

The authenticated read-only resolver accepts either `/resolve?ip=<IPv4>` or
`/resolve?instance_id=<trusted control-plane instance ID>`, exactly one value
and no additional parameters. Instance lookup does not require an IP address.
Both paths require a unique RUNNING sandbox with complete instance/runtime/
sandbox/resource-generation identity, matching Stats generation, and an unchanged
second List result. The response is a fresh observation, not a lease for future
mutations. Its response contains no birth-resource proof. Keep the separate
resolver token out of trial artifacts.

# Scheduler birth-resource evidence

Elastic Start/Restore now saves `akernel.scheduler/birth-resources` in the
incarnation's INTENT metadata after leaf cgroup readback and before invoking the
runtime handler. Persistence failure prevents that invocation. The label contains
schema 1, sandbox ID, resource generation, start/restore phase, observation time,
CPU quota/period and memory hard limit. Create clears any caller/checkpoint copy;
restore records its newly observed limits under its fresh generation.
Only associate this record with a successfully committed matching incarnation.
It proves prepared leaf limits, not ancestor-effective capacity or runtime success.
List exposes the committed label. The authenticated `/resources` resolver route
accepts the same selector as `/resolve` and returns schema 1 with `identity`,
validated `birth`, Stats RPC start/end timestamps, and an allowlisted `current`
sample. Missing, malformed, mismatching or changing birth labels return 409;
`/resolve` remains available without birth evidence. StatsResponse and the
`current` sample carry source-validity flags `cpu_usage_known`,
`memory_usage_known`, `memory_limit_known`, and `memory_peak_known`: true only
when the cgroup v2 backend parsed the exact kernel file (cpu.stat usage_usec
within the nanosecond conversion range, memory.current, memory.max with its
"max" sentinel, memory.peak) under strict bounded rules, a genuine zero
included. When a flag is false the matching numeric still holds the legacy
fallback — a missing memory.peak substitutes current usage — so it must not be
read as an observed value, let alone a lifetime peak. The cgroup v1 backend
reports all four flags false: its library metrics cannot prove source presence.
Servers predating the flags default them false on the wire for the same
reason, so consumers must consult the flags, never infer validity from a
nonzero number. Harbor report consumption of node retirement evidence remains pending;
see the retirement-resource section below for daemon capture.
Metadata atomic writes now fsync the file, rename, then fsync its directory;
PersistMetadata also syncs parent entries through the containers-root parent
before publishing an INTENT in memory. A post-rename sync error can leave the
new file visible and must remain unresolved. Syscall fault checks are not a real
power-loss recovery acceptance run. Provision the daemon root durably and preserve
generation-segmented evidence before deletion.

# Scheduler retirement resource evidence

For a sandbox carrying a resource generation, both Delete and
DeleteIfGeneration archive observations in the daemon-owned
`<RootDir>/scheduler-resource-retirements` directory. One delete_attempt_id
links separate immutable before_runtime_delete and after_runtime_delete
records; retries create another attempt. The second observation is after
runtime deletion returns successfully (including NotFound), before daemon
cgroup/resource recycling. Both compare current metadata with the original
cloned snapshot under the physical resource lock. Completed conditional
retirement replay creates no new observation and cannot adopt a replacement.

Records contain only allowlisted identity, validated committed birth data,
and resource counters with knownness flags. Unavailable Stats is null with
an explicit category and does not alone prevent cleanup. The records never
prove full deletion: physical_deletion_confirmed remains false permanently;
only a separate matching completed retirement receipt proves full cleanup.
Pre-delete publication failure prevents the runtime call. Post-delete
publication failure prevents resource recycling and the completed receipt,
leaving a pending state that must be retried or reconciled.

Keep this directory on durable storage, mode0700; records are mode0600,
file-fsynced, linked without replacing existing records, then the temporary
name is removed before directory fsync. The append-only journal permits
65536 directory entries and at most32KiB per record, with no automatic GC.
Do not discard records merely to unblock a full journal. Export/history
consumption and safe archival/reclamation still require implementation.
These observations do not measure an instantaneous whole-lifetime CPU peak;
read memory peaks only when memory_peak_known is true.

# Managed restore completion ownership

The checkpoint coordinator may publish immutable completion bytes through
CompleteWithResult; each successful WaitResult returns a private copy. Legacy
checkpoint Complete remains payload-free. Completion is first-wins and only
the owning coordinator/attempt can release its in-flight lock keys.

Managed restore preserves the actual createSandbox StartResponse as the attempt
result. After waiting, it checks the current record under the physical resource
lock against that original generation, restore identity, runtime, labels and
ports. A same-identity replacement generation, missing/uncommitted/non-running
record or missing result cannot become a successful response. The pre-dispatch
replay also uses the physical lock and requires a nonempty generation. These
lookups never clean up a sandbox and do not nest locks across creation or waits.

This is in-process result ownership, not durable operation fencing. The
coordinator still drops completed entries and physical metadata can be deleted.
Also, LoadStatus currently defaults missing status files to RUNNING: cache state
is not authoritative runtime liveness. F8 still requires a read-only runtime
query, persistent operation identity across controller/node restarts, delayed
request fencing after retirement and authoritative budget reconciliation.

# Scheduler resource revisions and shrink

Every elastic physical incarnation carries one bounded, daemon-owned record
under `<RootDir>/scheduler-resource-states` (0700 dir, 0600 files, temp +
fsync + rename + dir fsync, 65536-entry cap, no GC). It binds sandbox,
resource generation, cgroup path plus inode/device identity, the monotonic
resource revision (initialized to 1 between birth evidence and runtime start
for Start and Restore alike), and the last operation's ID, fingerprint,
limits and outcome. A missing record is unknown state — never an inferred
initial revision — and a damaged record keeps the incarnation fail-closed
with Stats reporting a pending operation. A revision at UINT64_MAX refuses
new operations instead of wrapping.

ResizeResources and the separate ShrinkResources RPC share one contract:
non-empty printable operation_id, expected_revision CAS against the journal,
and a full-request fingerprint (kind, identity, revision, both limit triples,
deadline). Admission resolves the recorded outcome first: the same ID with
the same fingerprint replays only its recorded outcome and never re-executes,
and a replay repeats a recorded complete only while the CURRENT physical
readback still verifies the target limits, the enforced high and an unfrozen
sandbox — any later perturbation downgrades it to a conservative non-complete
answer. A different fingerprint under the same ID is rejected. A fresh
operation then compares strictly (expected limits equal the live limits);
live==target never substitutes for that compare. The next revision and the
complete intent are persisted before any side effect; partial or UNKNOWN
outcomes keep the advanced revision and new operations are rejected until
reconciliation closes the record. Legacy revision-less requests and
revision-less incarnations are rejected: there is no implicit compatibility
path that would break the ABA fence.

Grow stays grow-only (max then high, both verified) and refuses a
proven-frozen sandbox; its complete demands the same full readback contract
as shrink — limits, the enforced memory.high, and frozen_known with
frozen=false. Shrink requires runsc on cgroup v2 with a configured
memory.high ratio, unchanged CPU numbers, target within the persisted policy
floor/ceiling, proven usage/limits/high/frozen readings, and no pre-existing
freeze request or state. It persists a freeze-owning intent, writes
cgroup.freeze=1, confirms events.frozen within 500ms (timeout releases the
request and never lowers limits; the poll honors the command context, a
confirmed frozen reading still counts), re-checks the command deadline and
context after the freeze is confirmed and before any memory write (expiry
stops at the already-frozen point), re-checks frozen current + node headroom
(minimum 16 MiB, configurable upward only) against the target high, writes
memory.high then memory.max, and only reports complete after verified limits,
correct high, and a confirmed unfreeze through an RPC-cancellation-independent
2s cleanup. The enforced high is ceil(ratio*max) page-aligned DOWN to the
kernel page size. Partial writes restore the recorded original controls
(never above the original max) and stay partial. Unconfirmed unfreeze leaves
the journal open for the self-heal loop; recovery and healing never convert
an error into a success. Every RPC response is assembled from an observation
taken after the durable journal close under the same physical lock, so
pending=false, the operation ID and the advanced revision in a response are
always the closed record's facts; a failed close returns an uncertain error
and never fakes a terminal state.

Daemon restart scans the journal before recoveryReady: only records whose
sandbox, generation, cgroup path and inode/device still match are touched,
their owned freeze is released and read back, and the record closes at its
advanced revision (complete only when the recorded target fully verifies).
Foreign or missing incarnations are never unfrozen; their records are
retained. A physical delete of the generation is the only authority that
retires a record, and it releases the owned freeze first so the runtime
handler never meets a frozen Sentry. Pause, Resume and Checkpoint also
refuse to start while this daemon owns an open or damaged resource operation
for the incarnation — their Sentry round-trips could hang under the physical
lock against our own frozen sandbox and wedge recovery; the refusal never
releases anyone's freeze. Pause/Resume serialize on the same per-sandbox
physical lock as Stats/Resize/Shrink/Delete/Checkpoint; the lock is not
reentrant. Recycled cgroups reset cgroup.freeze to 0.

Stats reports resource_revision/known, memory.high bytes/known/unlimited
(unlimited is explicit, never a finite 0), kernel-confirmed frozen/known
(frozen_known true and frozen false is the only accepted "unfrozen"), the
last operation ID with a pending flag, and memory_cgroup_path (field 33):
the absolute cgroup v2 directory behind the read, exposed only when the
incarnation's revision record verifies against the live cgroup identity and
empty for cgroup v1 or unverifiable records. It is a read-only locator for
event watchers — never a write target, never a replacement for journal
identity verification. pending=true never closes an UNKNOWN by itself:
reconciliation must match operation_id and revision with pending=false,
verified limits and an unfrozen sandbox.
