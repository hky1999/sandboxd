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

The AKernel gVisor release is a temporary compatibility build based on an
upstream release tag. It currently carries the direct-TAP `readv` seccomp fix
and the KVM address-width fix for hosts without LA57. When updating gVisor,
first check whether upstream already includes both fixes and remove downstream
patches that are no longer required.

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

The suite builds the project binaries once, assembles targeted runtime images,
and tests runsc with systrap, runsc with KVM, Kata, Firecracker, and runc. CI
passes those binaries to five independent matrix jobs. Keep the gVisor TAP
contract, network ACL cases, and AKernel's shared manifest consumer in sync
when changing this path.

# Checkpoint and Restore Contract

When changing the checkpoint/restore API, runtime support, artifact ownership,
compatibility requirements, or failure semantics, update
`doc/checkpoint-restore.md` in the same change so the public design contract
stays synchronized with the implementation.

# Firecracker Storage Contract

The Firecracker adapter uses local or image-provider-backed regular EROFS files by default. An operator may instead enable the migration-capable, read-only virtio-fs path with `plugin.runtime.firecracker.virtiofs_enabled`; that path accepts directory root filesystems and explicitly read-only host directory mounts and exports them through one sandbox-scoped virtiofsd. OCI and Nydus root filesystems require virtio-fs and are consumed directly from the directory mounted by the image manager; never eagerly materialize those directories as EROFS. OCI image mounts remain unsupported by Firecracker.

Per-sandbox Firecracker storage is limited to the private ext4 writable layer,
virtio-fs staging and restored live-memory files, and runtime state. Every
virtio-fs export must remain read-only; never extend this path to writable host
sharing. Bounded read-only regular-file injection remains a separate
startup-metadata mechanism for files such as `resolv.conf`.

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
