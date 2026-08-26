# Deploying sandboxd with Firecracker checkpoint/restore

Production deployment notes for the Firecracker CR runtime. Version and
progress tracking lives in the workspace `VERSION_FC.md`; this file is the
on-node runbook shipped with the code.

## Hard requirements

1. **One reflink filesystem** (XFS): the template registry, the writable
   filestore (`plugin.runtime.filestore_dir`, plain directory mode — do NOT
   configure `filestore_dir_size`), and every checkpoint directory must live
   on the same reflink-capable filesystem. Crossing filesystems silently
   degrades FICLONE to full copies: disk cost becomes O(memory) per
   generation and fork stops being O(1).
2. **Component upgrades invalidate all templates.** The compatibility tuple
   pins the Firecracker binary, guest kernel, initrd, kernel args and vCPU
   count; any change makes every existing template refuse to restore. The
   upgrade runbook is therefore: upgrade binaries → re-manufacture templates
   (`deploy/fc-template.sh`) → switch traffic. Budget manufacture time
   (~1s/GiB memory + 20s warmup per SKU; the fsync tail runs outside the
   pause window but extends wall time).
3. **One daemon per network segment**: two sandboxd daemons on the same host
   must not share a TAP pool / bridge segment (plan distinct `ip_range`s).

## Layout

```
/srv/akernel/<instance>/            # instance root (--root)
    config.toml
    state/                          # sandboxd.sock, logs (created by unit)
    rootfs.erofs                    # read-only guest rootfs
/usr/local/bin/{sandboxd,checkpoint-restore}
<reflink-xfs>/templates/           # TEMPLATE_ROOT for fc-template.sh
<reflink-xfs>/filestore/           # plugin.runtime.filestore_dir
<reflink-xfs>/checkpoints/         # caller-owned checkpoint dirs
```

## Install

```sh
cp deploy/sandboxd.service /etc/systemd/system/sandboxd@.service
cp output/sandboxd /usr/local/bin/
cp output/checkpoint-restore /usr/local/bin/
systemctl daemon-reload
systemctl enable --now sandboxd@m2
```

The unit exists because sandboxd installs its own SIGHUP handler: a daemon
started from an ssh session dies when systemd-logind tears the session
cgroup down (`nohup`/`setsid` do not protect it).

## Templates

```sh
export TEMPLATE_ROOT=/mnt/xfs/templates SANDBOXD_SOCKET=/srv/akernel/m2/state/sandboxd.sock
deploy/fc-template.sh make python-2c4g 4096 2048 \
  'python3 -m pip install numpy >/dev/null 2>&1'
deploy/fc-template.sh show
```

Note: `storageMB` is the writable layer quota — size it to the workload's
real footprint (the historical bench script defaulted it to 64, which
silently ENOSPCs larger warmup writes).

## Checkpoint policy (caller-side, by contract)

- Rolling checkpoints are incremental (soft-dirty windows); each generation
  is a complete, independently restorable artifact; measured pause windows:
  ~20ms at 512MiB window-dirty, ~0.9s at 8GiB.
- Retention: deleting older generations is always safe; the newest
  generation must survive (the incremental baseline references it). A
  rolling N=3 with disk-pressure alerts is a sane production start.
- Restoration is a plain Start with `checkpoint_info`; a missing template
  fails fast (~8ms) — orchestration decides cold-start fallback.
