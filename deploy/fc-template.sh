#!/usr/bin/env bash
# Production Firecracker template manufacture pipeline.
#
#   deploy/fc-template.sh make <name> <memMB> <storageMB> <hook-shell>
#   deploy/fc-template.sh show [<name>]
#
# A template is a sealed, content-addressed v2 checkpoint registered in
# templates.json. Orchestration lives outside sandboxd by contract; this
# script is the reference pipeline production uses.
#
# Deployment prerequisites (hard requirements, see deploy/README.md):
#   - TEMPLATE_ROOT, FILESTORE and all checkpoint directories must live on
#     the SAME reflink-capable filesystem (XFS); otherwise FICLONE degrades
#     to full copies and disk usage becomes O(memory) per generation.
#   - Every binary/kernel/initrd/kernel-args change invalidates ALL existing
#     templates (compat tuple); rerun this pipeline for each SKU after any
#     component upgrade.
set -euo pipefail

SOCK=${SANDBOXD_SOCKET:-/srv/akernel/m2/state/sandboxd.sock}
REQ=${SANDBOXD_REQUEST:-/srv/akernel/m2/req.json}
ROOTFS=${SANDBOXD_ROOTFS:-/srv/akernel/m2/rootfs.erofs}
CLI=${SANDBOXD_CLI:-/usr/local/bin/checkpoint-restore}
STAGE=${TEMPLATE_STAGE:-$TEMPLATE_ROOT/stage}

make_template() { # name memMB storageMB hook
  local name=$1 mem=$2 storage=$3 hook=$4 build="tpl-$1-build-$$"
  rm -rf "$STAGE" && mkdir -p "$STAGE" "$TEMPLATE_ROOT"

  "$CLI" -action start -socket "$SOCK" -request-file "$REQ" \
    -sandbox-id "$build" -rootfs "$ROOTFS" -memory-mb "$mem" -storage-mb "$storage" \
    -runtime firecracker -timeout 300s \
    -workload-cmd "$hook; echo warmed > /var/template-warmed; sync; while :; do sleep 1; done"

  echo "warming (20s)..." && sleep 20

  "$CLI" -action checkpoint -socket "$SOCK" -request-file "$REQ" \
    -sandbox-id "$build" -checkpoint-dir "$STAGE" \
    -compress=false -leave-running=false -snapshot-type Full -timeout 300s
  "$CLI" -action delete -socket "$SOCK" -request-file "$REQ" \
    -sandbox-id "$build" -timeout 120s || true

  local id dir
  id=$(cat "$STAGE"/manifest.json "$STAGE"/vmstate "$STAGE"/memory "$STAGE"/overlay.ext4 \
       | sha256sum | cut -c1-16)
  dir=$TEMPLATE_ROOT/$id
  [ -e "$dir" ] && { echo "template id collision: $id"; exit 1; }
  mv "$STAGE" "$dir" && chmod 0555 "$dir" && chmod 0444 "$dir"/*
  python3 - "$TEMPLATE_ROOT/templates.json" "$id" "$name" "$dir" << 'PY'
import json, sys, os, datetime
reg_path, tid, name, tdir = sys.argv[1:5]
m = json.load(open(f"{tdir}/manifest.json"))
reg = {"templates": []}
if os.path.exists(reg_path):
    reg = json.load(open(reg_path))
reg["templates"] = [t for t in reg["templates"] if t["name"] != name]
reg["templates"].append({
    "id": tid, "name": name, "dir": tdir,
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "snapshot_type": m["snapshot_type"], "memory_size": m["memory_size"],
    "compat": m.get("compat", {}), "digests": m["digests"],
})
json.dump(reg, open(reg_path, "w"), indent=2)
PY
  echo "TEMPLATE $name id=$id dir=$dir"
}

show() {
  python3 - "$TEMPLATE_ROOT/templates.json" "${1:-}" << 'PY'
import json, sys
for t in json.load(open(sys.argv[1]))["templates"]:
    if not sys.argv[2] or t["name"] == sys.argv[2]:
        print(f'{t["name"]}: id={t["id"]} mem={t["memory_size"]>>20}MiB '
              f'type={t["snapshot_type"]} fc={t["compat"].get("firecracker","")[:12]}')
PY
}

case "${1:-}" in
  make) make_template "$2" "$3" "$4" "$5" ;;
  show) show "${2:-}" ;;
  *) echo "usage: $0 make <name> <memMB> <storageMB> <hook> | show [<name>]"; exit 2 ;;
esac
