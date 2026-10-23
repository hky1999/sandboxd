#!/usr/bin/env bash
# PVM runtime qualification. The runner is an owned disposable L1.
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${PVM_CI_OUTPUT:-${root}/output/pvm-ci}"
mkdir -p "${out}"
: "${PVM_HOST_PROFILE:?caller must select a committed expected host profile}"
source_sha=$(git -C "${root}" rev-parse HEAD)
[[ -z "${PVM_SOURCE_SHA:-}" || "${PVM_SOURCE_SHA}" == "${source_sha}" ]]
python3 "${root}/test/e2e/pvm-l1.py" > "${out}/l1-before.json"
cp "${PVM_HOST_PROFILE}" "${out}/expected-host-profile.json"
cp /opt/akernel-pvm-ci/host-build.json "${out}/host-build.json"
python3 - "${out}" "${source_sha}" <<'PVM_SOURCE'
import json,os,sys
from pathlib import Path
(Path(sys.argv[1])/'qualification-source.json').write_text(json.dumps({'schema':1,'source_sha':sys.argv[2],'workflow_sha':os.environ.get('GITHUB_SHA'),'repository':os.environ.get('GITHUB_REPOSITORY')},indent=2))
PVM_SOURCE
[[ "${EUID}" == 0 ]] || { echo 'PVM L1 runner must be root' >&2; exit 1; }
[[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" == unix:///run/pvm-ci-docker.sock ]] || {
  echo 'PVM CI requires its private L1 Docker daemon' >&2; exit 1;
}
for process in firecracker sandboxd virtiofsd; do
  if pgrep -x "${process}"; then
    echo "PVM CI refuses an existing ${process} process" >&2
    exit 1
  fi
done
[[ ! -d /sys/module/kvm && ! -d /sys/module/kvm_pvm ]] || {
  echo 'PVM qualification requires an unloaded module pair' >&2; exit 1;
}
# Record ownership before the first insmod so failure after loading the core
# still cleans that owned core, while a rejected pre-existing pair is untouched.
cp "${out}/l1-before.json" "${out}/module-load-intent.json"
modprobe irqbypass
insmod /opt/akernel-pvm-ci/modules/kvm.ko
insmod /opt/akernel-pvm-ci/modules/kvm-pvm.ko
python3 "${root}/test/e2e/pvm-l1.py" --probe > "${out}/abi.json"
for module in erofs fuse loop tun br_netfilter ip_tables ip6_tables \
  iptable_filter ip6table_filter iptable_nat ip6table_nat xt_conntrack xt_connmark; do
  modprobe "${module}"
done
cd "${root}"
distribution=$(python3 -c 'import json;print(json.load(open("third_party/firecracker-pvm.json")).get("distribution","actions"))')
if [[ "${distribution}" == actions ]]; then
  export PVM_CANDIDATE_ARCHIVE="${PVM_CANDIDATE_ARCHIVE:-/opt/akernel-pvm-ci/firecracker.tgz}"
fi
export GOMAXPROCS=2 GOFLAGS=-p=2
python3 test/e2e/test_pvm_l1.py -v
python3 test/e2e/test_pvm_request.py -v
python3 third_party/test_prepare_firecracker_pvm.py -v
python3 test/e2e/test_redis_stage.py -v
make check-fmt vet test e2e-runtime-binaries
fixture="${PVM_CI_FIXTURES:-/opt/akernel-pvm-ci/fixtures.json}"
[[ -f "${fixture}" ]]
export E2E_OCI_REGISTRY_SCHEME=http
export E2E_OCI_ROOTFS_IMAGE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["runtime_oci"])' "$fixture")
docker start review-registry >/dev/null
for runtime in firecracker-pvm firecracker-pvm-incremental firecracker-pvm-virtiofs; do
  SANDBOXD_E2E_CONTAINER="pvm-ci-${GITHUB_RUN_ID:-local}-${runtime}" \
    SANDBOXD_E2E_DISABLED_CONTAINER="pvm-ci-${GITHUB_RUN_ID:-local}-${runtime}-no-cgroup" \
    E2E_CASE="${runtime}" make e2e-runtime-case > "${out}/${runtime}.log" 2>&1
  printf '0\n' > "${out}/${runtime}.rc"
done
dmesg > "${out}/l1.dmesg"
if grep -E 'BUG:|Oops|WARNING:|general protection' "${out}/l1.dmesg"; then exit 1; fi
for process in firecracker sandboxd virtiofsd; do
  if pgrep -x "${process}"; then
    echo "PVM CI left an unexpected ${process} process" >&2
    exit 1
  fi
done
