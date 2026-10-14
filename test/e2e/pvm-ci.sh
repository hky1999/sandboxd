#!/usr/bin/env bash
# PVM runtime qualification. The runner is an owned disposable L1.
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${PVM_CI_OUTPUT:-${root}/output/pvm-ci}"
mkdir -p "${out}"
python3 "${root}/test/e2e/pvm-l1.py" > "${out}/l1-before.json"
[[ "${EUID}" == 0 ]] || { echo 'PVM L1 runner must be root' >&2; exit 1; }
[[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" == unix:///run/pvm-ci-docker.sock ]] || {
  echo 'PVM CI requires its private L1 Docker daemon' >&2; exit 1;
}
! pgrep -x firecracker
! pgrep -x sandboxd
if [[ -d /sys/module/kvm_pvm ]]; then
  python3 "${root}/test/e2e/pvm-l1.py" --probe > "${out}/abi.json"
else
  [[ ! -d /sys/module/kvm ]] || { echo 'PVM CI refuses an existing KVM core' >&2; exit 1; }
  modprobe irqbypass
  insmod /opt/akernel-pvm-ci/modules/kvm.ko
  insmod /opt/akernel-pvm-ci/modules/kvm-pvm.ko
  python3 "${root}/test/e2e/pvm-l1.py" --probe > "${out}/abi.json"
fi
cd "${root}"
export PVM_CANDIDATE_ARCHIVE="${PVM_CANDIDATE_ARCHIVE:-/opt/akernel-pvm-ci/firecracker.tgz}"
export GOMAXPROCS=2 GOFLAGS=-p=2
python3 third_party/test_prepare_firecracker_pvm.py -v
make check-fmt vet test e2e-runtime-binaries
for runtime in firecracker-pvm firecracker-pvm-incremental firecracker-pvm-virtiofs; do
  SANDBOXD_E2E_CONTAINER="pvm-ci-${GITHUB_RUN_ID:-local}-${runtime}" \
    SANDBOXD_E2E_DISABLED_CONTAINER="pvm-ci-${GITHUB_RUN_ID:-local}-${runtime}-no-cgroup" \
    E2E_CASE="${runtime}" make e2e-runtime-case > "${out}/${runtime}.log" 2>&1
  printf '0\n' > "${out}/${runtime}.rc"
done
dmesg > "${out}/l1.dmesg"
if grep -E 'BUG:|Oops|WARNING:|general protection' "${out}/l1.dmesg"; then exit 1; fi
! pgrep -x firecracker
! pgrep -x sandboxd
! pgrep -x virtiofsd
