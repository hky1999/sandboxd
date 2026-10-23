#!/usr/bin/env python3
"""Verify L1 ownership and the caller's committed host profile before module use."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import urllib.parse

MODULE_PAIR = {"kvm.ko", "kvm-pvm.ko"}


def require(ok, message):
    if not ok:
        raise SystemExit(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_boundary(marker, *, machine, kernel, cmdline, flags):
    require(marker["schema"] == 1 and marker["isolation"] == "disposable-l1",
            "requires a disposable L1 runner")
    require(machine == "x86_64" and kernel == marker["kernel_release"],
            "unqualified L1 kernel")
    require("init=/root/l1-init.sh" in cmdline,
            "refusing module operations outside the owned L1")
    require("vmx" not in flags and "svm" not in flags, "PVM CI must hide VMX/SVM")
    require(all(x in flags for x in ["fsgsbase", "rdtscp", "cx16"]),
            "PVM CPU prerequisites missing")
    require(marker["outer_network"] == "none" and marker["cpu_quota"] == 2
            and marker["memory_gib"] == 10, "unbounded L1 runner")
    require(marker["debugctl_applied"] is False,
            "default PVM CI must leave DEBUGCTL unapplied")


def validate_host_profile(marker, expected, receipt_path, module_root, *, machine, kernel):
    """Compare observed inputs with caller-owned expectations, never marker pins."""
    require(expected["schema"] == 1, "unsupported expected host profile schema")
    source, target = expected["source"], expected["target"]
    require(machine == target["architecture"], "unexpected host architecture")
    require(kernel == target["kernel_release"] == marker["kernel_release"],
            "running kernel does not match expected host profile")
    require(marker["kernel_sha256"] == target["kernel_image_sha256"],
            "kernel image does not match expected host profile")
    require(marker["host_source"] == source["commit"],
            "host source does not match expected host profile")
    require(marker["host_baseline"] == source["baseline_commit"],
            "host baseline does not match expected host profile")
    require(expected["debugctl_applied"] is False and marker["debugctl_applied"] is False,
            "unqualified DEBUGCTL variant")
    require(sha256(receipt_path) == expected["build_evidence_sha256"],
            "build evidence checksum does not match committed host profile")
    build = json.loads(receipt_path.read_text())
    require(build["schema"] == 1, "unsupported build evidence schema")
    prepared = build["prepared"]
    require(build["source"] == source["commit"], "build source does not match expected pin")
    require(build["baseline"] == source["baseline_commit"]
            == prepared["source"]["commit"], "build baseline does not match expected pin")
    require(prepared["source"]["repository"] == source["repository"]
            and prepared["source"]["upstream_base"] == source["upstream_commit"],
            "build source provenance does not match expected host profile")
    require(prepared["profile"] == expected["id"]
            and prepared["profile_sha256"] == target["profile_sha256"],
            "build target profile does not match expected host profile")
    require(prepared["prepared_tree_sha256"] == target["prepared_tree_sha256"],
            "prepared tree does not match expected host profile")
    for key in ("architecture", "kernel_release", "compiler_version", "files_sha256"):
        require(prepared["target"][key] == target[key],
                "build target identity mismatch: " + key)
    require(build["modpost_passed"] is True, "host module modpost did not pass")
    require(build["debugctl_applied"] is False, "unqualified DEBUGCTL build")
    require(sorted(expected["modules"]) == sorted(MODULE_PAIR)
            and set(marker["modules"]) == MODULE_PAIR
            and set(build["modules"]) == MODULE_PAIR,
            "requires the complete module pair")
    require(marker["modules"] == build["modules"],
            "marker module pair differs from qualified build evidence")
    for name, digest in build["modules"].items():
        path = module_root / name
        require(path.is_file() and not path.is_symlink(), "missing module: " + name)
        require(sha256(path) == digest, "host module checksum mismatch: " + name)
    return {"host_source": source["commit"], "host_baseline": source["baseline_commit"],
            "host_profile": expected["id"], "target_profile_sha256": target["profile_sha256"],
            "build_evidence_sha256": expected["build_evidence_sha256"],
            "modules": build["modules"]}


def probe():
    with open("/dev/kvm", "rb", buffering=0) as kvm:
        require(fcntl.ioctl(kvm, 0xAE00, 0) == 12, "KVM API mismatch")
        msrs = bytearray(4004)
        struct.pack_into("I", msrs, 0, 1000)
        fcntl.ioctl(kvm, 0xC004AE02, msrs, True)
        count = struct.unpack_from("I", msrs)[0]
        require(count <= 1000, "MSR list overflow")
        require(0x4B564DF1 in struct.unpack_from(str(count) + "I", msrs, 4),
                "the running KVM backend is not PVM")
        require(fcntl.ioctl(kvm, 0xAE03, 60) == 0, "unexpected PVM TSC scaling")
        vm = fcntl.ioctl(kvm, 0xAE01, 0)
        try:
            vcpu = fcntl.ioctl(vm, 0xAE41, 0)
            try:
                frequency = fcntl.ioctl(vcpu, 0xAEA3, 0)
            finally:
                os.close(vcpu)
        finally:
            os.close(vm)
        require(frequency > 0, "PVM TSC frequency is not verifiable")
        return {"backend": "pvm", "tsc_frequency_khz": frequency, "tsc_scaling": False}


def validate_fixtures(actual, expected):
    require(expected["schema"] == 1, "unsupported fixture manifest schema")
    require(actual["registry_container"] == expected["registry_container"],
            "unexpected fixture registry container")
    hosts = set()
    for key, image in expected["images"].items():
        reference = actual[key]
        require(reference.endswith("/" + image), "fixture image pin mismatch: " + key)
        authority = reference.split("/", 1)[0]
        url = urllib.parse.urlsplit("http://" + authority)
        require(url.hostname and not url.username and not url.password
                and url.port == expected["registry_port"], "invalid anonymous fixture registry")
        hosts.add(url.hostname)
    require(len(hosts) == 1, "fixture images must use one owned registry")
    network = urllib.parse.urlsplit(actual["network_url"])
    require(network.scheme == "http" and network.hostname in hosts
            and network.port == expected["http_port"]
            and network.path == expected["http_path"]
            and not network.username and not network.password,
            "unexpected private network fixture")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", type=Path, default=Path("/etc/akernel-pvm-ci.json"))
    parser.add_argument("--expected-host-profile", type=Path,
                        default=os.environ.get("PVM_HOST_PROFILE"))
    parser.add_argument("--build-evidence", type=Path,
                        default=Path("/opt/akernel-pvm-ci/host-build.json"))
    parser.add_argument("--module-root", type=Path,
                        default=Path("/opt/akernel-pvm-ci/modules"))
    parser.add_argument("--fixtures", type=Path,
                        default=Path("/opt/akernel-pvm-ci/fixtures.json"))
    parser.add_argument("--boundary-only", action="store_true",
                        help="ownership check for cleanup; does not qualify a host version")
    parser.add_argument("--probe", action="store_true")
    args = parser.parse_args(argv)
    if args.boundary_only and args.probe:
        parser.error("--probe requires a qualified host profile")
    if not args.boundary_only and args.expected_host_profile is None:
        parser.error("--expected-host-profile or PVM_HOST_PROFILE is required")
    marker = json.loads(args.marker.read_text())
    machine, kernel = platform.machine(), platform.release()
    cmdline = Path("/proc/cmdline").read_text().split()
    flags = Path("/proc/cpuinfo").read_text().split("flags", 1)[1].splitlines()[0].split(":", 1)[1].split()
    validate_boundary(marker, machine=machine, kernel=kernel, cmdline=cmdline, flags=flags)
    proof = {"kernel": kernel, "vmx": False, "svm": False,
             "debugctl_applied": False, "lab_id": marker["lab_id"],
             "qualification": "boundary-only" if args.boundary_only else "host-profile"}
    if not args.boundary_only:
        expected = json.loads(args.expected_host_profile.read_text())
        for argument in expected["boot"]["required_kernel_arguments"]:
            require(argument in cmdline, "missing qualified boot argument: " + argument)
        require(not set(expected["boot"]["forbidden_cpu_flags"]).intersection(flags),
                "unqualified CPU mode")
        proof.update(validate_host_profile(marker, expected, args.build_evidence,
                                           args.module_root, machine=machine, kernel=kernel))
        proof["host_profile_sha256"] = sha256(args.expected_host_profile)
        validate_fixtures(json.loads(args.fixtures.read_text()), expected["fixtures"])
        proof["fixtures_sha256"] = sha256(args.fixtures)
    if args.probe:
        proof.update(probe())
    print(json.dumps(proof))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        raise SystemExit("invalid PVM qualification input: " + str(error)) from error
