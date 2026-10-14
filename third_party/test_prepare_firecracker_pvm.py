#!/usr/bin/env python3
"""Candidate integrity and profile regression tests; no privileged workloads."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("prepare-firecracker-pvm.py")
spec = importlib.util.spec_from_file_location("candidate", SCRIPT)
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class CandidateTests(unittest.TestCase):
    def fixture(self, root, *, profile="pvm", extra=None, mpk=True):
        elf = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(80)
        config = (
            "\n".join(
                "CONFIG_" + name + "=y"
                for name in ["KVM_GUEST", "PVM_GUEST", "X86_PIE"]
                + (["X86_INTEL_MEMORY_PROTECTION_KEYS"] if mpk else [])
            )
            + "\n"
        )
        digest = lambda b: hashlib.sha256(b).hexdigest()
        manifest = {
            "component": "akernel-firecracker-runtime",
            "repository": "akernel-dev/firecracker",
            "commit": "a" * 40,
            "workflow_run_id": "12",
            "release_tag": "v1.16.1-akernel.4",
            "architecture": "x86_64",
            "kernel_profile": profile,
            "vmm": {"source": "fork-source-build", "binary_sha256": digest(elf)},
            "guest_kernel": {
                "source_tag": "b" * 40,
                "source_sha256": "c" * 64,
                "image_sha256": digest(elf),
                "config_sha256": digest(config.encode()),
            },
        }
        files = {
            "firecracker": elf,
            "vmlinux": elf,
            "kernel.config": config.encode(),
            "manifest.json": json.dumps(manifest).encode(),
        }
        files["SHA256SUMS"] = "".join(
            digest(data) + "  ./" + name + "\n" for name, data in files.items()
        ).encode()
        path = root / "candidate.tgz"
        with tarfile.open(path, "w:gz") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo("release-v1.16.1-akernel.4-x86_64/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if extra:
                member = tarfile.TarInfo(extra)
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        pin = {
            "schema": 1,
            "repository": "akernel-dev/firecracker",
            "commit": "a" * 40,
            "run_id": 12,
            "artifact_id": 34,
            "artifact_digest": "sha256:" + "d" * 64,
            "release_tag": "v1.16.1-akernel.4",
            "archive_name": "firecracker-v1.16.1-akernel.4-x86_64.tgz",
            "archive_sha256": candidate.sha256(path),
            "guest_commit": "b" * 40,
            "guest_source_sha256": "c" * 64,
        }
        pin_path = root / "pin.json"
        pin_path.write_text(json.dumps(pin))
        return path, pin, pin_path

    def test_valid_original_archive_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            path, pin, _ = self.fixture(Path(d))
            self.assertEqual(
                candidate.verify_archive(path, pin)["kernel_profile"], "pvm"
            )

    def test_outer_checksum_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path, pin, _ = self.fixture(Path(d))
            path.write_bytes(path.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                candidate.verify_archive(path, pin)

    def test_hardware_kvm_bundle_cannot_satisfy_pvm(self):
        with tempfile.TemporaryDirectory() as d:
            path, pin, _ = self.fixture(Path(d), profile="kvm")
            with self.assertRaisesRegex(ValueError, "kernel_profile"):
                candidate.verify_archive(path, pin)

    def test_different_guest_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path, pin, _ = self.fixture(Path(d))
            pin["guest_commit"] = "e" * 40
            with self.assertRaises(ValueError):
                candidate.verify_archive(path, pin)

    def test_unsafe_member_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path, pin, _ = self.fixture(Path(d), extra="../escape")
            with self.assertRaises(ValueError):
                candidate.verify_archive(path, pin)

    def test_missing_mpk_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path, pin, _ = self.fixture(Path(d), mpk=False)
            with self.assertRaisesRegex(ValueError, "X86_INTEL_MEMORY_PROTECTION_KEYS"):
                candidate.verify_archive(path, pin)

    def test_optimized_python_does_not_disable_verification(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path, _, pin = self.fixture(root, profile="kvm")
            result = subprocess.run(
                [
                    sys.executable,
                    "-O",
                    str(SCRIPT),
                    "--pin",
                    str(pin),
                    "--archive",
                    str(path),
                    "--destination",
                    str(root / "staged.tgz"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("kernel_profile", result.stderr)
            self.assertFalse((root / "staged.tgz").exists())


if __name__ == "__main__":
    unittest.main()
