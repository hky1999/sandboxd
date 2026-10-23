#!/usr/bin/env python3
"""Offline qualification regressions: no ioctl, module load, or real L1 needed."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("pvm_l1", Path(__file__).with_name("pvm-l1.py"))
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class QualificationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.modules = self.root / "modules"
        self.modules.mkdir()
        pair = {}
        for name in ("kvm.ko", "kvm-pvm.ko"):
            data = ("fixture " + name).encode()
            (self.modules / name).write_bytes(data)
            pair[name] = digest(data)
        self.build = {
            "schema": 1,
            "source": "a" * 40,
            "baseline": "b" * 40,
            "prepared": {
                "profile": "test-profile",
                "profile_sha256": "c" * 64,
                "prepared_tree_sha256": "d" * 64,
                "source": {
                    "repository": "https://example.invalid/linux.git",
                    "commit": "b" * 40,
                    "upstream_base": "e" * 40,
                },
                "target": {
                    "architecture": "x86_64",
                    "kernel_release": "test-kernel",
                    "compiler_version": "fixture compiler",
                    "files_sha256": {".config": "f" * 64},
                },
            },
            "modules": pair,
            "debugctl_applied": False,
            "modpost_passed": True,
        }
        self.receipt = self.root / "host-build.json"
        self.receipt.write_text(json.dumps(self.build))
        self.expected = {
            "schema": 1,
            "id": "test-profile",
            "source": {
                "repository": "https://example.invalid/linux.git",
                "commit": "a" * 40,
                "baseline_commit": "b" * 40,
                "upstream_commit": "e" * 40,
            },
            "target": {
                "profile": "tools/profiles/test/profile.json",
                "profile_sha256": "c" * 64,
                "prepared_tree_sha256": "d" * 64,
                "kernel_image_sha256": "1" * 64,
                **self.build["prepared"]["target"],
            },
            "build_evidence_sha256": digest(self.receipt.read_bytes()),
            "modules": ["kvm.ko", "kvm-pvm.ko"],
            "debugctl_applied": False,
        }
        self.marker = {
            "schema": 1,
            "isolation": "disposable-l1",
            "kernel_release": "test-kernel",
            "kernel_sha256": "1" * 64,
            "host_source": "a" * 40,
            "host_baseline": "b" * 40,
            "modules": pair.copy(),
            "debugctl_applied": False,
            "outer_network": "none",
            "cpu_quota": 2,
            "memory_gib": 10,
            "lab_id": "owned-fixture",
        }

    def validate(self):
        return guard.validate_host_profile(
            self.marker, self.expected, self.receipt, self.modules,
            machine="x86_64", kernel="test-kernel",
        )

    def rejected(self, text):
        with self.assertRaisesRegex(SystemExit, text), patch.object(guard, "probe") as probe:
            self.validate()
        probe.assert_not_called()

    def test_matching_profile_and_original_build_receipt(self):
        self.validate()

    def test_marker_source_cannot_replace_expected_source(self):
        self.marker["host_source"] = "0" * 40
        self.rejected("host source")

    def test_updated_pin_rejects_stale_build(self):
        self.expected["source"]["commit"] = "9" * 40
        self.marker["host_source"] = "9" * 40
        self.rejected("build source")

    def test_stale_baseline_is_rejected(self):
        self.marker["host_baseline"] = "0" * 40
        self.rejected("baseline")

    def test_wrong_kernel_image_is_rejected(self):
        self.marker["kernel_sha256"] = "0" * 64
        self.rejected("kernel image")

    def test_wrong_running_kernel_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "running kernel"):
            guard.validate_host_profile(self.marker, self.expected, self.receipt, self.modules,
                                        machine="x86_64", kernel="old-kernel")

    def test_stale_target_profile_is_rejected(self):
        self.expected["target"]["profile_sha256"] = "0" * 64
        self.rejected("target profile")

    def test_stale_prepared_tree_is_rejected(self):
        self.expected["target"]["prepared_tree_sha256"] = "0" * 64
        self.rejected("prepared tree")

    def test_changed_build_evidence_is_rejected(self):
        self.receipt.write_text(json.dumps(self.build) + "\n")
        self.rejected("build evidence checksum")

    def test_failed_modpost_is_rejected_even_with_matching_receipt_digest(self):
        self.build["modpost_passed"] = False
        self.receipt.write_text(json.dumps(self.build))
        self.expected["build_evidence_sha256"] = digest(self.receipt.read_bytes())
        self.rejected("modpost")

    def test_unsupported_build_receipt_schema(self):
        self.build["schema"] = 2
        self.receipt.write_text(json.dumps(self.build))
        self.expected["build_evidence_sha256"] = digest(self.receipt.read_bytes())
        self.rejected("build evidence schema")

    def test_marker_and_file_cannot_self_authorize_wrong_module(self):
        data = b"another core"
        (self.modules / "kvm.ko").write_bytes(data)
        self.marker["modules"]["kvm.ko"] = digest(data)
        self.rejected("module pair")

    def test_missing_module_file_is_rejected(self):
        (self.modules / "kvm-pvm.ko").unlink()
        self.rejected("missing module")

    def test_missing_pair_in_marker_is_rejected(self):
        del self.marker["modules"]["kvm-pvm.ko"]
        self.rejected("complete module pair")

    def test_extra_module_path_is_rejected(self):
        self.marker["modules"]["../kvm.ko"] = "0" * 64
        self.rejected("complete module pair")

    def test_debugctl_variant_is_rejected(self):
        self.marker["debugctl_applied"] = True
        self.rejected("DEBUGCTL")

    def test_expected_profile_is_required_before_reading_l1_or_probing(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(guard, "probe") as probe:
            with self.assertRaises(SystemExit) as error:
                guard.main([])
        self.assertEqual(error.exception.code, 2)
        probe.assert_not_called()

    def test_cleanup_boundary_mode_cannot_be_used_for_a_probe(self):
        with self.assertRaises(SystemExit) as error:
            guard.main(["--boundary-only", "--probe"])
        self.assertEqual(error.exception.code, 2)


class FixtureTest(unittest.TestCase):
    def setUp(self):
        self.expected = {"schema": 1, "registry_container": "review-registry",
                         "registry_port": 5000, "http_port": 18090, "http_path": "/health.txt",
                         "images": {"oci": "pvm/sdk@sha256:" + "a" * 64,
                                    "nydus": "pvm/sdk@sha256:" + "b" * 64,
                                    "runtime_oci": "pvm/redis@sha256:" + "c" * 64}}
        self.actual = {key: "fixture.test:5000/" + value
                       for key, value in self.expected["images"].items()}
        self.actual.update(registry_container="review-registry",
                           network_url="http://fixture.test:18090/health.txt")

    def test_matching_immutable_fixtures(self):
        guard.validate_fixtures(self.actual, self.expected)

    def test_wrong_fixture_digest(self):
        self.actual["nydus"] = self.actual["oci"]
        with self.assertRaisesRegex(SystemExit, "image pin"):
            guard.validate_fixtures(self.actual, self.expected)

    def test_mutable_fixture_tag(self):
        self.actual["oci"] = "fixture.test:5000/pvm/sdk:latest"
        with self.assertRaisesRegex(SystemExit, "image pin"):
            guard.validate_fixtures(self.actual, self.expected)

    def test_mixed_registry_hosts(self):
        self.actual["oci"] = self.actual["oci"].replace("fixture.test", "other.test")
        with self.assertRaisesRegex(SystemExit, "one owned registry"):
            guard.validate_fixtures(self.actual, self.expected)

    def test_network_fixture_must_belong_to_the_registry_host(self):
        self.actual["network_url"] = "http://other.test:18090/health.txt"
        with self.assertRaisesRegex(SystemExit, "network fixture"):
            guard.validate_fixtures(self.actual, self.expected)


if __name__ == "__main__":
    unittest.main()
