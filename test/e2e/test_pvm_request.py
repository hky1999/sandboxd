#!/usr/bin/env python3
"""Allowed-ref and immutable-input regressions, without network or a runner."""
import base64
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("pvm_request", Path(__file__).with_name("pvm-request.py"))
request = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(request)


class RequestTest(unittest.TestCase):
    def get(self, path):
        if "/contents/" in path:
            return {"encoding": "base64", "content": base64.b64encode(json.dumps({"schema": 1}).encode()).decode()}
        if "/commits/" in path:
            return {"sha": "a" * 40}
        if "/pulls/" in path:
            return {"state": "open", "base": {"ref": "develop", "repo": {"full_name": "inclusionAI/AKernel"}}, "head": {"sha": "b" * 40}}
        return {"parent": {"full_name": "inclusionAI/sandboxd"}}

    def test_upstream_defaults_to_exact_dispatch_sha(self):
        result = request.resolve_request("runtime", "inclusionAI/sandboxd", "refs/heads/main", "c" * 40, "", "develop", self.get)
        self.assertEqual(result["source_sha"], "c" * 40)
        self.assertEqual(result["profile_sha"], "a" * 40)

    def test_profile_can_be_qualified_from_consumer_pr_before_merge(self):
        result = request.resolve_request("runtime", "inclusionAI/sandboxd", "refs/heads/main", "c" * 40, "", "refs/pull/104/head", self.get)
        self.assertEqual(result["profile_sha"], "b" * 40)

    def test_upstream_rejects_a_workflow_from_an_unreviewed_branch(self):
        with self.assertRaisesRegex(ValueError, "maintained workflow"):
            request.resolve_request("runtime", "inclusionAI/sandboxd", "refs/heads/other", "c" * 40, "", "develop", self.get)

    def test_fork_qualification_uses_exact_dispatch_sha(self):
        result = request.resolve_request("runtime", "owner/sandboxd", "refs/heads/feature", "c" * 40, "", "develop", self.get)
        self.assertEqual(result["source_sha"], "c" * 40)

    def test_arbitrary_ref_or_sha_cannot_replace_an_allowed_ref(self):
        for ref in ("other", "refs/heads/other", "d" * 40, "refs/tags/v1", "refs/pull/1/merge"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                request.resolve_ref("inclusionAI/AKernel", ref, "develop", self.get)

    def test_closed_pr_is_rejected(self):
        def closed(path):
            result = self.get(path)
            result["state"] = "closed"
            return result
        with self.assertRaisesRegex(ValueError, "must be open"):
            request.resolve_ref("inclusionAI/AKernel", "refs/pull/104/head", "develop", closed)

    def test_adx_uses_its_own_committed_profile(self):
        result = request.resolve_request("adx", "inclusionAI/AKernel", "refs/heads/develop", "c" * 40, "", "ignored", self.get)
        self.assertEqual(result["profile_sha"], result["source_sha"])

    def test_pr_targeting_another_branch_is_rejected(self):
        def wrong_base(path):
            result = self.get(path)
            result["base"]["ref"] = "main"
            return result
        with self.assertRaisesRegex(ValueError, "maintained branch"):
            request.resolve_ref("inclusionAI/AKernel", "refs/pull/104/head", "develop", wrong_base)

    def test_unrelated_repository_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "upstream or its fork"):
            request.resolve_request("adx", "unrelated/repository", "refs/heads/feature", "c" * 40,
                                    "", "develop", self.get)

    def test_api_must_return_an_immutable_commit_identity(self):
        with self.assertRaisesRegex(ValueError, "resolved qualification SHA"):
            request.resolve_ref("inclusionAI/AKernel", "develop", "develop", lambda path: {"sha": "develop"})


if __name__ == "__main__":
    unittest.main()
