#!/usr/bin/env python3
"""Resolve maintainer-dispatched PVM qualification inputs before assigning an L1."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request


def require(ok, message):
    if not ok:
        raise ValueError(message)


def api(path):
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    with urllib.request.urlopen(urllib.request.Request("https://api.github.com/" + path,
                                                     headers=headers), timeout=30) as response:
        return json.load(response)


def resolve_ref(repository, ref, branch, get=api):
    """Allow a maintained branch or an open PR targeting that branch."""
    if ref in (branch, "refs/heads/" + branch):
        result = get(f"repos/{repository}/commits/{branch}")["sha"]
    else:
        match = re.fullmatch(r"refs/pull/([1-9][0-9]*)/head", ref)
        require(match is not None, "qualification ref must be the maintained branch or refs/pull/N/head")
        pr = get(f"repos/{repository}/pulls/{match[1]}")
        require(pr["state"] == "open" and pr["base"]["ref"] == branch
                and pr["base"]["repo"]["full_name"] == repository,
                "qualification PR must be open and target the maintained branch")
        result = pr["head"]["sha"]
    require(re.fullmatch(r"[0-9a-f]{40}", result), "invalid resolved qualification SHA")
    return result


def resolve_request(kind, repository, workflow_ref, workflow_sha, source_ref, profile_ref, get=api):
    canonical = "inclusionAI/" + ("sandboxd" if kind == "runtime" else "AKernel")
    branch = "main" if kind == "runtime" else "develop"
    require(repository == canonical or get(f"repos/{repository}").get("parent", {}).get("full_name") == canonical,
            "qualification repository must be upstream or its fork")
    if repository == canonical:
        require(workflow_ref == "refs/heads/" + branch,
                "upstream dispatch must use the maintained workflow branch")
    if source_ref:
        source_sha = resolve_ref(repository, source_ref, branch, get)
    else:
        require(re.fullmatch(r"[0-9a-f]{40}", workflow_sha), "invalid dispatch SHA")
        source_sha = workflow_sha
    profile_repository = "inclusionAI/AKernel" if kind == "runtime" else repository
    profile_sha = resolve_ref(profile_repository, profile_ref, "develop", get) if kind == "runtime" else source_sha
    file = get(f"repos/{profile_repository}/contents/deploy/pvm/host-profile.json?ref={profile_sha}")
    require(file["encoding"] == "base64", "unsupported host profile encoding")
    data = base64.b64decode(file["content"], validate=False)
    require(json.loads(data)["schema"] == 1, "unsupported host profile schema")
    return {"source_sha": source_sha, "profile_repository": profile_repository,
            "profile_sha": profile_sha, "profile_digest": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("runtime", "adx"), required=True)
    args = parser.parse_args()
    require(os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch", "manual qualification dispatch required")
    resolved = resolve_request(args.kind, os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_REF"],
                               os.environ["GITHUB_SHA"], os.environ.get("PVM_SOURCE_REF", ""),
                               os.environ.get("PVM_HOST_PROFILE_REF", "develop"))
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        for key, value in resolved.items():
            stream.write(f"{key}={value}\n")
    print(json.dumps(resolved))


if __name__ == "__main__":
    main()
