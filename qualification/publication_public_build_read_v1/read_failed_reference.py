#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every byte of the complete retained failed public-reference artifact."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

def require(value, message):
    if not value:
        raise ValueError(message)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def download():
    url = "https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14312092541/zip"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        response = urllib.request.build_opener(NoRedirect()).open(request, timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301, 302, 303, 307, 308), "artifact API did not redirect")
        location = error.headers["Location"]
        require(urllib.parse.urlparse(location).scheme == "https", "non-HTTPS artifact location")
        response = urllib.request.urlopen(location, timeout=60)
    with response:
        return response.read()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    require(not a.output.exists(), "fresh artifact read output required")
    a.output.mkdir(parents=True)
    raw = download()
    require(len(raw) == 104659685 and hashlib.sha256(raw).hexdigest() == "033ae23c7c021f6c6d6858b87b5f1a54d41f9362bbdd623014a1321bfd83ee71", "complete build ZIP differs")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(set(z.namelist()) == {"evidence.tar.gz", "FILES.json", "ARCHIVE.json"}
            and len(z.namelist()) == 3 and z.testzip() is None, "build ZIP member inventory differs")
        data = {name: z.read(name) for name in z.namelist()}
    index = json.loads(data["FILES.json"])
    receipt = json.loads(data["ARCHIVE.json"])
    identity = {"bytes": 103534599, "sha256": "7f53a8d84797f89a414d84b4c4a20b56ec18fd5079479f56dbbb76ef5ba3c3f8"}
    require(receipt["archive"] == identity and len(data["evidence.tar.gz"]) == identity["bytes"]
        and hashlib.sha256(data["evidence.tar.gz"]).hexdigest() == identity["sha256"], "complete build TAR differs")
    wanted = {row["path"]: row for row in index["files"]}
    require(len(wanted) == len(index["files"]) == 5167, "build manifest cardinality differs")
    seen = set()
    selected = {}
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]), mode="r:gz") as tar:
        for member in tar:
            require(member.isfile() and member.name in wanted and member.name not in seen, "build member type or set differs")
            row = wanted[member.name]
            with tar.extractfile(member) as stream:
                if member.name in ["capture/cargo-build.stderr"]:
                    observed = stream.read()
                    selected[member.name] = observed
                    digest = hashlib.sha256(observed).hexdigest()
                else:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
            require(member.size == row["bytes"] and member.mode == row["mode"] and digest == row["sha256"], "build complete member differs")
            seen.add(member.name)
    require(seen == set(wanted) and sum(r["bytes"] for r in wanted.values()) == 298590987, "build archive omitted bytes")
    require(set(selected) == set(["capture/cargo-build.stderr"]), "selected retained diagnostic missing")
    for name in ("FILES.json", "ARCHIVE.json"):
        (a.output / name).write_bytes(data[name])
    for name, value in selected.items():
        (a.output / name.replace("/", "--")).write_bytes(value)
        print(json.dumps({"selected_path":name,"bytes":len(value),"sha256":hashlib.sha256(value).hexdigest(),"text":value.decode("utf-8")}, sort_keys=True))
    out = {"status": "COMPLETE_RETAINED_FAILURE_ARCHIVE_BYTES_PASS", "source_commit": "5b6e596f619a1613cbc965f16e3e4ed7d2cd36f4",
        "run": 44047628781, "job": 133917177720, "files": 5167, "logical_bytes": 298590987,
        "zip": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "archive": identity,
        "executed_hia": False, "executed_rust": False}
    (a.output / "REVIEW.json").write_text(json.dumps(out, sort_keys=True, indent=2) + "\n")
    print(json.dumps(out, sort_keys=True))

if __name__ == "__main__":
    main()
