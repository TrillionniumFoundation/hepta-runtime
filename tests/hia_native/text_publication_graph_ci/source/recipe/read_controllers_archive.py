#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every byte of the complete successful controller-build artifact."""
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
    url = "https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14307710562/zip"
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
    require(len(raw) == 20316942 and hashlib.sha256(raw).hexdigest() == "95286e31ab9dd42746c83d2a7ef9d3025f39a1506b6ec62990b23eb0ad40559f", "complete build ZIP differs")
    (a.output / "artifact.zip").write_bytes(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(set(z.namelist()) == {"evidence.tar.gz", "FILES.json", "ARCHIVE.json"}
            and len(z.namelist()) == 3 and z.testzip() is None, "build ZIP member inventory differs")
        data = {name: z.read(name) for name in z.namelist()}
    index = json.loads(data["FILES.json"])
    receipt = json.loads(data["ARCHIVE.json"])
    identity = {"bytes": 20063018, "sha256": "f0030c8785910d7190250ccc074c7214fb73cc678bdd0494b6635fbfbc309871"}
    require(receipt["archive"] == identity and len(data["evidence.tar.gz"]) == identity["bytes"]
        and hashlib.sha256(data["evidence.tar.gz"]).hexdigest() == identity["sha256"], "complete build TAR differs")
    wanted = {row["path"]: row for row in index["files"]}
    require(len(wanted) == len(index["files"]) == 1188, "build manifest cardinality differs")
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]), mode="r:gz") as tar:
        for member in tar:
            require(member.isfile() and member.name in wanted and member.name not in seen, "build member type or set differs")
            row = wanted[member.name]
            with tar.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            require(member.size == row["bytes"] and member.mode == row["mode"] and digest == row["sha256"], "build complete member differs")
            seen.add(member.name)
    require(seen == set(wanted) and sum(r["bytes"] for r in wanted.values()) == 57336474, "build archive omitted bytes")
    for name, value in data.items():
        (a.output / name).write_bytes(value)
    out = {"status": "COMPLETE_UPLOADED_BUILD_ARCHIVE_BYTES_PASS", "source_commit": "341c35fa0436da44016d38bcc5e15108d767ab83",
        "run": 44036227398, "job": 133879629258, "files": 1188, "logical_bytes": 57336474,
        "zip": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "archive": identity,
        "executed_hia": False, "executed_rust": False}
    (a.output / "REVIEW.json").write_text(json.dumps(out, sort_keys=True, indent=2) + "\n")
    print(json.dumps(out, sort_keys=True))

if __name__ == "__main__":
    main()
