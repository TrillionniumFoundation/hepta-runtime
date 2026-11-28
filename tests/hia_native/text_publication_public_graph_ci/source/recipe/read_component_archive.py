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
    url = "https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14310377461/zip"
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
    require(len(raw) == 14865522 and hashlib.sha256(raw).hexdigest() == "1aa68b24923744910e0ceee2d44e9282a0acc3f341636fe2f2c60209cfec7cba", "complete build ZIP differs")
    (a.output / "artifact.zip").write_bytes(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(set(z.namelist()) == {"evidence.tar.gz", "FILES.json", "ARCHIVE.json"}
            and len(z.namelist()) == 3 and z.testzip() is None, "build ZIP member inventory differs")
        data = {name: z.read(name) for name in z.namelist()}
    index = json.loads(data["FILES.json"])
    receipt = json.loads(data["ARCHIVE.json"])
    identity = {"bytes": 14616681, "sha256": "38de392d8eb5d5b3bf8b61faeecc594d06ae5acd57d8f31be5b4a4106a496bbf"}
    require(receipt["archive"] == identity and len(data["evidence.tar.gz"]) == identity["bytes"]
        and hashlib.sha256(data["evidence.tar.gz"]).hexdigest() == identity["sha256"], "complete build TAR differs")
    wanted = {row["path"]: row for row in index["files"]}
    require(len(wanted) == len(index["files"]) == 1162, "build manifest cardinality differs")
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]), mode="r:gz") as tar:
        for member in tar:
            require(member.isfile() and member.name in wanted and member.name not in seen, "build member type or set differs")
            row = wanted[member.name]
            with tar.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            require(member.size == row["bytes"] and member.mode == row["mode"] and digest == row["sha256"], "build complete member differs")
            seen.add(member.name)
    require(seen == set(wanted) and sum(r["bytes"] for r in wanted.values()) == 53069318, "build archive omitted bytes")
    for name, value in data.items():
        (a.output / name).write_bytes(value)
    out = {"status": "COMPLETE_UPLOADED_BUILD_ARCHIVE_BYTES_PASS", "source_commit": "f6828b79dc184acd9dc873156bba322209d24235",
        "run": 44043871190, "job": 133904676721, "files": 1162, "logical_bytes": 53069318,
        "zip": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "archive": identity,
        "executed_hia": False, "executed_rust": False}
    (a.output / "REVIEW.json").write_text(json.dumps(out, sort_keys=True, indent=2) + "\n")
    print(json.dumps(out, sort_keys=True))

if __name__ == "__main__":
    main()
