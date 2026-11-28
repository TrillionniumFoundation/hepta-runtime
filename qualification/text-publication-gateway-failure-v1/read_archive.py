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
    url = "https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14306460111/zip"
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
    require(len(raw) == 526222923 and hashlib.sha256(raw).hexdigest() == "ea13efa1039c2a4b784c2335cc1306120ccb115060e657b172a53519359376ef", "complete failure ZIP differs")
    (a.output / "artifact.zip").write_bytes(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(set(z.namelist()) == {"evidence.tar.gz", "FILES.json", "ARCHIVE.json"}
            and len(z.namelist()) == 3 and z.testzip() is None, "failure ZIP member inventory differs")
        data = {name: z.read(name) for name in z.namelist()}
    index = json.loads(data["FILES.json"])
    receipt = json.loads(data["ARCHIVE.json"])
    identity = {"bytes": 523605142, "sha256": "8c1c59c962134d53c229c3c3c051ddf036629d19b57960eee815c6812062fc23"}
    require(receipt["archive"] == identity and len(data["evidence.tar.gz"]) == identity["bytes"]
        and hashlib.sha256(data["evidence.tar.gz"]).hexdigest() == identity["sha256"], "complete failure TAR differs")
    wanted = {row["path"]: row for row in index["files"]}
    require(len(wanted) == len(index["files"]) == 10564, "failure manifest cardinality differs")
    seen = set()
    selected = {}
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]), mode="r:gz") as tar:
        for member in tar:
            require(member.isfile() and member.name in wanted and member.name not in seen, "failure member type or set differs")
            row = wanted[member.name]
            with tar.extractfile(member) as stream:
                if member.name.startswith("capture/profiles/") and member.name.endswith(("/PROCESS.json","/CAPTURE.json","/stderr","/records.jsonl")):
                    value=stream.read()
                    selected[member.name]=value
                    digest=hashlib.sha256(value).hexdigest()
                else:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
            require(member.size == row["bytes"] and member.mode == row["mode"] and digest == row["sha256"], "failure complete member differs")
            seen.add(member.name)
    require(seen == set(wanted) and sum(r["bytes"] for r in wanted.values()) == 1093156671, "failure archive omitted bytes")
    for name, value in data.items():
        (a.output / name).write_bytes(value)
    out = {"status": "COMPLETE_UPLOADED_BUILD_ARCHIVE_BYTES_PASS", "source_commit": "cd170dc41cb2dbefdd2a9eb4e0e888a7c708ba87",
        "run": 44032621165, "job": 133867911842, "files": 10564, "logical_bytes": 1093156671,
        "zip": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "archive": identity,
        "executed_hia": False, "executed_rust": False}
    (a.output / "REVIEW.json").write_text(json.dumps(out, sort_keys=True, indent=2) + "\n")
    out["source_commit"]="e5fd94b853ee4a32022a67b690854c4d1a3fca29"
    out["status"]="COMPLETE_FAILED_GATEWAY_ARTIFACT_BYTES_PASS"
    (a.output/"REVIEW.json").write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    diagnosis=[]
    for name,value in sorted(selected.items()):
        if name.endswith("/stderr"):
            diagnosis.append(dict(path=name,bytes=len(value),text=value.decode(errors="replace")))
        elif name.endswith("/PROCESS.json") or name.endswith("/CAPTURE.json"):
            row=json.loads(value)
            diagnosis.append(dict(path=name,value={k:v for k,v in row.items() if k not in ("source_dependencies",)}))
        elif name.endswith("/records.jsonl"):
            rows=[json.loads(line) for line in value.splitlines()]
            diagnosis.append(dict(path=name,rows=len(rows),
                first_input=rows[0]["input"] if rows else None,last_input=rows[-1]["input"] if rows else None))
    (a.output/"DIAGNOSTIC.json").write_text(json.dumps(diagnosis,sort_keys=True,indent=2)+"\n")
    print("GATEWAY_FAILURE_DIAGNOSTIC="+json.dumps(diagnosis,sort_keys=True))
    print(json.dumps(out,sort_keys=True))

if __name__ == "__main__":
    main()
