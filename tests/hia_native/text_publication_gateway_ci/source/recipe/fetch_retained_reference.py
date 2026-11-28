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
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]), mode="r:gz") as tar:
        for member in tar:
            require(member.isfile() and member.name in wanted and member.name not in seen, "failure member type or set differs")
            row = wanted[member.name]
            relative = Path(member.name)
            require(not relative.is_absolute() and ".." not in relative.parts and relative.as_posix() == member.name, "archive path is not contained")
            destination = a.output / "extracted" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as stream, destination.open("xb") as saved:
                digest_object = hashlib.sha256()
                while block := stream.read(1 << 20):
                    digest_object.update(block)
                    saved.write(block)
                digest = digest_object.hexdigest()
            destination.chmod(member.mode)
            require(member.size == row["bytes"] and member.mode == row["mode"] and digest == row["sha256"], "failure complete member differs")
            seen.add(member.name)
    require(seen == set(wanted) and sum(r["bytes"] for r in wanted.values()) == 1093156671, "failure archive omitted bytes")
    for name, value in data.items():
        (a.output / name).write_bytes(value)
    out = {"status": "COMPLETE_UPLOADED_BUILD_ARCHIVE_BYTES_PASS", "source_commit": "e5fd94b853ee4a32022a67b690854c4d1a3fca29",
        "run": 44032621165, "job": 133867911842, "files": 10564, "logical_bytes": 1093156671,
        "zip": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "archive": identity,
        "executed_hia": False, "executed_rust": False}
    (a.output / "REVIEW.json").write_text(json.dumps(out, sort_keys=True, indent=2) + "\n")
    outer_capture = a.output / "extracted/capture"
    capture = outer_capture / "frozen-graph/extracted/capture"
    source = capture / "composition/source"
    build = capture / "native-build"
    metadata = json.loads((build / "build/publisher-private/manifest.json").read_bytes())
    binary = build / "build/publisher-private" / metadata["elf"]
    require(len(binary.read_bytes()) == 24768512 and hashlib.sha256(binary.read_bytes()).hexdigest() == "4e2708e0ac1a844943dc767570d904a35428ffba2136fb87322e69ce1e569bfb", "actual116 ELF differs")
    require(metadata["physical_images"] == 109 and metadata["runtime_hia_images"] == 116 and len(metadata["members"]) == 108, "graph count differs")
    binding = json.loads((source / "native/runtime_mcp_sources.json").read_bytes())
    require(hashlib.sha256((source / "native/runtime_mcp_sources.json").read_bytes()).hexdigest() == "3f2073e5bc48b196ae2a0f3b56cf6d019cdd94fed1df5c73d31e6b89ec65a14b", "graph source binding differs")
    for name,pin in binding["sources"].items():
        contents=(source/name).read_bytes()
        require(pin == dict(bytes=len(contents),sha256=hashlib.sha256(contents).hexdigest()), "graph source differs")
    wide = None
    for row in metadata["members"]:
        require(row["fresh_compile"] is True, "not a fresh same-build HIA leaf")
        old = Path(row["manifest"])
        relative = old.relative_to("/home/runner/work/_temp/text-publication-graph/native-build")
        manifest = build / relative
        require(hashlib.sha256(manifest.read_bytes()).hexdigest() == row["manifest_sha256"], "leaf manifest differs")
        leaf=json.loads(manifest.read_bytes())
        require((manifest.parent/leaf["source"]).read_bytes() == (source/row["source"]).read_bytes(), "compiled source differs")
        image=(manifest.parent/leaf["image"]).read_bytes()
        require(len(image)==row["image_bytes"] and hashlib.sha256(image).hexdigest()==row["image_sha256"]==leaf["image_sha256"], "leaf image differs")
        if row["name"]=="wide_value":
            require(wide is None, "duplicate Value leaf")
            wide=dict(manifest=str(manifest),manifest_sha256=row["manifest_sha256"])
    require(wide is not None, "missing actual Value leaf")
    deps=dict(source=str(source),manifest=str(build/"build/publisher-private/manifest.json"),
        binary=str(binary),binary_bytes=24768512,binary_sha256="4e2708e0ac1a844943dc767570d904a35428ffba2136fb87322e69ce1e569bfb",
        serde_json_span=wide,graph_source_files=len(binding["sources"])+1,physical_images=109,runtime_hia_images=116,
        reused_frozen_build=True,graph_build_run=44030741825)
    original_build=outer_capture/"original-build"
    original=json.loads((original_build/"BUILD.json").read_bytes())
    require(original["status"]=="FRESH_CURRENT_GATEWAY_REFERENCE_BUILD_PASS" and original["registry_crates"]==86
        and original["source_files"]==41,"retained fresh original build differs")
    original_binary=original_build/"target/release/hepta-text-editor-gateway-local-original-oracle"
    require(original_binary.stat().st_size==4237776 and hashlib.sha256(original_binary.read_bytes()).hexdigest()
        =="061c2fa34f5ceb5f2163d439e2b4e33db7f5995fa2d4c6676b254b5a23aaf7ab","retained original binary differs")
    current_reference=Path(__file__).resolve().parents[1]/"reference"
    retained_reference=a.output/"extracted/recipe-source/reference"
    names={p.relative_to(current_reference).as_posix() for p in current_reference.rglob("*") if p.is_file()}
    require(names=={p.relative_to(retained_reference).as_posix() for p in retained_reference.rglob("*") if p.is_file()},
        "actual compiled original source set changed")
    for name in names:
        require((current_reference/name).read_bytes()==(retained_reference/name).read_bytes(),
            "actual compiled original source bytes changed")
    deps.update(original_build=str(original_build),original_binary=str(original_binary),
        retained_absent=str(outer_capture/"profiles/absent"),retained_original_source_commit="e5fd94b853ee4a32022a67b690854c4d1a3fca29",
        retained_original_fresh_build_run=44032621165,reference_recompiled=False)
    (a.output / "DEPENDENCIES.json").write_text(json.dumps(deps,sort_keys=True,indent=2)+"\n")
    print(json.dumps(out, sort_keys=True))

if __name__ == "__main__":
    main()
