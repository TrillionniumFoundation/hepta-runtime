#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read immutable complete graph and original-reference artifacts; execute no HIA or Rust."""
from pathlib import Path,PurePosixPath
import argparse
import hashlib
import io
import json
import os
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import require,canonical,decode,pin
import fetch_retained_reference

GRAPH={
  "artifact": 14307238964,
  "commit": "0fe40f84cc3730c60daad86bf645da85712744f4",
  "run": 44037165057,
  "job": 133882707592,
  "zip": {
    "bytes": 141469802,
    "sha256": "0ec6eddedb6e77aae5a7974a3797c60bd257a09374ad4be9d3089edfeabdaf87"
  },
  "archive": {
    "bytes": 140265956,
    "sha256": "e98f62d4a5746235115edc6e5690d602442eeb23feb86f37476091ebf8ad4b96"
  },
  "files": 5164,
  "logical_bytes": 501505272,
  "binding": {
    "bytes": 91761,
    "sha256": "d2c1959a6fcbacd34eae120a84937a900457196ec9864f7e70f11e9154f7b9c8"
  },
  "manifest_sha256": "057b5bcc6f618534209884effa00dd3f72c42e6c24345aa463f91f49539360df",
  "binary": {
    "bytes": 24768512,
    "sha256": "7e2019d78ee18996c7a19f40318c721b5c8797c0c318c91d8fc5a0f3a6f6c396"
  },
  "old_build_root": "/home/runner/work/_temp/text-publication-graph/native-build"
}
def download():
    url="https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(GRAPH["artifact"])+"/zip"
    request=urllib.request.Request(url,headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
        "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:response=urllib.request.build_opener(fetch_retained_reference.NoRedirect()).open(request,timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301,302,303,307,308),"artifact API did not redirect")
        location=error.headers["Location"]
        require(urllib.parse.urlparse(location).scheme=="https","non-HTTPS artifact location")
        response=urllib.request.urlopen(location,timeout=60)
    with response:return response.read()
def graph_read(root):
    root.mkdir()
    raw=download()
    require(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==GRAPH["zip"],"complete new graph ZIP differs")
    (root/"artifact.zip").write_bytes(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(len(z.namelist())==3 and set(z.namelist())=={"evidence.tar.gz","FILES.json","ARCHIVE.json"}
            and z.testzip() is None,"complete new graph ZIP member inventory")
        data={name:z.read(name) for name in z.namelist()}
    index=decode(data["FILES.json"]);receipt=decode(data["ARCHIVE.json"])
    require(receipt["archive"]==GRAPH["archive"] and
        dict(bytes=len(data["evidence.tar.gz"]),sha256=hashlib.sha256(data["evidence.tar.gz"]).hexdigest())==GRAPH["archive"],
        "complete graph TAR identity")
    wanted={r["path"]:r for r in index["files"]}
    require(len(wanted)==len(index["files"])==GRAPH["files"],"graph member cardinality")
    seen=set()
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]),mode="r:gz") as tar:
        for member in tar:
            relative=PurePosixPath(member.name)
            require(member.isfile() and member.name in wanted and member.name not in seen
                and not relative.is_absolute() and ".." not in relative.parts and relative.as_posix()==member.name,
                "graph archive member set/type/path")
            row=wanted[member.name];destination=root/"extracted"/member.name
            destination.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(member) as source,destination.open("xb") as target:
                digest=hashlib.sha256()
                while block:=source.read(1<<20):digest.update(block);target.write(block)
            destination.chmod(member.mode)
            require(member.size==row["bytes"] and member.mode==row["mode"]
                and digest.hexdigest()==row["sha256"],"complete graph member identity")
            seen.add(member.name)
    require(seen==set(wanted) and sum(r["bytes"] for r in wanted.values())==GRAPH["logical_bytes"],
        "complete graph archive coverage")
    for name,value in data.items():(root/name).write_bytes(value)
    capture=root/"extracted/capture";source=capture/"composition/source";build=capture/"native-build"
    report=decode((build/"BUILD.json").read_bytes())
    require(report["status"]=="FRESH_PRIVATE_PUBLISHER116_BUILD_PASS" and report["direct_fresh_hia_images"]==108
        and report["packed_fresh_hia_images"]==8,"fresh graph build evidence")
    binding_path=source/"native/runtime_mcp_sources.json"
    require(pin(binding_path)==GRAPH["binding"],"actual new graph source binding")
    binding=decode(binding_path.read_bytes())
    files={p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    require(files==set(binding["sources"])|{"native/runtime_mcp_sources.json"},"actual new graph source set")
    for name,identity in binding["sources"].items():require(pin(source/name)==identity,"actual graph source: "+name)
    manifest=build/"build/publisher-private/manifest.json"
    require(pin(manifest)["sha256"]==GRAPH["manifest_sha256"]==report["manifest_sha256"],"actual graph manifest")
    metadata=decode(manifest.read_bytes());binary=manifest.parent/metadata["elf"]
    require(pin(binary)==GRAPH["binary"]==dict(bytes=metadata["elf_bytes"],sha256=metadata["elf_sha256"]),
        "actual graph executable identity")
    require(metadata["physical_images"]==109 and metadata["runtime_hia_images"]==116 and len(metadata["members"])==108,
        "actual graph image inventory")
    require(metadata["publication_private_slots"]==[64,65,66,67,68] and metadata["publication_forget_capability"]
        ==dict(slot=68,parent=66,local=6,scope_output_loan=96),"fixed Forget capability binding")
    wide=None
    for row in metadata["members"]:
        require(row["fresh_compile"] is True,"new graph unexpectedly reused a leaf")
        relative=Path(row["manifest"]).relative_to(GRAPH["old_build_root"])
        leaf_path=build/relative
        require(pin(leaf_path)["sha256"]==row["manifest_sha256"],"full compiled leaf manifest")
        leaf=decode(leaf_path.read_bytes())
        require((leaf_path.parent/leaf["source"]).read_bytes()==(source/row["source"]).read_bytes(),
            "compiled leaf source differs")
        identity=pin(leaf_path.parent/leaf["image"])
        require(identity==dict(bytes=row["image_bytes"],sha256=row["image_sha256"])
            and identity["sha256"]==leaf["image_sha256"],"complete actual leaf image")
        if row["name"]=="wide_value":
            require(wide is None,"duplicate Value leaf")
            wide=dict(manifest=str(leaf_path),manifest_sha256=row["manifest_sha256"])
    require(wide is not None,"actual Value leaf missing")
    review=dict(status="COMPLETE_NEW_GRAPH_ARCHIVE_AND_BINDING_PASS",identity=GRAPH,
        hia_executed=False,rust_executed=False)
    (root/"REVIEW.json").write_bytes(canonical(review))
    return dict(source=str(source),manifest=str(manifest),binary=str(binary),binary_bytes=GRAPH["binary"]["bytes"],
        binary_sha256=GRAPH["binary"]["sha256"],serde_json_span=wide,graph_source_files=len(files),
        physical_images=109,runtime_hia_images=116,reused_frozen_build=True,graph_build_run=GRAPH["run"],
        graph_source_commit=GRAPH["commit"],graph_archive_review=str(root/"REVIEW.json"))
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",required=True,type=Path);a=p.parse_args()
    require(not a.output.exists(),"fresh dependency output");a.output.mkdir(parents=True)
    before=sys.argv
    try:
        sys.argv=[before[0],"--output",str(a.output/"retained-reference")]
        fetch_retained_reference.main()
    finally:sys.argv=before
    old=decode((a.output/"retained-reference/DEPENDENCIES.json").read_bytes())
    deps=graph_read(a.output/"new-graph")
    for key in ("original_build","original_binary","retained_original_source_commit",
        "retained_original_fresh_build_run","reference_recompiled"):deps[key]=old[key]
    require(deps["reference_recompiled"] is False,"reference provenance changed")
    (a.output/"DEPENDENCIES.json").write_bytes(canonical(deps))
    print(json.dumps(dict(status="COMPLETE_EXACT_GATEWAY_DEPENDENCIES_PASS",dependencies=deps),sort_keys=True))
if __name__=="__main__":main()
