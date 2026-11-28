#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind every compiled original byte and the complete actual SDK observer."""
from pathlib import Path
import argparse, hashlib, importlib.util, json
EXPECTED_MANIFEST="21d8dff68ac76e41d78dc39f8dd53f4e74073c5cf5d9baf440f131669f11ae92"
TARGET="d3d75c30719db966b004756f610007a7c723729e"
TREE="612e145513961556ac8844b5cc978f9b5175e4d4"
def identity(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def verify(reference,target_checkout=None):
    reference=Path(reference)
    raw=(reference/"source_manifest.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest()==EXPECTED_MANIFEST
    manifest=json.loads(raw)
    assert (manifest["target_commit"],manifest["target_tree"])==(TARGET,TREE)
    actual={p.relative_to(reference).as_posix() for p in reference.rglob("*") if p.is_file()}
    assert actual==set(manifest["files"])|{"source_manifest.json"}
    for name,pin in manifest["files"].items():
        assert identity((reference/name).read_bytes())==pin,name
    for name,pin in manifest["target_files"].items():
        original=(reference/"target"/name).read_bytes()
        assert identity(original)==pin,name
        if target_checkout is not None:
            assert (Path(target_checkout)/name).read_bytes()==original,name
    assert len(manifest["exact_original_items"])==111
    assert len(manifest["public_original_items"])==9
    for item in manifest["exact_original_items"]+manifest["public_original_items"]:
        original=(reference/"target"/item["target"]).read_bytes()[item["start"]:item["end"]]
        assert identity(original)=={k:item[k] for k in ("bytes","sha256","git_blob")}
        assert item["compiled_spans"]
        for span in item["compiled_spans"]:
            assert span["container"].startswith("src/")
            compiled=(reference/span["container"]).read_bytes()
            assert compiled[span["included_start"]:span["included_end"]]==original,item["declaration"]
    base=json.loads((reference.parent/"retained/private-source-manifest.json").read_bytes())
    assert base["exact_original_items"]==manifest["exact_original_items"]
    for name,pin in base["files"].items():
        if name!="src/main.rs":
            assert manifest["files"][name]==pin,name
    raw_tools=(reference/"raw-catalog-input.json").read_bytes()
    assert identity(raw_tools)=={k:manifest["raw_catalog"][k] for k in ("bytes","sha256","git_blob")}
    tools=json.loads(raw_tools)
    assert len(tools)==len({tool["name"] for tool in tools})==136
    assert all(sum(tool["name"]==name for tool in tools)==1 for name in manifest["installed_tools"])
    root=reference.parent
    spec=importlib.util.spec_from_file_location("publisher_public_wrapper",root/"authoring/verify_wrapper.py")
    author=importlib.util.module_from_spec(spec);spec.loader.exec_module(author)
    composed=author.verify(root)
    return dict(status="EXACT_PUBLIC_PUBLISHER_REFERENCE_SOURCE_PASS",target_commit=TARGET,
        target_files=len(manifest["target_files"]),retained_original_items=111,
        added_original_items=9,wrapper=composed,actual_sdk_serve=True,
        public_handler_qualified=False,full_async=False,full_sdk=False,whole_runtime_replaced=False)
if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--reference",required=True,type=Path)
    parser.add_argument("--target",type=Path)
    args=parser.parse_args()
    print(json.dumps(verify(args.reference,args.target),sort_keys=True))
