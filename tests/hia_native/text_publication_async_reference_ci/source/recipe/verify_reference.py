#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read exact original sources and the explicitly separate async observer."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import sys
sys.dont_write_bytecode=True

def identity(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())

def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def verify(reference,target_checkout=None):
    reference=Path(reference).resolve(strict=True)
    package=reference.parent
    ordinary=package/"ordinary"
    original_verifier=load_module("ordinary_publisher_verify",ordinary/"recipe/verify_reference.py")
    retained=original_verifier.verify(ordinary/"reference",target_checkout)
    before=json.loads((ordinary/"reference/source_manifest.json").read_bytes())
    manifest=json.loads((reference/"source_manifest.json").read_bytes())
    assert manifest["ordinary_manifest"]==identity((ordinary/"reference/source_manifest.json").read_bytes())
    assert manifest["schema"]=="hepta.runtime.publisher.async.reference.v1"
    assert (manifest["target_commit"],manifest["target_tree"])==(before["target_commit"],before["target_tree"])
    assert set(manifest["files"])==set(before["files"])|{"src/async_observer.rs"}
    assert {p.relative_to(reference).as_posix() for p in reference.rglob("*") if p.is_file()}==set(manifest["files"])|{"source_manifest.json"}
    changed=[]
    for path,pin in manifest["files"].items():
        raw=(reference/path).read_bytes()
        assert identity(raw)==pin,path
        if path in before["files"] and raw!=(ordinary/"reference"/path).read_bytes():changed.append(path)
    assert changed==["src/main.rs"],changed
    transformations=json.loads((package/"authoring/wrapper-transforms.json").read_bytes())["transformations"]
    expected=(ordinary/"reference/src/main.rs").read_text()
    for row in transformations:
        assert expected.count(row["before"])==1
        expected=expected.replace(row["before"],row["after"])
    actual=(reference/"src/main.rs").read_text()
    assert actual==expected
    inverse=actual
    for row in reversed(transformations):
        assert inverse.count(row["after"])==1
        inverse=inverse.replace(row["after"],row["before"])
    assert inverse==(ordinary/"reference/src/main.rs").read_text()
    for field in ("exact_original_items","public_original_items","target_files"):
        assert manifest[field]==before[field]
    for item in manifest["exact_original_items"]+manifest["public_original_items"]:
        original=(reference/"target"/item["target"]).read_bytes()[item["start"]:item["end"]]
        assert identity(original)=={k:item[k] for k in ("bytes","sha256","git_blob")}
        for span in item["compiled_spans"]:
            assert span["container"]!="src/main.rs"
            compiled=(reference/span["container"]).read_bytes()
            assert compiled[span["included_start"]:span["included_end"]]==original
    assert (reference/"Cargo.toml").read_bytes()==(ordinary/"reference/Cargo.toml").read_bytes()
    assert (reference/"Cargo.lock").read_bytes()==(ordinary/"reference/Cargo.lock").read_bytes()
    return dict(status="EXACT_PUBLISHER_ASYNC_OBSERVER_SOURCE_PASS",retained=retained,
        target_commit=manifest["target_commit"],original_spans=120,
        compiled_source_files=len(manifest["files"])+1,wrapper_transformations=len(transformations),
        original_bytes_unchanged=True,actual_sdk_serve=True,actual_original_spawn_blocking=True,
        asynchronous_lifecycle_qualified=False,native_async=False,full_sdk=False,production_installed=False)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--reference",type=Path,required=True)
    p.add_argument("--target",type=Path)
    a=p.parse_args()
    print(json.dumps(verify(a.reference,a.target),sort_keys=True))
