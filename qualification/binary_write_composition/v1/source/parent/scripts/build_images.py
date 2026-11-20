#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh image compilation using an exact copied actual development B3."""
import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dependency/scripts"))
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild
from evidence_common import source_evidence

B3 = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
MEMBERS = (
    ("parent", "native/binary_parent_owner.hepta"),
    ("body", "dependency/native/binary_write_body.hepta"),
    ("metadata", "dependency/native/file_metadata.hepta"),
    ("codec", "dependency/native/binary_codec.hepta"),
    ("stat", "dependency/native/stat_version.hepta"),
    ("error", "dependency/native/path_error.hepta"),
    ("publish", "dependency/native/publish_at.hepta"),
    ("read", "dependency/native/binary_read_body.hepta"),
    ("base64", "dependency/native/binary_base64_decode.hepta"),
    ("entropy", "dependency/native/binary_entropy.hepta"),
    ("linker", "compiler/elf_static_linker.hepta"),
    ("packer", "dependency/native/runtime_mcp_image_packer.hepta"),
)


def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("bootstrap symlink")
        mode = path.stat().st_mode
        if stat.S_ISREG(mode):
            result[path.relative_to(root).as_posix()] = dict(**pin(path), mode=stat.S_IMODE(mode))
        elif not stat.S_ISDIR(mode):
            raise ValueError("bootstrap special file")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--retained-bootstrap", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--parent-only", action="store_true")
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists():
        raise ValueError("fresh build directory required")
    output.mkdir(parents=True)
    source_identity=source_evidence(ROOT)
    start = time.monotonic_ns()
    native = NativeBuild(args.hepta, output / "build")
    if native.identity!=json.loads((ROOT/"COMPILER_INPUT.json").read_bytes()):
        raise ValueError("full frozen compiler source identity differs")
    retained = args.retained_bootstrap.resolve(strict=True)
    receipt = json.loads((retained / "bootstrap.json").read_bytes())
    if (receipt["schema"] != "hepta.runtime.native-bootstrap.v1"
            or receipt["dependency"] != native.identity
            or receipt["qualification"] != "development_fixed_point"
            or receipt["generation_sha256"] != B3):
        raise ValueError("retained real B3 dependency receipt differs")
    before = inventory(retained)
    target = output / "build/bootstrap"
    shutil.copytree(retained, target, copy_function=shutil.copy2)
    if inventory(target) != before:
        raise ValueError("complete copied bootstrap bytes or modes differ")
    compiler = native.bootstrap()
    if pin(compiler)["sha256"] != B3:
        raise ValueError("actual copied B3 differs")
    reauthors=[]
    commands=(
        ("hia-author",[sys.executable,"-I","-S","-B",ROOT/"authoring/author_binary_parent_owner.py",
                       "--source",ROOT,"--hepta",args.hepta.resolve(strict=True),"--output",output/"authored"],
         ("binary_parent_owner.hepta","binary_parent_owner_composition.json","binary_parent_owner.pseudo"),"authored","native"),
        ("fixture-author",[sys.executable,"-I","-S","-B",ROOT/"authoring/author_native_fixture.py",
                           "--source",ROOT,"--output",output/"fixture-authored"],
         ("binary_parent_owner_fixture.S","binary_parent_owner_fixture_edits.json"),"fixture-authored",None),
    )
    for label,argv,names,folder,destination in commands:
        began=time.monotonic_ns()
        with (output/(label+".stdout")).open("xb")as out,(output/(label+".stderr")).open("xb")as err:
            child=subprocess.run([str(x)for x in argv],stdout=out,stderr=err,timeout=30,check=False)
        row=dict(argv=[str(x)for x in argv],returncode=child.returncode,elapsed_ns=time.monotonic_ns()-began,limit_seconds=30,
                 stdout=pin(output/(label+".stdout")),stderr=pin(output/(label+".stderr")))
        (output/(label+".json")).write_text(json.dumps(row,sort_keys=True,indent=2)+"\n")
        if child.returncode!=0 or row["stderr"]["bytes"]!=0:
            raise ValueError("source author did not complete exactly: "+label)
        for name in names:
            suffix=destination or ("asm"if name.endswith(".S")else"native")
            if (output/folder/name).read_bytes()!=(ROOT/suffix/name).read_bytes():
                raise ValueError("complete frozen source author output differs: "+name)
        reauthors.append(row)
    members = {}
    for name, path in MEMBERS[:1] if args.parent_only else MEMBERS:
        manifest = native.compile("binary-parent-" + name, ROOT / path, standalone=None, buffer_profile="history.v1")
        meta = json.loads(manifest.read_bytes())
        members[name] = dict(source_path=path, source=pin(ROOT / path), manifest=manifest.relative_to(output).as_posix(),
                             identity=pin(manifest), image=pin(manifest.parent / meta["image"]))
        print(json.dumps(dict(compiled=name, image=members[name]["image"]), sort_keys=True), flush=True)
    native._recheck()
    if inventory(retained) != before or inventory(target) != before:
        raise ValueError("complete retained/copy B3 changed during compilation")
    copied=output/"compiler-source"
    copied.mkdir()
    for name,digest in native.identity["files"].items():
        origin=args.hepta.resolve(strict=True)/name
        target_path=copied/name
        target_path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(origin,target_path)
        if pin(target_path)["sha256"]!=digest:
            raise ValueError("complete copied compiler source differs")
    native._recheck()
    if source_evidence(ROOT)!=source_identity:
        raise ValueError("whole frozen source changed during compilation")
    result = dict(schema="hepta.runtime.binary-parent-images.v1", status="FRESH_ACTUAL_B3_COMPILE_PASS",
                  source=source_identity,reauthors=reauthors,
                  compiler=native.identity, compiler_image=pin(compiler), members=members,
                  retained_bootstrap=before, elapsed_ns=time.monotonic_ns() - start,
                  new_seed_executions=0, new_bootstrap_generations=0,
                  application_executions=0, qualification="development_fixed_point",
                  public_binary_write_registered=False, whole_runtime_replaced=False)
    (output / "IMAGES.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
