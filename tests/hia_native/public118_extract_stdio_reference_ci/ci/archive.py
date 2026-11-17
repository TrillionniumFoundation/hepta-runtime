"""Complete, relocatable success/failure archives with full member readback."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tarfile
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import files, pin, put, require

def safe(name):
    path = PurePosixPath(name)
    require(type(name) is str and name and not path.is_absolute()
            and path.as_posix() == name and all(p not in ("", ".", "..") for p in path.parts),
            "noncanonical archive member")
    return path

def member_pin(stream):
    digest, count = hashlib.sha256(), 0
    while chunk := stream.read(1<<20):
        count += len(chunk)
        digest.update(chunk)
    return {"bytes":count,"sha256":digest.hexdigest()}

def compare_archive(archive, manifest, manifest_raw):
    expected = dict(manifest["files"])
    expected["artifact-manifest.json"] = {"bytes":len(manifest_raw),
        "sha256":hashlib.sha256(manifest_raw).hexdigest(),"mode":0o600}
    seen = set()
    with tarfile.open(archive,"r:gz") as tar:
        for member in tar:
            require(member.name.startswith("capture/"), "archive prefix differs")
            name = member.name.removeprefix("capture/")
            safe(name)
            require(member.isfile() and not member.islnk() and not member.issym(),
                    "archive contains a nonregular object")
            require(name in expected and name not in seen, "archive member set differs")
            row = expected[name]
            require(member.mode == row["mode"] and member.size == row["bytes"],
                    "archive member metadata differs")
            stream = tar.extractfile(member)
            require(stream is not None, "missing archive member stream")
            with stream:
                require(member_pin(stream) == {"bytes":row["bytes"],"sha256":row["sha256"]},
                        "archive full member bytes differ")
            seen.add(name)
    require(seen == set(expected), "archive omitted source/evidence bytes")
    return {"files":len(seen), "logical_bytes":sum(row["bytes"] for row in expected.values())}

def pack(a):
    root, output, package = a.capture.resolve(), a.output.resolve(), a.package.resolve(strict=True)
    require(not output.exists() and not output.is_relative_to(root), "archive output overlaps or exists")
    output.mkdir(parents=True)
    paths = {}
    if root.exists():
        for name in files(root):
            paths[name] = root/name
    require(not any(name == "ci-package" or name.startswith("ci-package/") for name in paths),
            "capture already contains an archive source snapshot")
    for name in files(package):
        paths["ci-package/"+name] = package/name
    if a.driver_prefix is not None:
        for suffix in ("stdout","stderr"):
            path = Path(str(a.driver_prefix)+"."+suffix)
            if path.is_file():
                require("driver."+suffix not in paths,"duplicate full driver stream")
                paths["driver."+suffix] = path
    declaration = {"manifest_sha256":a.manifest_sha256,"source_path":str(package),"capture_path":str(root),
        "git_head":os.environ.get("GITHUB_SHA"),"run_id":os.environ.get("GITHUB_RUN_ID"),
        "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT"),
        "label":a.label,"archive_is_qualification":False,"captured_tree_modified_by_export":False}
    virtual = {"CI_SOURCE_DECLARATION.json":(json.dumps(declaration,sort_keys=True,indent=2)+"\n").encode()}
    require("artifact-manifest.json" not in paths and not (set(virtual)&set(paths)),
            "capture already contains archive declarations")
    directories = {}
    for base,prefix in ((root,""),(package,"ci-package")):
        if not base.exists():
            continue
        if prefix:
            directories[prefix]=stat.S_IMODE(base.stat().st_mode)
        for path in sorted(base.rglob("*")):
            info=path.lstat()
            require(not stat.S_ISLNK(info.st_mode),"directory source contains a symlink")
            if stat.S_ISDIR(info.st_mode):
                name=(prefix+"/" if prefix else "")+path.relative_to(base).as_posix()
                safe(name);directories[name]=stat.S_IMODE(info.st_mode)
    inventory = {}
    for name,path in paths.items():
        safe(name)
        inventory[name] = {**pin(path),"mode":stat.S_IMODE(path.lstat().st_mode)}
    for name,value in virtual.items():
        inventory[name] = {"bytes":len(value),"sha256":hashlib.sha256(value).hexdigest(),"mode":0o600}
    manifest = {"schema":"hepta.runtime.complete-ci-archive.v2","files":inventory,"directories":directories,
        "label":a.label,"source_manifest_sha256":a.manifest_sha256,
        "qualification_inferred_from_archive":False}
    manifest_raw = (json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
    virtual["artifact-manifest.json"] = manifest_raw
    archive = output/"capture.tar.gz"
    with tarfile.open(archive,"w:gz",compresslevel=1,format=tarfile.PAX_FORMAT,dereference=True) as tar:
        for name in ["artifact-manifest.json",*sorted(inventory)]:
            if name in virtual:
                value=virtual[name]
                info=tarfile.TarInfo("capture/"+name)
                info.size=len(value);info.mode=0o600;info.mtime=0
                tar.addfile(info,io.BytesIO(value))
            else:
                tar.add(paths[name],arcname="capture/"+name,recursive=False)
    readback = compare_archive(archive,manifest,manifest_raw)
    report = {"schema":"hepta.runtime.complete-ci-archive-receipt.v1","label":a.label,
        "archive":pin(archive),"manifest":{"bytes":len(manifest_raw),"sha256":hashlib.sha256(manifest_raw).hexdigest()},
        "readback":readback,"source_manifest_sha256":a.manifest_sha256,
        "git_head":os.environ.get("GITHUB_SHA"),"run_id":os.environ.get("GITHUB_RUN_ID"),
        "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT"),"qualification_inferred_from_archive":False,
        "captured_tree_modified_by_export":False}
    put(output/"archive.json",report)
    print(json.dumps(report,sort_keys=True))

def extract(a):
    archive = a.archive.resolve(strict=True)
    report = json.loads(a.receipt.read_bytes())
    require(pin(archive) == report["archive"], "full archive identity differs")
    out = a.output.resolve()
    require(not out.exists(),"extraction output already exists")
    out.mkdir(parents=True)
    seen, expected, manifest_raw = set(), None, None
    with tarfile.open(archive,"r:gz") as tar:
        for member in tar:
            require(member.name.startswith("capture/"),"archive prefix differs")
            name = member.name.removeprefix("capture/")
            safe(name)
            require(member.isfile() and not member.islnk() and not member.issym(),
                    "archive object type differs")
            require(name not in seen,"duplicate archive member")
            stream = tar.extractfile(member)
            require(stream is not None,"missing archive member stream")
            if not seen:
                require(name=="artifact-manifest.json" and member.mode==0o600,"first inventory missing")
                with stream:
                    manifest_raw=stream.read()
                require({"bytes":len(manifest_raw),"sha256":hashlib.sha256(manifest_raw).hexdigest()}
                        == report["manifest"],"archive inventory identity differs")
                manifest=json.loads(manifest_raw)
                expected=dict(manifest["files"])
                for relative,row in expected.items():
                    safe(relative)
                    require(set(row)=={"bytes","sha256","mode"} and type(row["bytes"]) is int
                            and row["bytes"]>=0 and type(row["mode"]) is int and 0<=row["mode"]<=0o777,
                            "archive inventory schema differs")
                require("artifact-manifest.json" not in expected,"inventory contains itself")
                expected["artifact-manifest.json"]={**report["manifest"],"mode":0o600}
                with (out/name).open("xb") as dest:
                    dest.write(manifest_raw)
                os.chmod(out/name,0o600)
            else:
                require(expected is not None and name in expected,"unclaimed archive member")
                row=expected[name]
                require(member.mode==row["mode"] and member.size==row["bytes"],"archive metadata differs")
                target=out/name
                target.parent.mkdir(parents=True,exist_ok=True)
                digest,count=hashlib.sha256(),0
                with stream, target.open("xb") as dest:
                    while chunk:=stream.read(1<<20):
                        count+=len(chunk);digest.update(chunk);dest.write(chunk)
                require({"bytes":count,"sha256":digest.hexdigest()}==
                        {"bytes":row["bytes"],"sha256":row["sha256"]},"full extracted member differs")
                os.chmod(target,row["mode"])
            seen.add(name)
    require(expected is not None and seen==set(expected),"archive omitted a member")
    require(manifest["schema"]=="hepta.runtime.complete-ci-archive.v2"
        and type(manifest["directories"]) is dict,"complete directory inventory missing")
    for name,mode in manifest["directories"].items():
        safe(name)
        require(type(mode) is int and 0<=mode<=0o777,"directory mode")
        path=out/name
        require(not path.exists() or path.is_dir(),"declared directory conflicts with file")
        path.mkdir(parents=True,exist_ok=True)
    actual_dirs={p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_dir()}
    require(actual_dirs==set(manifest["directories"]),"complete directory set differs")
    for name,mode in sorted(manifest["directories"].items(),key=lambda item:len(Path(item[0]).parts),reverse=True):
        os.chmod(out/name,mode)

    require(report["readback"]=={"files":len(expected),"logical_bytes":sum(x["bytes"] for x in expected.values())},
            "archive full readback count differs")
    print(json.dumps({"status":"COMPLETE_ARCHIVE_EXTRACTION_PASS","files":len(expected),
        "logical_bytes":report["readback"]["logical_bytes"],"archive":report["archive"]},sort_keys=True))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="command",required=True)
    one=sub.add_parser("pack")
    for name in ("capture","output","package"):
        one.add_argument("--"+name,type=Path,required=True)
    one.add_argument("--manifest-sha256",required=True)
    one.add_argument("--driver-prefix",type=Path)
    one.add_argument("--label",required=True)
    two=sub.add_parser("extract")
    for name in ("archive","receipt","output"):
        two.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    pack(a) if a.command=="pack" else extract(a)

if __name__=="__main__":
    main()
