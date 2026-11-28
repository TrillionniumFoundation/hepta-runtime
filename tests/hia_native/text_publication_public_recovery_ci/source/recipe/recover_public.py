#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Restore and compare complete immutable public captures; no native or Rust execution."""
from pathlib import Path,PurePosixPath
import argparse,ast,hashlib,io,json,os,shutil,signal,subprocess,sys,tarfile,time,zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"));sys.path.insert(0,str(ROOT))
from common import canonical,decode,pin,sha,require,source_evidence
import dependencies
def verify_patch():
    before=(ROOT/"retained/public-reader-v1.py.txt").read_bytes()
    after=(ROOT/"recipe/read_public.py").read_bytes()
    old=b'primary["slot"]==32 and primary["code"]==32'
    new=b'primary["slot"]==32 and primary["code"]==len(primary["output"])'
    require(before.count(old)==1 and before.replace(old,new)==after,"only cache return-extent admission changed")
    original=(ROOT/"retained/private-reference-main.rs.txt").read_bytes()
    require(b'(output.len() as u64,output)' in original,"retained actual original cache fixture return")
    prior=decode((ROOT/"retained/public-domain-v1-manifest.json").read_bytes())
    mapping={r["path"]:r for r in prior["files"]}
    for name in ("recipe/capture_public.py","recipe/public_domain.py","recipe/input_domain.py",
        "recipe/body_cases.py","recipe/body_filesystem.py","recipe/readonly.py"):
        require(pin(ROOT/name)=={k:mapping[name][k] for k in ("bytes","sha256")},"frozen execution/input/guard changed")
    return dict(status="ONE_CACHE_EXTENT_READER_REPAIR_ONLY",old=sha(before),new=sha(after),
        capture_and_domain_unchanged=True,source_graph_unchanged=True,native_replayed=False,rust_replayed=False)
def restore(item,out):
    out.mkdir(parents=True)
    archive=out/"artifact.zip";dependencies.download(item,archive)
    with zipfile.ZipFile(archive) as z:
        require(len(z.namelist())==3 and set(z.namelist())=={"evidence.tar.gz","FILES.json","ARCHIVE.json"}
            and z.testzip() is None,"complete public ZIP")
        for name in z.namelist():
            with z.open(name) as incoming,(out/name).open("xb") as target:
                while block:=incoming.read(1<<20):target.write(block)
    index=decode((out/"FILES.json").read_bytes());receipt=decode((out/"ARCHIVE.json").read_bytes())
    require(pin(out/"evidence.tar.gz")==receipt["archive"],"complete public TAR")
    wanted={r["path"]:r for r in index["files"]}
    require(len(wanted)==len(index["files"])==receipt["files"],"full archive file set")
    directories=index["directories"]
    require(len(directories)==len({r["path"] for r in directories}),"unique archived directories")
    root=out/"retained";root.mkdir()
    for row in sorted(directories,key=lambda r:(len(PurePosixPath(r["path"]).parts),r["path"])):
        path=PurePosixPath(row["path"])
        require(not path.is_absolute() and ".." not in path.parts and path.as_posix()==row["path"]
            and row["path"] not in wanted and 0<=row["mode"]<=0o777,"exact archived ordinary directory")
        target=root/row["path"];target.mkdir(parents=True,exist_ok=True);target.chmod(row["mode"])
    seen=set()
    with tarfile.open(out/"evidence.tar.gz","r:gz") as tar:
        for member in tar:
            path=PurePosixPath(member.name)
            require(member.isfile() and member.name in wanted and member.name not in seen
                and not path.is_absolute() and ".." not in path.parts and path.as_posix()==member.name,
                "archive member path/type/set")
            row=wanted[member.name];target=root/member.name
            require(target.parent.is_dir(),"complete directory index omitted parent")
            with tar.extractfile(member) as incoming,target.open("xb") as output:
                digest=hashlib.sha256()
                while block:=incoming.read(1<<20):output.write(block);digest.update(block)
            target.chmod(member.mode)
            require(member.size==row["bytes"] and member.mode==row["mode"] and digest.hexdigest()==row["sha256"],
                "complete archived member bytes/mode")
            seen.add(member.name)
    require(seen==set(wanted) and sum(r["bytes"] for r in wanted.values())==receipt["logical_bytes"],
        "complete archive byte coverage")
    require({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir()}=={r["path"] for r in directories},
        "complete directory restoration")
    require((root/"recipe-source/SOURCE_MANIFEST.json").read_bytes()==(ROOT/"retained/public-domain-v1-manifest.json").read_bytes(),
        "actual archived semantic source manifest")
    declared=decode((root/"recipe-source/SOURCE_MANIFEST.json").read_bytes())
    require({p.relative_to(root/"recipe-source").as_posix() for p in (root/"recipe-source").rglob("*") if p.is_file()}
        =={r["path"] for r in declared["files"]}|{"SOURCE_MANIFEST.json"},"complete archived semantic source files")
    for row in declared["files"]:
        require(pin(root/"recipe-source"/row["path"])=={k:row[k] for k in ("bytes","sha256")},
            "actual retained semantic source")
    proof=dict(status="COMPLETE_PUBLIC_CAPTURE_ARCHIVE_RESTORED",input=item,archive=receipt,
        directories=len(directories),native_executed=False,rust_executed=False)
    (out/"RESTORED.json").write_bytes(canonical(proof))
    return root,proof

def inventory(root):
    return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(root.rglob("*")) if p.is_file()}
def run_reader(capture,out,physical):
    command=[sys.executable,"-I","-S","-B",str(ROOT/"recipe/qualify_readonly.py"),"--capture",str(capture)]
    if physical:command+=["--physical-controls"]
    started=time.monotonic();timed=False
    with (out/"reader.stdout").open("xb") as stdout,(out/"reader.stderr").open("xb") as stderr:
        proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
        try:proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed=True;os.killpg(proc.pid,signal.SIGKILL);proc.wait()
    receipt=dict(command=command,exit_code=proc.returncode,timed_out=timed,timeout_seconds=180,
        elapsed_seconds=time.monotonic()-started,stdout=pin(out/"reader.stdout"),stderr=pin(out/"reader.stderr"),
        native_executed=False,rust_executed=False)
    (out/"READER_PROCESS.json").write_bytes(canonical(receipt))
    sys.stdout.buffer.write((out/"reader.stdout").read_bytes())
    sys.stderr.buffer.write((out/"reader.stderr").read_bytes())
    require(proc.returncode==0 and not timed,"complete pure reader process")
    return receipt
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",required=True,type=Path)
    p.add_argument("--key",required=True);a=p.parse_args()
    require(not a.output.exists(),"fresh immutable-capture review");a.output.mkdir(parents=True)
    source_evidence(ROOT);patch=verify_patch()
    inputs=decode((ROOT/"RECOVERY_INPUTS.json").read_bytes())
    chosen=[r for r in inputs if r["key"]==a.key];require(len(chosen)==1,"one fixed capture artifact")
    item=chosen[0];retained,archive=restore(item,a.output/"acquired")
    before=inventory(retained)
    if item["key"]=="dependencies":
        receipt=decode((retained/"capture/DEPENDENCIES.json").read_bytes())
        dependencies.verify_receipt(receipt)
        result=dict(status="COMPLETE_RETAINED_PUBLIC_DEPENDENCY_PROOF_READ_PASS")
    else:
        review=a.output/"review";review.mkdir()
        shutil.copytree(retained/"capture",review/"capture",copy_function=shutil.copy2)
        require(inventory(review/"capture")==inventory(retained/"capture"),"complete independent capture view")
        reader=run_reader(review/"capture",a.output,item["key"]=="carrier_configured_legacy")
        result=decode((review/"capture-result.json").read_bytes())
        require(result["comparison"]["mode"]==item["mode"] and result["comparison"]["profile"]==item["profile"]
            and result["comparison"]["era"]==item["era"],"exact restored lane")
        result=dict(status="COMPLETE_RETAINED_PUBLIC_LANE_RECOVERY_PASS",reader=reader,comparison=result)
    require(inventory(retained)==before,"original immutable archive expansion changed")
    (a.output/"RESULT.json").write_bytes(canonical(dict(result=result,input=item,archive=archive,patch=patch,
        retained_bytes_unchanged=True,native_executed=False,rust_executed=False)))
    print(json.dumps(dict(key=a.key,status=result["status"],native_executed=False,rust_executed=False),sort_keys=True))
if __name__=="__main__":main()
