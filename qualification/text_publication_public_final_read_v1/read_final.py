#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independent uploaded-archive and complete guarded public evidence read; no implementation execution."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,importlib.util,json,os,shutil,sys,tarfile,time,zipfile
sys.dont_write_bytecode=True
def need(v,m):
    if not v:raise ValueError(m)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(p):
    with p.open("rb") as f:return dict(bytes=p.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def encode(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def restore(item,root,dep):
    root.mkdir(parents=True)
    zip_path=root/"artifact.zip";dep.download(item,zip_path)
    with zipfile.ZipFile(zip_path) as z:
        need(len(z.namelist())==3 and set(z.namelist())=={"evidence.tar.gz","FILES.json","ARCHIVE.json"}
            and z.testzip() is None,"complete uploaded ZIP")
        for name in z.namelist():
            with z.open(name) as a,(root/name).open("xb") as b:
                while block:=a.read(1<<20):b.write(block)
    index=json.loads((root/"FILES.json").read_bytes());receipt=json.loads((root/"ARCHIVE.json").read_bytes())
    need(pin(root/"evidence.tar.gz")==receipt["archive"],"complete uploaded TAR")
    files={r["path"]:r for r in index["files"]}
    dirs={r["path"]:r for r in index["directories"]}
    need(len(files)==len(index["files"])==receipt["files"] and len(dirs)==len(index["directories"]),"complete member counts")
    out=root/"extracted";out.mkdir()
    for name,row in sorted(dirs.items(),key=lambda v:(len(PurePosixPath(v[0]).parts),v[0])):
        p=PurePosixPath(name)
        need(not p.is_absolute() and ".." not in p.parts and p.as_posix()==name and name not in files,
            "ordinary indexed directory")
        target=out/name;target.mkdir(parents=True,exist_ok=True);target.chmod(row["mode"])
    seen=set()
    with tarfile.open(root/"evidence.tar.gz","r:gz") as tar:
        for member in tar:
            p=PurePosixPath(member.name)
            need(member.isfile() and member.name in files and member.name not in seen
                and not p.is_absolute() and ".." not in p.parts and p.as_posix()==member.name,"actual uploaded member inventory")
            row=files[member.name];target=out/member.name
            need(target.parent.is_dir(),"indexed complete parent directory")
            with tar.extractfile(member) as a,target.open("xb") as b:
                digest=hashlib.sha256()
                while block:=a.read(1<<20):b.write(block);digest.update(block)
            target.chmod(member.mode)
            need(member.size==row["bytes"] and member.mode==row["mode"] and digest.hexdigest()==row["sha256"],
                "complete uploaded member bytes and mode")
            seen.add(member.name)
    need(seen==set(files) and sum(r["bytes"] for r in files.values())==receipt["logical_bytes"],"uploaded archive coverage")
    need({p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_dir()}==set(dirs),"restored complete directory set")
    return out,dict(key=item["key"],input=item,archive=receipt,directories=len(dirs))
def source_equal(left,right):
    l={p.relative_to(left).as_posix():pin(p) for p in left.rglob("*") if p.is_file()}
    r={p.relative_to(right).as_posix():pin(p) for p in right.rglob("*") if p.is_file()}
    need(l==r,"complete frozen current reader source")
def gate(proof):
    need(proof["status"]=="READONLY_PASS" and proof["before"]==proof["after"] and len(proof["probes"])==11
        and all(x["rejected"] is True for x in proof["probes"])
        and proof["native_executed"] is proof["rust_executed"] is proof["evidence_written"] is False,
        "complete retained readonly proof")
def main():
    p=argparse.ArgumentParser()
    for name in ("reader-source","work","output"):p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args();source=a.reader_source.resolve(strict=True)
    need(not a.work.exists() and not a.output.exists(),"fresh independent proof paths")
    a.work.mkdir(parents=True);a.output.mkdir(parents=True)
    sys.path.insert(0,str(source/"recipe"));sys.path.insert(0,str(source))
    import dependencies as dep,read_public,public_reader_controls as controls,readonly,recover_public
    from helper_source import prepare
    from common import source_evidence
    need(pin(source/"SOURCE_MANIFEST.json")=={"bytes":8947,"sha256":"c825ab0f81fbc39b3620884570933c312b52249e5bcadf663ece0e104b9fb32a"},
        "exact source manifest")
    source_evidence(source);patch=recover_public.verify_patch()
    prepare(source/"retained/text75_qualify.py");read_public.old.retained_filesystem()
    originals=dep.extract(dep.GRAPH,a.work/"graph")
    reference=dep.extract(dep.REFERENCE,a.work/"reference")
    inputs=json.loads((Path(__file__).with_name("INPUTS.json")).read_bytes())
    need(len(inputs)==25 and len({x["key"] for x in inputs})==25,"all25 uploaded recovery artifacts")
    captures={};archives=[]
    for item in inputs:
        root,receipt=restore(item,a.work/str(item["artifact"]),dep)
        source_equal(root/"recipe-source",source)
        captures[item["key"]]=root;archives.append(receipt)
    def operation():
        _,graph=dep.read_graph(originals)
        _,original=dep.read_reference(reference)
        results={};physical=None;relocations=[]
        for key,root in sorted(captures.items()):
            top=root/"capture";retained=json.loads((top/"RESULT.json").read_bytes())
            need(retained["native_executed"] is retained["rust_executed"] is False
                and retained["retained_bytes_unchanged"] is True and retained["patch"]==patch,
                "retained recovery scope and exact one-expression repair")
            if key=="dependencies":
                value=json.loads((top/"acquired/retained/capture/DEPENDENCIES.json").read_bytes())
                dep.verify_receipt(value);continue
            capture=top/"review/capture"
            actual=read_public.read(capture)
            summary=json.loads((top/"review/capture-result.json").read_bytes())
            need(summary==retained["result"]["comparison"] and actual==summary["comparison"],"whole retained comparison")
            proc=json.loads((top/"READER_PROCESS.json").read_bytes())
            need(proc["exit_code"]==0 and proc["timed_out"] is False and proc["timeout_seconds"]==180
                and proc["elapsed_seconds"]<180 and proc["native_executed"] is proc["rust_executed"] is False,
                "actual pure reader process")
            need(pin(top/"reader.stdout")==proc["stdout"] and pin(top/"reader.stderr")==proc["stderr"],
                "complete pure reader streams")
            earlier=json.loads((top/"review/capture-readonly.json").read_bytes());gate(earlier)
            need(earlier["evidence"]==actual,"retained first guarded comparison")
            if key=="carrier_configured_legacy":
                control=top/"review/capture-reader-controls"
                physical=controls.verify(capture,control)
                for name in ("relocation-one","relocation-two"):
                    moved=read_public.read(control/name/"capture")
                    prior=json.loads((control/name/"READONLY.json").read_bytes());gate(prior)
                    need(moved==prior["evidence"]==actual,"complete actual relocation")
                    relocations.append(dict(name=name,evidence=moved))
                final=json.loads((control/"FINAL_READONLY.json").read_bytes());gate(final)
                need(final["evidence"]["comparison"]==actual and final["evidence"]["physical"]==physical,
                    "retained final physical control proof")
            results[key]=actual
        need(len(results)==24 and sum(r["cases"] for r in results.values())==686
            and sum(r["responses"] for r in results.values())==612,"complete686 pairs and612 real public responses")
        need(physical is not None and len(physical["controls"])==10 and len(relocations)==2,"all physical controls and relocations")
        return dict(status="COMPLETE_PUBLIC_PUBLISHER_UPLOADED_READONLY_PASS",graph=graph,original=original,
            cases=686,responses=612,lanes=24,results=results,physical=physical,relocations=relocations,
            full_async=False,full_sdk=False,production_installed=False)
    started=time.monotonic()
    proof=readonly.guarded(operation,roots=(source,originals,reference,*captures.values()))
    elapsed=time.monotonic()-started;need(elapsed<180,"original pure reader180-second bound")
    (a.output/"READONLY.json").write_bytes(encode(proof))
    (a.output/"ARCHIVES.json").write_bytes(encode(dict(archives=archives)))
    (a.output/"RESULT.json").write_bytes(encode(dict(status=proof["evidence"]["status"],elapsed_seconds=elapsed,
        full_member_files=sum(x["archive"]["files"] for x in archives),
        full_member_bytes=sum(x["archive"]["logical_bytes"] for x in archives),
        guard_entries=proof["entries"],guard_probes=len(proof["probes"]),cases=686,responses=612,
        physical_controls=10,relocations=2,hia_executed=False,rust_executed=False,
        source_manifest=pin(source/"SOURCE_MANIFEST.json"),patch=patch)))
    for label,root in (("graph",a.work/"graph"),("reference",a.work/"reference")):
        dest=a.output/"parent-archive-indices"/label;dest.mkdir(parents=True)
        for name in ("FILES.json","ARCHIVE.json"):shutil.copyfile(root/name,dest/name)
    for item in inputs:
        dest=a.output/"uploaded-archive-indices"/str(item["artifact"]);dest.mkdir(parents=True)
        for name in ("FILES.json","ARCHIVE.json"):shutil.copyfile(a.work/str(item["artifact"])/name,dest/name)
    shutil.copytree(source,a.output/"frozen-reader-source")
    print((a.output/"RESULT.json").read_text(),end="")
if __name__=="__main__":main()
