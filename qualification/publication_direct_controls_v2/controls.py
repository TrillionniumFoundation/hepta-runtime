#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Six honest physical refusals and two whole-copy direct-future relocations."""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,json,os,shutil,stat,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def require(value,message):
    if not value:raise ValueError(message)
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def decode(raw):return json.loads(raw)
def pin(path):
    with Path(path).open("rb") as stream:return dict(bytes=Path(path).stat().st_size,sha256=hashlib.file_digest(stream,"sha256").hexdigest())
def sources(root):
    root=Path(root);manifest=decode((root/"SOURCE_MANIFEST.json").read_bytes())
    rows=manifest["files"] if isinstance(manifest,dict) else manifest
    if isinstance(rows,dict):rows=[dict(path=p,**r) for p,r in rows.items()]
    for row in rows:
        p=root/row["path"];require(pin(p)=={k:row[k] for k in ("bytes","sha256")},"whole source "+row["path"])
    require({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}==
        {row["path"] for row in rows}|{"SOURCE_MANIFEST.json"},"complete package source set")
    return pin(root/"SOURCE_MANIFEST.json")
def inventory(root):
    rows={}
    for p in [root,*sorted(root.rglob("*"))]:
        s=p.lstat();require(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode),"ordinary retained input")
        r=dict(mode=stat.S_IMODE(s.st_mode),kind="file" if p.is_file() else "directory",
            mtime_ns=s.st_mtime_ns,xattrs={k:os.getxattr(p,k).hex() for k in os.listxattr(p)})
        if p.is_file():
            require(s.st_nlink==1,"complete independent retained ordinary files")
            r.update(pin(p))
        rows[p.relative_to(root).as_posix()]=r
    return rows
def fullcopy(source,target):
    before=inventory(source);shutil.copytree(source,target,copy_function=shutil.copy2)
    after=inventory(target);require(before==after,"all relocated bytes modes timestamps and xattrs")
    original={(p.stat().st_dev,p.stat().st_ino) for p in [source,*source.rglob("*")]}
    copied={(p.stat().st_dev,p.stat().st_ino) for p in [target,*target.rglob("*")]}
    require(not original&copied,"actual distinct physical file and directory objects")
    return dict(files=before,before=before,after=after,independent_inodes=True)
def joined(n,o,case,binary):
    import read_direct,direct_worker
    return dict(status="COMPLETE_DIRECT_STATE_FILES_WORKER_DROP_AND_LIFECYCLE_JOIN_PASS",
        case=case["case"],name=case["name"],semantics=read_direct.compare(n,o,case,binary),
        worker=direct_worker.verify(n,o,case),semantic_replay=False,full_sdk=False)
def verify_negative(n,o,case,binary,baseline,mutation):
    import read_direct,direct_worker
    semantics=read_direct.compare(n,o,case,binary)
    expected=copy.deepcopy(baseline["semantics"])
    expected["all_native_streams"]["host-trace"]=mutation["after_raw"]
    require(decode(canonical(semantics))==expected,"complete commands state files all other streams remain equal before semantic refusal")
    try:direct_worker.verify(n,o,case)
    except ValueError as error:
        require(str(error)==mutation["expected_refusal"],"exact actual cross-edge refusal: "+str(error))
        return dict(status="HONEST_RESEALED_SEMANTIC_REFUSAL_PASS",case=case["case"],
            name=mutation["name"],outer_full_comparison=semantics,refusal_type=type(error).__name__,
            refusal=str(error),application_replayed=False)
    raise ValueError("physical mutation was accepted")
def main():
    p=argparse.ArgumentParser()
    for name in ("source","prepared","build-recipe","direct-recipe","public-reader","retained","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);a.retained.mkdir(parents=True,exist_ok=False)
    own=sources(HERE);info=decode((HERE/"INPUTS.json").read_bytes())
    require(pin(a.source/"SOURCE_MANIFEST.json")==info["reader"]["manifest"],"exact unchanged full reader")
    sys.path.insert(0,str(a.source))
    from common import source_evidence
    import readonly,read_direct,direct_worker
    source_evidence(a.source)
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    failed,failed_archive=restore(a.retained/"preserved-v1-failure",info["retained_failure"])
    require(pin(failed/"recipe-source/controls.py")==info["retained_failure"]["controls"]
        and sources(failed/"recipe-source")==info["retained_failure"]["manifest"],"entire retained prior control source")
    error=(failed/"driver.stderr").read_bytes()
    require(b"ValueError: complete independent relocation within original180" in error,
        "actual prior Python representation comparison failure retained")
    saved=a.output/"preserved-v1-failure";saved.mkdir()
    for name in ("READ.json","FILES.json","ARCHIVE.json"):
        shutil.copyfile(a.retained/"preserved-v1-failure"/name,saved/name)
    for name in ("driver.stdout","driver.stderr"):shutil.copyfile(failed/name,saved/name)
    (saved/"SUMMARY.json").write_bytes(canonical(dict(archive=failed_archive,
        failure_conclusion_unchanged=True,application_replayed=False,
        repair="Compare the complete Python result in its exact JSON evidence representation; tuples serialize as lists.")))
    spec=importlib.util.spec_from_file_location("direct_physical_mutations",HERE/"mutations.py")
    mutations=importlib.util.module_from_spec(spec);spec.loader.exec_module(mutations)
    prep=decode((a.prepared/"domain/PREPARED.json").read_bytes())
    original=Path(prep["original"]);plan=decode((original/"PLAN.json").read_bytes())
    expected={k:decode((a.source/"INPUTS.json").read_bytes())["direct_build"]["binary"][k] for k in ("bytes","sha256")}
    require(pin(Path(prep["binary"]))==expected,"actual qualified direct capability")
    receipts=[]
    for role in ("old22","new26"):
        out=a.output/("admission-"+role);command=[sys.executable,"-I","-S","-B",str(a.source/"recover_direct.py"),
            "--prepared",str(a.prepared),"--build-recipe",str(a.build_recipe),"--direct-recipe",str(a.direct_recipe),
            "--public-reader",str(a.public_reader),"--retained",str(a.retained/role),"--output",str(out),"--role",role]
        start=time.monotonic()
        with (a.output/(role+".stdout")).open("xb") as so,(a.output/(role+".stderr")).open("xb") as se:
            result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=so,stderr=se)
        row=dict(role=role,command=command,exit_code=result.returncode,elapsed_seconds=time.monotonic()-start,
            stdout=pin(a.output/(role+".stdout")),stderr=pin(a.output/(role+".stderr")),applications=0)
        receipts.append(row);(a.output/"ADMISSION.json").write_bytes(canonical(receipts))
        require(result.returncode==0,"whole retained role admission "+role)
    baselines={};relocations=[];roots=[HERE,a.source,original/"cases/000"]
    for number,role in ((23,"old22"),(26,"new26")):
        origin=a.retained/role/"extracted/capture/native/cases"/("%03d"%number)
        target=a.output/("relocated-%03d"%number);copyproof=fullcopy(origin,target)
        case=plan["cases"][number];o=original/"cases"/("%03d"%number)
        retained=decode((a.output/("admission-"+role)/("READ-%03d.json"%number)).read_bytes())["evidence"]
        start=time.monotonic()
        proof=readonly.guarded(lambda:joined(target,o,case,expected),roots=[*roots,target,o])
        elapsed=time.monotonic()-start
        require(elapsed<180 and decode(canonical(proof["evidence"]))==retained,"complete independent relocation within original180")
        (a.output/("RELOCATION-%03d.json"%number)).write_bytes(canonical(dict(copy=copyproof,reader=proof,elapsed_seconds=elapsed)))
        baselines[number]=(target,o,case,retained)
        relocations.append(dict(case=number,entries=proof["entries"],guards=len(proof["probes"]),
            proof=pin(a.output/("RELOCATION-%03d.json"%number)),elapsed_seconds=elapsed))
    rows=[]
    for name,number,phase,refusal in mutations.SPECS:
        base,o,case,baseline=baselines[number];target=a.output/name;before=fullcopy(base,target)
        started=time.monotonic();mutation=mutations.transform(target,name)
        parent=target/"process";st=parent.stat()
        os.utime(parent,ns=(st.st_atime_ns,before["files"]["process"]["mtime_ns"]))
        after=inventory(target)
        changed=sorted(k for k in before["files"] if before["files"][k]!=after[k])
        require(set(before["files"])==set(after) and changed==["RESULT.json","process/PROCESS.json","process/host-trace.gz"],
            "only full trace plus honest two outer custody records changed")
        for path in changed:
            require(before["files"][path]["kind"]==after[path]["kind"]=="file"
                and before["files"][path]["mode"]==after[path]["mode"]
                and before["files"][path]["xattrs"]==after[path]["xattrs"],"mutations retain mode and xattrs")
        record=dict(mutation=mutation,copy=before,after=after,changed=changed,
            source=own,reader_source=info["reader"],native_executed=False,rust_executed=False)
        witness=a.output/(name+".mutation.json");witness.write_bytes(canonical(record))
        proof=readonly.guarded(lambda:verify_negative(target,o,case,expected,baseline,mutation),
            roots=[*roots,target,o])
        elapsed=time.monotonic()-started
        require(elapsed<180,"complete physical mutation and reader within original180")
        resultpath=a.output/(name+".read.json");resultpath.write_bytes(canonical(proof))
        row=dict(name=name,case=number,elapsed_seconds=elapsed,guards=len(proof["probes"]),
            entries=proof["entries"],mutation=pin(witness),proof=pin(resultpath),refusal=proof["evidence"]["refusal"])
        rows.append(row);(a.output/"PHYSICAL_RESULTS.json").write_bytes(canonical(rows))
        print("DIRECT_PHYSICAL "+json.dumps(row,sort_keys=True),flush=True)
    require(len(rows)==6 and len(relocations)==2,"complete minimum physical and relocation domain")
    summary=dict(status="DIRECT_FUTURE_PHYSICAL_6_RELOCATIONS_2_PASS",source=own,reader=info["reader"],
        production=info["production"],binary=expected,controls=rows,relocations=relocations,
        native_executed=False,rust_executed=False,application_replayed=False,full_sdk=False)
    (a.output/"SUMMARY.json").write_bytes(canonical(summary));print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
