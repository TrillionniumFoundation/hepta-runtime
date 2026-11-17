#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independently read uploaded complete Direct8 mutations and relocations; zero replay."""
from pathlib import Path
import argparse,copy,gzip,hashlib,importlib.util,json,os,shutil,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def main():
    p=argparse.ArgumentParser()
    for name in ("source","prepared","build-recipe","direct-recipe","public-reader","retained","output","proof"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);a.retained.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.source))
    from common import canonical,decode,pin,require,source_evidence
    import readonly,direct_worker,read_direct,direct_provenance
    own=source_evidence(HERE);reader=source_evidence(a.source);inputs=decode((HERE/"INPUTS.json").read_bytes())
    require(pin(a.source/"SOURCE_MANIFEST.json")==inputs["reader_manifest"],"unchanged complete semantic reader")
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    failed,failed_archive=restore(a.retained/"upload-v1-failure",inputs["reader_failure"])
    require(source_evidence(failed/"recipe-source")["manifest"]==inputs["reader_failure"]["manifest"]
        and b"KeyError: 'git_blob'" in (failed/"driver.stderr").read_bytes(),
        "complete original schema-assumption failure preserved")
    saved=a.output/"reader-v1-failure";saved.mkdir()
    for name in ("READ.json","FILES.json","ARCHIVE.json"):
        shutil.copyfile(a.retained/"upload-v1-failure"/name,saved/name)
    for name in ("driver.stdout","driver.stderr"):shutil.copyfile(failed/name,saved/name)
    (saved/"SUMMARY.json").write_bytes(canonical(dict(archive=failed_archive,original_conclusion="failure",
        source_unchanged=True,application_replayed=False)))
    uploaded,archive=restore(a.proof,inputs["uploaded"])
    package=uploaded/"recipe-source"
    require(pin(package/"SOURCE_MANIFEST.json")==inputs["physical_manifest"],"exact complete physical source manifest")
    manifest=decode((package/"SOURCE_MANIFEST.json").read_bytes())
    require(manifest["schema"]=="source-manifest-v1" and len(manifest["files"])==4,
        "retained physical manifest uses its exact bytes/mode schema")
    require({x.relative_to(package).as_posix() for x in package.rglob("*") if x.is_file()}==
        {r["path"] for r in manifest["files"]}|{"SOURCE_MANIFEST.json"},"whole physical source set")
    for row in manifest["files"]:
        path=package/row["path"]
        require(path.is_file() and not path.is_symlink() and row["mode"]=="100644"
            and path.stat().st_mode&0o777==0o644 and pin(path)=={k:row[k] for k in ("bytes","sha256")},
            "complete physical source bytes and mode "+row["path"])
    control=load_module("retained_direct_physical_control",package/"controls.py")
    mutation_source=load_module("retained_direct_physical_mutations",package/"mutations.py")
    info=decode((a.source/"INPUTS.json").read_bytes())
    prep=decode((a.prepared/"domain/PREPARED.json").read_bytes())
    original=Path(prep["original"]);plan=decode((original/"PLAN.json").read_bytes())
    graph=a.prepared/"domain/public-prepared/build/extracted/capture/source"
    expected=info["direct_build"]["binary"]
    expected={k:expected[k] for k in ("bytes","sha256")}
    require(pin(Path(prep["binary"]))==expected,"whole admitted fixed direct executable")
    summary=decode((uploaded/"capture/SUMMARY.json").read_bytes())
    require(summary["status"]=="DIRECT_FUTURE_PHYSICAL_6_RELOCATIONS_2_PASS"
        and summary["source"]==inputs["physical_manifest"] and summary["production"]==inputs["production"]
        and summary["binary"]==expected and summary["native_executed"] is summary["rust_executed"] is summary["application_replayed"] is False
        and [r["case"] for r in summary["relocations"]]==[23,26]
        and [(r["name"],r["case"]) for r in summary["controls"]]==[(s[0],s[1]) for s in mutation_source.SPECS],
        "complete uploaded control domain and original scope")
    retained={}
    for role in ("old22","new26"):
        target,proof=restore(a.retained/role,info["roles"][role]["artifact"])
        closure=direct_provenance.verify(a.source,target/"recipe-source",graph,a.direct_recipe,a.public_reader,
            info["roles"][role]["producer_manifest"])
        retained[role]=target
        saved=a.output/(role+"-archive");saved.mkdir()
        for name in ("READ.json","FILES.json","ARCHIVE.json"):shutil.copyfile(a.retained/role/name,saved/name)
        (saved/"PROVENANCE.json").write_bytes(canonical(closure))
    def valid_guard(value):
        require(value["status"]=="READONLY_PASS" and value["before"]==value["after"]
            and value["entries"]==len(value["before"]) and len(value["probes"])==11
            and all(x["rejected"] is True for x in value["probes"])
            and value["native_executed"] is value["rust_executed"] is value["evidence_written"] is False,
            "complete retained guarded byte and metadata proof")
    def normalized(value):return decode(canonical(value))
    def stream_inverse(before,after,record):
        require(pin(before)==record["before_gzip"] and pin(after)==record["after_gzip"],"complete physical stream pins")
        patches=record["patches"];end=0
        for row in patches:
            require(type(row["offset"]) is type(row["bytes"]) is int and row["bytes"]>0 and row["offset"]>=end
                and len(bytes.fromhex(row["before"]))==len(bytes.fromhex(row["after"]))==row["bytes"]
                and row["before"]!=row["after"],"canonical nonoverlapping exact mutation spans")
            end=row["offset"]+row["bytes"]
        oldhash=hashlib.sha256();newhash=hashlib.sha256();offset=0;changed=0
        with gzip.open(before,"rb") as left,gzip.open(after,"rb") as right:
            while True:
                x=left.read(1<<20);y=right.read(1<<20)
                require(len(x)==len(y),"complete logical trace extent unchanged")
                if not x:break
                oldhash.update(x);newhash.update(y);want=bytearray(x)
                for row in patches:
                    lo=max(offset,row["offset"]);hi=min(offset+len(x),row["offset"]+row["bytes"])
                    if lo>=hi:continue
                    start=lo-row["offset"];stop=hi-row["offset"]
                    require(x[lo-offset:hi-offset]==bytes.fromhex(row["before"])[start:stop]
                        and y[lo-offset:hi-offset]==bytes.fromhex(row["after"])[start:stop],
                        "actual original and mutated byte span")
                    want[lo-offset:hi-offset]=bytes.fromhex(row["after"])[start:stop];changed+=hi-lo
                require(bytes(want)==y,"all full unmodified trace bytes are retained")
                offset+=len(x)
        require(changed==sum(r["bytes"] for r in patches) and end<=offset
            and dict(bytes=offset,sha256=oldhash.hexdigest())==record["before_raw"]
            and dict(bytes=offset,sha256=newhash.hexdigest())==record["after_raw"],
            "whole stream inverse with exactly every declared changed byte")
        return dict(bytes=offset,changed_bytes=changed,patches=len(patches),complete_inverse=True)
    baselines={};relocations=[]
    for number,role in ((23,"old22"),(26,"new26")):
        n=retained[role]/"capture/native/cases"/("%03d"%number)
        moved=uploaded/"capture"/("relocated-%03d"%number)
        o=original/"cases"/("%03d"%number);case=plan["cases"][number]
        previous_path=uploaded/"capture"/("RELOCATION-%03d.json"%number)
        prior=decode(previous_path.read_bytes())
        row=next(r for r in summary["relocations"] if r["case"]==number)
        require(pin(previous_path)==row["proof"] and row["guards"]==11 and row["elapsed_seconds"]<180,
            "whole original relocation proof")
        valid_guard(prior["reader"])
        def operation():
            require(control.inventory(n)==control.inventory(moved)==prior["copy"]["files"]
                ==prior["copy"]["before"]==prior["copy"]["after"],"complete actual retained relocation bytes metadata xattrs")
            left={(x.stat().st_dev,x.stat().st_ino) for x in [n,*n.rglob("*")]}
            right={(x.stat().st_dev,x.stat().st_ino) for x in [moved,*moved.rglob("*")]}
            require(not left&right and prior["copy"]["independent_inodes"] is True,"actual independent relocation storage")
            found=control.joined(moved,o,case,expected)
            require(normalized(found)==prior["reader"]["evidence"],"whole independent relocation semantic result")
            return found
        start=time.monotonic()
        proof=readonly.guarded(operation,roots=[HERE,a.source,package,n,moved,o,original/"cases/000"])
        elapsed=time.monotonic()-start;require(elapsed<180,"complete independent relocation read180")
        out=a.output/("RELOCATION-%03d.json"%number);out.write_bytes(canonical(proof))
        baselines[number]=(moved,o,case,prior["reader"]["evidence"])
        relocations.append(dict(case=number,guards=len(proof["probes"]),entries=proof["entries"],
            elapsed_seconds=elapsed,proof=pin(out)))
    results=[]
    for name,number,phase,refusal in mutation_source.SPECS:
        base,o,case,baseline=baselines[number];target=uploaded/"capture"/name
        row=next(r for r in summary["controls"] if r["name"]==name)
        wp=uploaded/"capture"/(name+".mutation.json");rp=uploaded/"capture"/(name+".read.json")
        require(pin(wp)==row["mutation"] and pin(rp)==row["proof"] and row["elapsed_seconds"]<180 and row["guards"]==11,
            "full original physical witness and result")
        witness=decode(wp.read_bytes());prior=decode(rp.read_bytes());valid_guard(prior)
        record=witness["mutation"]
        def operation():
            before=control.inventory(base);after=control.inventory(target)
            require(before==witness["copy"]["files"]==witness["copy"]["before"]==witness["copy"]["after"]
                and after==witness["after"],"all uploaded before/after files metadata and xattrs")
            changed=sorted(k for k in before if before[k]!=after[k])
            require(set(before)==set(after) and changed==witness["changed"]==
                ["RESULT.json","process/PROCESS.json","process/host-trace.gz"],"exact full physical file mutation set")
            require(record["name"]==name and record["case"]==number and record["expected_refusal"]==refusal
                and record["honest_outer_reseal"] is True and record["application_executed"] is False,
                "fixed actual semantic mutation")
            inverse=stream_inverse(base/"process/host-trace.gz",target/"process/host-trace.gz",record)
            oldprocess=decode((base/"process/PROCESS.json").read_bytes())
            newprocess=copy.deepcopy(oldprocess)
            newprocess["files"]["host-trace"].update(raw=record["after_raw"],gzip=record["after_gzip"])
            require(decode((target/"process/PROCESS.json").read_bytes())==newprocess,"honest complete process reseal")
            oldresult=decode((base/"RESULT.json").read_bytes());newresult=copy.deepcopy(oldresult);newresult["process"]=newprocess
            require(decode((target/"RESULT.json").read_bytes())==newresult,"honest complete result reseal")
            found=control.verify_negative(target,o,case,expected,baseline,record)
            require(normalized(found)==prior["evidence"],"exact complete independent cross-edge refusal result")
            return dict(inverse=inverse,evidence=found)
        start=time.monotonic()
        proof=readonly.guarded(operation,roots=[HERE,a.source,package,base,target,o,original/"cases/000"])
        elapsed=time.monotonic()-start;require(elapsed<180,"complete independent semantic refusal read180")
        out=a.output/(name+".json");out.write_bytes(canonical(proof))
        results.append(dict(name=name,case=number,guards=len(proof["probes"]),entries=proof["entries"],
            elapsed_seconds=elapsed,proof=pin(out),refusal=proof["evidence"]["evidence"]["refusal"]))
        (a.output/"READ_RESULTS.json").write_bytes(canonical(results))
        print("UPLOADED_PHYSICAL "+json.dumps(results[-1],sort_keys=True),flush=True)
    saved=a.output/"physical-archive";saved.mkdir()
    for name in ("READ.json","FILES.json","ARCHIVE.json"):shutil.copyfile(a.proof/name,saved/name)
    final=dict(status="COMPLETE_UPLOADED_DIRECT_PHYSICAL_6_RELOCATIONS_2_PASS",source=own,reader=reader,
        archive=archive,controls=results,relocations=relocations,application_executions=0,
        native_executed=False,rust_executed=False,full_sdk=False)
    (a.output/"SUMMARY.json").write_bytes(canonical(final));print(json.dumps(final,sort_keys=True),flush=True)
if __name__=="__main__":main()
