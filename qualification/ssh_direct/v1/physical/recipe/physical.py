#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Physical refusals and complete relocations of already captured SSH evidence."""
from pathlib import Path
import argparse,importlib,os,re,shutil,stat,struct,sys,time,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,need,pin,unpack,inventories
from common import source_evidence
PROTECTED=[];BLOCKED=[]
def beneath(path,root):
    try:return os.path.commonpath((str(Path(path).absolute()),str(root)))==str(root)
    except (TypeError,ValueError):return False
def audit(event,args):
    if event.startswith(("subprocess.","os.exec","os.spawn","os.posix_spawn"))or event in("os.system","ctypes.dlopen"):
        raise PermissionError("no applications or compiler execution")
    if event=="open":
        path,mode,flags=args
        if isinstance(path,(str,bytes,os.PathLike)):
            if any(beneath(path,r)for r in BLOCKED):raise PermissionError("old original path is inaccessible")
            write=(isinstance(mode,str)and any(x in mode for x in"wax+"))or bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            if write and any(beneath(path,r)for r in PROTECTED):raise PermissionError("immutable captured input write")
    mutation={"os.remove":(0,),"os.rmdir":(0,),"os.mkdir":(0,),"os.rename":(0,1),"os.chmod":(0,),"os.utime":(0,),"os.link":(0,1),"os.symlink":(1,),"os.setxattr":(0,),"os.removexattr":(0,),"shutil.rmtree":(0,)}
    if event in mutation and any(i<len(args)and any(beneath(args[i],r)for r in PROTECTED)for i in mutation[event]):
        raise PermissionError("immutable captured input metadata")
def refusal(fn,wanted):
    try:fn()
    except (ValueError,PermissionError)as e:
        need(wanted in str(e),"unexpected refusal: "+str(e));return dict(type=type(e).__name__,message=str(e))
    raise ValueError("physically damaged evidence was admitted")
def guards(root,output):
    f=next(p for p in root.rglob("*")if p.is_file());old=BLOCKED[0]/"CASE.bin"
    actions=[
        ("write",lambda:f.open("wb")),("append",lambda:f.open("ab")),("unlink",lambda:os.unlink(f)),
        ("chmod",lambda:os.chmod(f,0o600)),("utime",lambda:os.utime(f,None)),
        ("rename",lambda:os.rename(f,output/"forbidden-move")),("mkdir",lambda:os.mkdir(root/"forbidden-dir")),
        ("link",lambda:os.link(f,output/"forbidden-link")),("old_path",lambda:old.open("rb")),
        ("shell",lambda:os.system("exit 0")),("exec",lambda:os.execv("/usr/bin/true",["true"]))]
    result=[]
    for name,fn in actions:
        try:fn()
        except PermissionError as e:result.append(dict(name=name,status="REFUSED_BEFORE_EFFECT",reason=str(e)))
        else:raise ValueError("read-only boundary permitted "+name)
    return result
def main():
    p=argparse.ArgumentParser()
    for n in("source","downloads","stage","output"):p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--group",choices=("probes","remaining"),required=True)
    p.add_argument("--mode",choices=("controls","relocation"),required=True)
    p.add_argument("--ordinal",type=int,default=0)
    a=p.parse_args();sys.addaudithook(audit)
    need(not a.stage.exists()and not a.output.exists(),"fresh physical proof paths")
    a.stage.mkdir();a.output.mkdir();source=source_evidence(a.source);allinputs=decode((a.source/"INPUTS.json").read_bytes());inputs=allinputs["groups"][a.group]
    roots={side:unpack(a.downloads/(side+".zip"),a.stage/side,inputs[side])for side in("native","original","baseline")}
    retained=a.source/"retained-reader"/a.group
    old_source=roots["baseline"].parent/"recipe-source"
    need(pin(retained/"SOURCE_MANIFEST.json")==pin(old_source/"SOURCE_MANIFEST.json")==inputs["source_manifest"],"exact previously frozen pure source manifest")
    need(source_evidence(retained)==source_evidence(old_source),"whole retained source set")
    for row in decode((retained/"SOURCE_MANIFEST.json").read_bytes())["files"]:
        need((retained/row["path"]).read_bytes()==(old_source/row["path"]).read_bytes(),"every retained source byte")
    baseline_path=roots["baseline"]/"comparison/EVIDENCE.json"
    need(pin(baseline_path)==inputs["evidence"],"entire previously completed proof")
    baseline=decode(baseline_path.read_bytes())
    need(baseline["case_ids"]==inputs["ids"]and baseline["applications_executed_by_reader"]==baseline["old_or_unknown_applications_replayed"]==0,"exact completed actual domain")
    snapshots={role:inventories(root)for role,root in roots.items()}
    for role in("native","original"):
        meta=decode((roots[role]/"PREDECESSOR.json").read_bytes())
        BLOCKED.extend(Path(v["path"]).parent for v in meta["binaries"].values())
        BLOCKED.extend(Path(decode((f/"PROCESS.json").read_bytes())["cwd"])for f in roots[role].glob("case-*"))
    BLOCKED[:]=sorted(set(BLOCKED),key=str)
    PROTECTED.extend([a.source.resolve(),old_source.resolve(),*map(lambda x:x.resolve(),roots.values()),*(a.downloads/(s+".zip")for s in roots)])
    guard=guards(roots["native"],a.output)
    sys.path.insert(0,str(retained/"recipe"));reader=importlib.import_module("read_capture");kernel=importlib.import_module("kernel")
    domain=decode((retained/"domain.json").read_bytes());byid={c["id"]:c for c in domain["cases"]}
    capture_inputs=decode((retained/"INPUTS.json").read_bytes())
    predecessor=decode((roots["native"]/"PREDECESSOR.json").read_bytes())
    binaries={k:v["path"]for k,v in predecessor["binaries"].items()}
    results=[]
    if a.mode=="relocation":
        need(a.ordinal in allinputs["relocations"],"frozen relocation ordinal")
        sys.argv=[str(retained/"recipe/read_capture.py"),"--source",str(retained),"--native",str(roots["native"]),
            "--original",str(roots["original"]),"--stage",str(a.stage/"compiled"),"--output",str(a.output/"comparison")]
        reader.main()
        actual=(a.output/"comparison/EVIDENCE.json").read_bytes();expected=baseline_path.read_bytes()
        need(actual==expected and decode(actual)==baseline,"whole relocated result bytes and objects equal")
        results=[dict(ordinal=a.ordinal,group=a.group,evidence=pin(a.output/"comparison/EVIDENCE.json"),whole_object_equal=True,
            original_absolute_paths_blocked=[str(x)for x in BLOCKED],relocated_roots={k:str(v)for k,v in roots.items()})]
    else:
        need(a.group=="remaining"and a.ordinal==0,"only fresh frozen physical controls")
        # These baselines were already completely read independently. Recheck
        # each component that will receive a physical full-buffer mutation.
        reader.frames(roots["native"]/"case-106/actual/HIA-JOURNAL.bin")
        rr,_=reader.run_report(roots["native"]/"case-107",byid[107],"native")
        ff,_=reader.frames(roots["native"]/"case-107/actual/HIA-JOURNAL.bin")
        kernel.verify_native(roots["native"]/"case-107",ff,byid[107],rr,binaries)
        reader.results(roots["native"]/"case-113",byid[113],"native")
        for spec in allinputs["controls"]:
            folder=a.output/"physical"/spec["name"];folder.mkdir(parents=True)
            original=retained if spec["kind"]=="source"else roots["native"]if spec["kind"]=="root"else roots["native"]/("case-"+str(spec["case"]))
            copied=folder/"complete-damaged-input";shutil.copytree(original,copied,copy_function=shutil.copy2)
            before=inventories(original);changes=[]
            if spec["name"]=="complete_process_ledger":
                target=copied/"LEDGER.json";value=decode(target.read_bytes());value["applications_started"]+=1;target.write_bytes(canonical(value));changes=[target]
                fn=lambda:reader.read_side(copied,[byid[i]for i in inputs["ids"]],"native",predecessor,{},inputs["ids"])
            elif spec["name"]=="exact_raw_hia_source":
                target=copied/spec["target"];raw=bytearray(target.read_bytes());raw[-1]^=1;target.write_bytes(raw);changes=[target]
                fn=lambda:source_evidence(copied)
            elif spec["name"]in("entire_readonly_input","entire_workspace_tail","entire_output_tail","actual_raw_hia_return"):
                target=copied/spec["target"];raw=bytearray(target.read_bytes());h=struct.unpack_from("<16Q",raw);il,wc,oc=h[10:13]
                offsets={"entire_readonly_input":128+il+wc+oc+il-1,"entire_workspace_tail":128+il+wc+oc+il+wc-1,
                    "entire_output_tail":h[1]-1,"actual_raw_hia_return":72}
                raw[offsets[spec["name"]]]^=1;target.write_bytes(raw);changes=[target]
                fn=lambda:reader.frames(target)
            elif spec["name"]=="honestly_resealed_wrong_reaped_pid":
                events,tids,rows=kernel.traces(copied)
                failed=[e for e in events if e["name"]=="execve"and e["ret"]==-2 and kernel.unquote(e["args"][0])==b"/hepta-ssh-frozen-domain-no-such-executable"]
                need(len(failed)==1,"one actual baseline ENOENT")
                pid=failed[0]["tid"];waits=[e for e in events if e["name"]=="wait4"and e["ret"]==pid]
                need(len(waits)==1,"one actual baseline original reap");e=waits[0];target=copied/("kernel."+str(e["tid"]))
                raw=target.read_text();pattern=r"((?:\bwait4\(|<\.\.\. wait4 resumed>)[^\n]*\)\s+=\s+)"+str(pid)+r"(?=\s|$)"
                raw,count=re.subn(pattern,lambda m:m[1]+str(pid+1000000),raw);need(count==1,"one complete physical wrong PID mutation")
                target.write_text(raw);receipt=copied/"PROCESS.json";value=decode(receipt.read_bytes())
                value["kernel_files"][target.name]=pin(target);receipt.write_bytes(canonical(value));changes=[target,receipt]
                report,_=reader.run_report(copied,byid[107],"native");records,_=reader.frames(copied/"actual/HIA-JOURNAL.bin")
                fn=lambda:kernel.verify_native(copied,records,byid[107],report,binaries)
            else:
                target=copied/spec["target"];raw=bytearray(target.read_bytes());need(len(raw)==8388608,"whole exact-bound output");raw[-1]^=1;target.write_bytes(raw);changes=[target]
                fn=lambda:reader.results(copied,byid[113],"native")
            denied=refusal(fn,spec["expected"])
            after=inventories(copied);original_map={r["path"]:r for r in before};changed=[dict(path=p.relative_to(copied).as_posix(),before=original_map[p.relative_to(copied).as_posix()],after=pin(p))for p in changes]
            record=dict(name=spec["name"],scope=spec,refusal=denied,changes=changed,
                complete_original_inventory=before,complete_damaged_inventory=after,retained_all_damaged_files=True)
            (folder/"CONTROL.json").write_bytes(canonical(record));results.append(dict(name=spec["name"],status="PHYSICAL_REFUSAL_PASS",proof=pin(folder/"CONTROL.json")))
        need(len(results)==8,"all frozen distinct physical refusals")
    for role,root in roots.items():need(inventories(root)==snapshots[role],"physical qualification mutated original input")
    need(source_evidence(a.source)==source,"frozen physical reader source changed")
    (a.output/"BASELINE.json").write_bytes(baseline_path.read_bytes())
    (a.output/"INPUT_INVENTORIES.json").write_bytes(canonical(snapshots))
    result=dict(status="SSH_PHYSICAL_CONTROLS_PASS"if a.mode=="controls"else"SSH_FULL_RELOCATION_PASS",
        group=a.group,mode=a.mode,ordinal=a.ordinal,results=results,guards=guard,source=source,retained_source=source_evidence(retained),
        baseline=inputs["evidence"],inputs=inputs,whole_input_unchanged=True,applications_executed=0,compilers_executed=0,
        completed_applications_replayed=0,unknown_applications_replayed=0,physical_controls_replayed=0,
        public_ssh=False,full_sdk=False)
    (a.output/"RESULT.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
