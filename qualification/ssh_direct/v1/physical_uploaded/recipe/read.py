#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read completed physical-control artifacts only; never rerun a control or application."""
from pathlib import Path
import argparse,os,re,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,need,pin,raw_pin,unpack,inventories
from common import source_evidence
PROTECTED=[]
def inside(p,r):
    try:return os.path.commonpath((str(Path(p).absolute()),str(r)))==str(r)
    except(TypeError,ValueError):return False
def audit(event,args):
    if event.startswith(("subprocess.","os.exec","os.spawn","os.posix_spawn"))or event in("os.system","ctypes.dlopen"):
        raise PermissionError("final reader cannot execute applications or controls")
    if event=="open":
        p,m,f=args
        if isinstance(p,(str,bytes,os.PathLike))and any(inside(p,r)for r in PROTECTED)and((isinstance(m,str)and any(x in m for x in"wax+"))or f&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)):
            raise PermissionError("immutable final input")
    effects={"os.remove":(0,),"os.rmdir":(0,),"os.mkdir":(0,),"os.rename":(0,1),"os.chmod":(0,),"os.utime":(0,),"os.link":(0,1),"os.symlink":(1,)}
    if event in effects and any(i<len(args)and any(inside(args[i],r)for r in PROTECTED)for i in effects[event]):raise PermissionError("immutable final metadata")
def guard(root,output):
    f=next(x for x in root.rglob("*")if x.is_file())
    plans=[("write",lambda:f.open("wb")),("append",lambda:f.open("ab")),("unlink",lambda:os.unlink(f)),
        ("chmod",lambda:os.chmod(f,0o600)),("utime",lambda:os.utime(f,None)),("rename",lambda:os.rename(f,output/"bad")),
        ("mkdir",lambda:os.mkdir(root/"bad")),("link",lambda:os.link(f,output/"badlink")),("symlink",lambda:os.symlink("bad",root/"badlink")),
        ("shell",lambda:os.system("exit 0")),("exec",lambda:os.execv("/usr/bin/true",["true"]))]
    out=[]
    for name,fn in plans:
        try:fn()
        except PermissionError as e:out.append(dict(name=name,status="REFUSED_BEFORE_EFFECT",reason=str(e)))
        else:raise ValueError("final guard failed "+name)
    return out
def metadata_without_time(r):return{k:v for k,v in r.items()if k!="mtime_ns"}
def physical(root,recipe,plan,receipt):
    before=decode((root/"INPUT_INVENTORIES.json").read_bytes())["native"]
    baseline_root=root/"physical/complete_process_ledger/complete-damaged-input"
    inventory=inventories(baseline_root);old={r["path"]:r for r in before};actual={r["path"]:r for r in inventory}
    need(set(actual)==set(old),"complete preserved baseline physical input")
    for name,row in actual.items():
        if name=="LEDGER.json":continue
        need(row==old[name],"complete physical baseline original bytes/mode/mtime")
    ledger=decode((baseline_root/"LEDGER.json").read_bytes());ledger["applications_started"]-=1
    need(raw_pin(canonical(ledger))=={k:old["LEDGER.json"][k]for k in("bytes","sha256")},"whole original ledger recovered by exact one-field mutation")
    wanted={x["name"]:x for x in plan["controls"]};got={x["name"]:x for x in receipt["results"]}
    need(set(got)==set(wanted)and len(got)==8,"all original distinct physical refusals")
    for name,spec in wanted.items():
        folder=root/"physical"/name;proof=folder/"CONTROL.json";record=decode(proof.read_bytes());damaged=folder/"complete-damaged-input"
        need(pin(proof)==got[name]["proof"]and got[name]["status"]=="PHYSICAL_REFUSAL_PASS","complete original physical receipt")
        need(record["scope"]==spec and record["retained_all_damaged_files"]is True and spec["expected"]in record["refusal"]["message"],"exact admitted refusal and scope")
        need(inventories(damaged)==record["complete_damaged_inventory"],"all retained physically damaged bytes/modes/mtime")
        if spec["kind"]=="source":original=recipe/"retained-reader/remaining";expected=inventories(original)
        elif spec["kind"]=="root":original=baseline_root;expected=before
        else:
            original=baseline_root/("case-"+str(spec["case"]));prefix="case-"+str(spec["case"])+"/"
            expected=[dict(r,path=r["path"][len(prefix):])for r in before if r["path"].startswith(prefix)]
        need(record["complete_original_inventory"]==expected,"entire pre-mutation object bound to original capture")
        oldmap={r["path"]:r for r in expected};newmap={r["path"]:r for r in record["complete_damaged_inventory"]}
        changed={r["path"]:r for r in record["changes"]};need(set(oldmap)==set(newmap),"control preserves complete original file/directory set")
        for path,row in newmap.items():
            if path in changed:
                need(changed[path]["before"]==oldmap[path]and changed[path]["after"]==pin(damaged/path),"every modified byte pin")
                need(row["mode"]==oldmap[path]["mode"]and row["kind"]==oldmap[path]["kind"],"physical mutation retains type/mode")
            else:need(row==oldmap[path],"all unmodified control bytes and metadata remain exact")
        if name=="complete_process_ledger":
            need(len(changed)==1 and decode((damaged/"LEDGER.json").read_bytes())["applications_started"]==ledger["applications_started"]+1,"actual complete ledger mutation")
        elif name=="honestly_resealed_wrong_reaped_pid":
            need(len(changed)==2 and"PROCESS.json"in changed,"kernel mutation and honest process reseal")
            trace=next(path for path in changed if path.startswith("kernel."))
            actual_receipt=decode((damaged/"PROCESS.json").read_bytes());original_receipt=decode((original/"PROCESS.json").read_bytes())
            expected_receipt=decode(canonical(original_receipt));expected_receipt["kernel_files"][trace]=pin(damaged/trace)
            need(actual_receipt==expected_receipt,"entire actual process receipt honestly resealed, no stale outer hash")
            left=(original/trace).read_text().splitlines();right=(damaged/trace).read_text().splitlines()
            need(len(left)==len(right),"complete kernel trace retained")
            differences=[(a,b)for a,b in zip(left,right)if a!=b];need(len(differences)==1,"only original PID return physically changed")
            a,b=differences[0];pat=r"^(.*(?:wait4\(|<\.\.\. wait4 resumed>).*?\)\s+=\s+)([0-9]+)(.*)$"
            x=re.match(pat,a);y=re.match(pat,b);need(x and y and x[1]==y[1]and x[3]==y[3]and int(y[2])==int(x[2])+1000000,"exact wrong-child reaping mutation")
        else:
            need(len(changed)==1,"one complete raw-buffer mutation");target=next(iter(changed))
            left=(original/target).read_bytes();right=(damaged/target).read_bytes();need(len(left)==len(right),"entire buffer retained")
            expected=bytearray(left)
            if name=="exact_raw_hia_source"or name=="last_byte_of_complete_stdout":offset=len(left)-1
            else:
                h=struct.unpack_from("<16Q",left);il,wc,oc=h[10:13]
                offset={"entire_readonly_input":128+il+wc+oc+il-1,"entire_workspace_tail":128+il+wc+oc+il+wc-1,"entire_output_tail":h[1]-1,"actual_raw_hia_return":72}[name]
            expected[offset]^=1;need(bytes(expected)==right,"exact physical single-byte change with complete tails retained")
    return dict(controls=8,original_files=len(old),original_bytes=sum(r.get("bytes",0)for r in before if r["kind"]=="file"))
def main():
    p=argparse.ArgumentParser()
    for n in("source","downloads","stage","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();sys.addaudithook(audit);need(not a.output.exists()and not a.stage.exists(),"fresh final artifact read")
    a.output.mkdir();a.stage.mkdir();PROTECTED.append(a.source.resolve());binding=source_evidence(a.source);inputs=decode((a.source/"INPUTS.json").read_bytes())
    records=[];relocations={};controls=0;guard_count=0;total_files=total_bytes=0
    for i,spec in enumerate(inputs["physical"]):
        root=unpack(a.downloads/(str(spec["artifact"])+".zip"),a.stage/str(i),spec);recipe=root.parent/"recipe-source"
        need(pin(recipe/"SOURCE_MANIFEST.json")==inputs["source_manifest"],"exact original physical reader source")
        source_evidence(recipe);PROTECTED.extend([root.resolve(),recipe.resolve(),(a.downloads/(str(spec["artifact"])+".zip")).resolve()])
        snap=inventories(root);fresh=guard(root,a.output);guard_count+=len(fresh)
        result=decode((root/"RESULT.json").read_bytes());plan=decode((recipe/"INPUTS.json").read_bytes())
        need(result["source"]==source_evidence(recipe)and result["whole_input_unchanged"]is True,"actual original source/readonly boundary")
        need((result["group"],result["mode"],result["ordinal"])==(spec["group"],spec["mode"],spec["ordinal"]),"exact frozen completed physical phase")
        need(all(result[n]==0 for n in("applications_executed","compilers_executed","completed_applications_replayed","unknown_applications_replayed","physical_controls_replayed")),"zero completed/UNKNOWN replay")
        need(len(result["guards"])==11 and len({r["name"]for r in result["guards"]})==11 and all(r["status"]=="REFUSED_BEFORE_EFFECT"for r in result["guards"]),"original eleven boundaries retained")
        group=plan["groups"][result["group"]];need(result["inputs"]==group and pin(root/"BASELINE.json")==group["evidence"],"complete actual baseline and capture identity")
        if result["mode"]=="controls":
            need(result["status"]=="SSH_PHYSICAL_CONTROLS_PASS","original physical qualification succeeded")
            summary=physical(root,recipe,plan,result);controls+=summary["controls"]
        else:
            need(result["status"]=="SSH_FULL_RELOCATION_PASS"and len(result["results"])==1,"original entire relocation completed")
            rr=result["results"][0];need(rr["whole_object_equal"]is True and rr["group"]==result["group"]and rr["ordinal"]==result["ordinal"],"original whole object closure")
            proof=root/"comparison/EVIDENCE.json";need(pin(proof)==rr["evidence"]==group["evidence"]and proof.read_bytes()==(root/"BASELINE.json").read_bytes(),"every relocated proof byte and object equal")
            need(rr["original_absolute_paths_blocked"]and rr["relocated_roots"]["native"]!=rr["relocated_roots"]["original"],"original paths inaccessible and new owned roots distinct")
            relocations.setdefault(result["group"],{})[result["ordinal"]]=rr
            summary=dict(whole_evidence=pin(proof),ordinal=result["ordinal"],case_ids=group["ids"])
        need(inventories(root)==snap,"final reader changed original artifact")
        total_files+=sum(r["kind"]=="file"for r in snap);total_bytes+=sum(r.get("bytes",0)for r in snap if r["kind"]=="file")
        records.append(dict(input=spec,summary=summary,guards=fresh,complete_result=pin(root/"RESULT.json")))
    need(controls==8 and set(relocations)=={"probes","remaining"},"complete physical evidence set")
    for g,rows in relocations.items():
        need(set(rows)=={1,2}and rows[1]["evidence"]==rows[2]["evidence"],"two complete actual relocations per cohort")
        need(rows[1]["relocated_roots"]!=rows[2]["relocated_roots"],"two physically distinct complete expansions")
    need(source_evidence(a.source)==binding,"final source changed")
    result=dict(status="SSH_NATIVE_ACTOR_13_LIFECYCLE_UPLOADED_PHYSICAL_PASS",cases=inputs["case_ids"],actual_processes=inputs["actual_processes"],
        requests_each=inputs["requests_each"],hia_calls=inputs["hias"],full_buffer_bytes=inputs["full_buffer_bytes"],physical_refusals=controls,
        complete_relocations_per_cohort=2,cohorts=2,complete_files_read=total_files,complete_bytes_read=total_bytes,fresh_guards=guard_count,
        new_applications=0,new_compilers=0,physical_controls_replayed=0,records=records,source=binding,public_ssh=False,full_sdk=False,old_stack_removed=False)
    (a.output/"RESULT.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
