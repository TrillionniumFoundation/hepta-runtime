"""Complete producer, every saved guard and every physical input; no execution."""
from pathlib import Path
from evidence_common import decode,encoded,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
import read_build_evidence,read_capture
from physical_controls import CASES,files
def process_table(folder,rows,expected):
    require(decode((folder/"processes.json").read_bytes())==rows,"complete retained process inventory")
    require([(r["name"],r["timeout_seconds"])for r in rows]==expected,"exact frozen bounded process sequence")
    result={}
    for r in rows:
        require(r["pid"]==r["pgid"]and r["parent_pid"]>0 and r["exit_code"]==0 and r["completed"]is True
            and r["timed_out"]is False and r["stdin"]is None and 0<=r["elapsed_seconds"]<r["timeout_seconds"],
            "natural complete pure/producer process")
        for suffix in("stdout","stderr"):
            v=r[suffix];require(v["file"]==r["name"]+"."+suffix
                and pin(folder/v["file"])=={k:v[k]for k in("bytes","sha256")},"entire retained process streams")
        require(r["stderr"]["bytes"]==0,"hidden process error")
        result[r["name"]]=decode((folder/r["stdout"]["file"]).read_bytes())
    return result
def verify(source,work):
    identity=source_evidence(source);gate=decode((work/"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["schema"]=="hepta.runtime.binary-entropy.actual-gate.v1"
        and gate["source"]==identity and gate["compiled_build_reused"]is True and gate["compiler_executions"]==0
        and gate["original_application_calls"]==gate["native_application_calls"]==97
        and gate["application_replays"]==0 and gate["whole_runtime_replaced"]is False,"complete actual qualification gate")
    expected=[("source-check",60),("build-fetch",60),("build-unpack",180),("build-read",180),
        ("capture-original",180),("capture-native",180),("full-read",180),("physical-controls",180)]
    rows=gate["processes"];returns=process_table(work/"processes",rows,expected)
    require(returns["source-check"]==gate["source_check"]==decode((work/"INPUT_DOMAIN.json").read_bytes())
        and returns["source-check"]["status"]=="ENTROPY_SOURCE_DOMAIN_AND_ACTUAL_CPYTHON_PASS"
        and returns["source-check"]["application_calls"]==0,"original source and runtime admission")
    runtime=work/"runtime"
    require(returns["source-check"]["runtime"]==decode((runtime/"BINDING.json").read_bytes()),"exact original runtime binding")
    require(returns["build-fetch"]==gate["build_fetch"]and returns["build-unpack"]==gate["build_restore"],
        "complete build archive extraction")
    reuse=work/"build-reuse";build_result=read_build_evidence.verify(source,reuse)
    build_guard=decode((work/"BUILD_ADMISSION.json").read_bytes())
    require(build_guard==returns["build-read"]and build_guard["evidence"]==gate["build_admission"]==build_result,
        "all complete original build evidence")
    require((runtime/"BUILD.json").read_bytes()==(reuse/"original/restored/run/build/BUILD.json").read_bytes(),
        "runtime entry map exactly equals the completely admitted build")
    source_origin=rows[0]["cwd"];reuse_origin=rows[1]["argv"][rows[1]["argv"].index("--work")+1]
    references=saved_guard(build_guard,{source_origin:tree(source),
        reuse_origin+"/original":tree(reuse/"original"),reuse_origin+"/download":tree(reuse/"download")})
    actual=read_capture.verify(source,work/"application",runtime)
    primary=decode((work/"READONLY.json").read_bytes())
    require(primary==returns["full-read"]and primary["evidence"]==gate["original_native"]==actual,
        "complete unchanged actual original/native comparison")
    actual_args=rows[6]["argv"];app_origin=actual_args[actual_args.index("--application")+1]
    runtime_origin=actual_args[actual_args.index("--runtime")+1]
    references+=saved_guard(primary,{source_origin:tree(source),app_origin:tree(work/"application"),runtime_origin:tree(runtime)})
    for role,process in zip(("original","native"),rows[4:6]):
        capture=decode((work/"application"/role/"CAPTURE.json").read_bytes())
        require(returns["capture-"+role]==dict(status="PASS",role=role,processes=42,application_calls=97)
            and all(r["parent_pid"]==process["pid"]for r in capture["processes"]),
            "all actual applications belong to their bounded frozen controller")
    controls=decode((work/"controls/CONTROLS.json").read_bytes())
    require(controls==gate["controls"]==returns["physical-controls"]and controls["source"]==identity
        and controls["status"]=="SEVEN_PHYSICAL_REFUSALS_TWO_RELOCATIONS_PASS"and controls["guard_probes"]==99
        and controls["application_executions"]==0 and controls["all_expanded_copies_retained"]is True,
        "complete seven physical controls and two relocations")
    returned=process_table(work/"controls/processes",controls["processes"],[(n,180)for n,_ in CASES])
    original_files={}
    for label,folder in(("source",source),("application",work/"application"),("runtime",runtime)):
        original_files.update({label+"/"+p:v for p,v in files(folder).items()})
    for row,(name,message)in zip(controls["cases"],CASES):
        folder=work/"controls"/name;working=folder/"working"
        value=decode((folder/"READONLY.json").read_bytes())
        require(row["name"]==name and row["process"]==next(r for r in controls["processes"]if r["name"]==name)
            and row["guard"]==pin(folder/"READONLY.json")and returned[name]==value
            and value["evidence"]==row["result"],"every full physical guard and process result")
        observed=files(working)
        require(set(observed)==set(original_files)and len(observed)==row["retained_complete_files"],
            "every actual retained physical-copy file")
        changes={p:dict(before=original_files[p],after=observed[p])for p in observed if observed[p]!=original_files[p]}
        require(changes==row["changes"]and bool(changes)==(message is not None),"all actual physical mutation bytes and modes")
        if message is None:
            require(row["result"]==dict(status="COMPLETE_RELOCATED_ENTROPY_PASS",name=name,qualification=actual),
                "complete semantic result under both relocations")
        else:
            require(row["result"]["status"]=="TARGETED_PHYSICAL_REFUSAL"and row["result"]["name"]==name
                and message in row["result"]["message"],"exact targeted physical refusal")
        labels=row["origins"]
        require(set(labels)=={"source","application","runtime"}and row["original_source"]==source_origin
            and all(Path(v).name==k and Path(v).parent.name=="working"
                and Path(v).parent.parent.name==name for k,v in labels.items()),"fixed historical physical roots")
        mapping={source_origin:tree(source)}
        mapping.update({label:tree(working/name)for name,label in labels.items()})
        references+=saved_guard(value,mapping)
    return dict(status="COMPLETE_UPLOADED_ENTROPY_ACTUAL_EVIDENCE_PASS",actual=actual,upstream_build=build_result,
        retained_guard_full_file_references=references,retained_guards=11,retained_guard_probes=121,
        physical_refusals=7,complete_relocations=2,new_hia_or_original_applications=0,whole_runtime_replaced=False)
