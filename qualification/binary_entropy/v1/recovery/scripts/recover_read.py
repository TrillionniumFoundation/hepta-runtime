"""Read the complete failed archive and its successful applications without replay."""
from pathlib import Path
import importlib.util
from evidence_common import decode,encoded,pin,require,sha,source_evidence
from protocol import events,signed,u
from read_build_evidence import tree,saved_guard
import read_build_evidence,read_capture
def exact_source(root,old):
    expected=root/"qualified";a={p.relative_to(expected).as_posix():p for p in expected.rglob("*")if p.is_file()}
    b={p.relative_to(old).as_posix():p for p in old.rglob("*")if p.is_file()}
    require(set(a)==set(b),"all original frozen source paths")
    for name in a:require(a[name].read_bytes()==b[name].read_bytes()
        and a[name].stat().st_mode&0o777==b[name].stat().st_mode&0o777==0o644,"every original frozen source byte and mode")
    return source_evidence(old)
def patch(root,old):
    value=decode((root/"READER_PATCH.json").read_bytes())
    before=(old/"scripts/read_capture.py").read_bytes();after=(root/"scripts/read_capture.py").read_bytes()
    require(pin(old/"scripts/read_capture.py")=={k:value["before"][k]for k in("bytes","sha256")}
        and pin(root/"scripts/read_capture.py")=={k:value["after"][k]for k in("bytes","sha256")},"exact pure reader before/after")
    text=before.decode()
    for item in value["replacements"]:
        require(text.count(item["before"])==1,"unique pure reader correction")
        text=text.replace(item["before"],item["after"])
    require(text.encode()==after and value["production_hia_native_and_inputs_unchanged"]is True
        and value["new_application_executions"]==0,"only the declared pure correction")
    for name in("protocol.py","entropy_model.py","read_journal.py","read_build_evidence.py","build_reuse.py",
        "evidence_common.py","readonly.py","process.py","physical_controls.py"):
        require((root/"scripts"/name).read_bytes()==(old/"scripts"/name).read_bytes(),"unchanged complete reader dependency: "+name)
    return value
def processes(run,gate):
    rows=decode((run/"processes/processes.json").read_bytes())
    expected=[("source-check",60),("build-fetch",60),("build-unpack",180),("build-read",180),
        ("capture-original",180),("capture-native",180),("full-read",180)]
    require(rows==gate["processes"]and[(r["name"],r["timeout_seconds"])for r in rows]==expected,"exact original process prefix")
    values={}
    for i,r in enumerate(rows):
        require(r["pid"]==r["pgid"]and r["parent_pid"]>0 and r["completed"]is True and r["timed_out"]is False
            and r["exit_code"]==(1 if i==6 else 0)and 0<=r["elapsed_seconds"]<r["timeout_seconds"]
            and r["stdin"]is None,"actual original terminal process is FAIL or PASS, never UNKNOWN")
        for name in("stdout","stderr"):
            v=r[name];require(v["file"]==r["name"]+"."+name
                and pin(run/"processes"/v["file"])=={k:v[k]for k in("bytes","sha256")},"all original process bytes")
        if i==6:
            err=(run/"processes"/r["stderr"]["file"]).read_text()
            require(r["stdout"]["bytes"]==0 and "ValueError: real successful stat/close/transfer response"in err,
                "exact old pure-reader failure and empty partial return")
        else:
            require(r["stderr"]["bytes"]==0,"no hidden application or build error")
            values[r["name"]]=decode((run/"processes"/r["stdout"]["file"]).read_bytes())
    return rows,values
def verify(root,input_work,old_module):
    binding=source_evidence(root);bound=decode((root/"CAPTURE_INPUT.json").read_bytes())
    require(pin(input_work/"download/complete.zip")=={k:bound["artifact"][k]for k in("bytes","sha256")},
        "full immutable original upload")
    base=input_work/"original/restored";old=base/"source";run=base/"run"
    original_identity=exact_source(root,old);correction=patch(root,old)
    gate=decode((run/"GATE.json").read_bytes())
    require(gate["status"]=="FAIL"and gate["source"]==original_identity and gate["application_execution_started"]is True
        and gate["error_type"]=="RuntimeError"and gate["message"]=="recorded command failed: full-read"
        and gate["unknown_inputs_never_replayed"]is True,"original known pure-stage failure")
    rows,values=processes(run,gate)
    require(values["source-check"]==decode((run/"INPUT_DOMAIN.json").read_bytes())
        and values["source-check"]["status"]=="ENTROPY_SOURCE_DOMAIN_AND_ACTUAL_CPYTHON_PASS"
        and values["source-check"]["application_calls"]==0,"whole source and original runtime admission")
    for role,p in zip(("original","native"),rows[4:6]):
        capture=decode((run/"application"/role/"CAPTURE.json").read_bytes())
        require(values["capture-"+role]==dict(status="PASS",role=role,processes=42,application_calls=97)
            and all(r["parent_pid"]==p["pid"]for r in capture["processes"]),"all 194 original/native applications already completed")
    build=read_build_evidence.verify(old,run/"build-reuse")
    admission=decode((run/"BUILD_ADMISSION.json").read_bytes())
    require(admission==values["build-read"]and admission["evidence"]==build,"complete original build admission")
    origins=rows[0]["cwd"];reuse=rows[1]["argv"][rows[1]["argv"].index("--work")+1]
    references=saved_guard(admission,{origins:tree(old),reuse+"/original":tree(run/"build-reuse/original"),
        reuse+"/download":tree(run/"build-reuse/download")})
    require((run/"runtime/BUILD.json").read_bytes()==(run/"build-reuse/original/restored/run/build/BUILD.json").read_bytes(),
        "actual immutable runtime export map")
    actual=read_capture.verify(old,run/"application",run/"runtime")
    # old_module was imported before the guard; no code or native capability is loaded inside it.
    failures=[];checks=0
    for case in decode((old/"DOMAIN.json").read_bytes())["cases"]:
        folder=run/"application/native"/case["name"]
        captured=[decode(s)for s in(folder/"results.jsonl").read_bytes().splitlines()]
        ev=events((folder/"events.bin").read_bytes());filters=list(captured[0]["filters"])
        for row in captured[1:-1]:
            for a in row["actions"]:
                if "filter"in a:filters.append(a["filter"])
            part=[e for e in ev if row["event_start"]["bytes"]<=e["start"]<row["event_end"]["bytes"]];caps=[]
            for i,e in enumerate(part):
                if e["kind"]==8:
                    r=part[i+1];require(r["kind"]==9,"all actual diagnostic syscall replies")
                    q=e["data"];data=r["data"];caps.append(dict(operation=u(q,24),a=u(q,32),b=u(q,40),
                        return_value=signed(u(data,24)),payload_hex=data[96:].hex(),sequence=u(q,16)))
            try:old_module.faults(case,caps,filters)
            except ValueError as error:failures.append(dict(case=case["name"],index=row["index"],message=str(error),capabilities=caps))
            checks+=1
    require(checks==97 and len(failures)==1 and failures[0]["case"]=="cache-closed"and failures[0]["index"]==1
        and failures[0]["message"]=="real successful stat/close/transfer response"
        and failures[0]["capabilities"][0]["operation"]==3 and failures[0]["capabilities"][0]["return_value"]==-9
        and failures[0]["capabilities"][0]["payload_hex"]=="","only the demonstrated closed-cache EBADF reader defect")
    return dict(status="ENTROPY_ALL_COMPLETED_APPLICATIONS_RECOVERED_WITHOUT_REPLAY",source=binding,
        original_source=original_identity,original_archive=bound,original_terminal_status="FAIL",
        correction=correction,diagnosis=dict(pure_case_checks=checks,failures=failures),upstream_build=build,
        original_guard_full_file_references=references,actual=actual,new_application_executions=0,
        source_hia_asm_and_actual_inputs_unchanged=True,whole_runtime_replaced=False)
def prepare(input_work):
    old=input_work/"original/restored/source";run=input_work/"original/restored/run"
    import build_reuse
    build_reuse.prepare_imports(run/"build-reuse")
    spec=importlib.util.spec_from_file_location("unmodified_entropy_capture_reader",old/"scripts/read_capture.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
