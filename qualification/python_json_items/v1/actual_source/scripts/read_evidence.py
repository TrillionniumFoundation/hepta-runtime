"""Independent full archive/source/process/application join; no application or control replay."""
from pathlib import Path
from common import canonical,decode,owned,pin,require,source_evidence
from guard_refs import tree,saved_guard
from reuse import processes,prepare_build,verify_build
import cases,read_archives,read_capture,read_runtime,controls
def prepare(source,work):
    _,module=prepare_build(source,work/"build-input");cases.domain();return module
def verify(source,work,module):
    source,work=map(Path,(source,work));identity=source_evidence(source)
    gate=decode(owned(work,"GATE.json").read_bytes());origin=decode(owned(work,"ORIGIN.json").read_bytes())
    shard=origin["shard"];domain=cases.shard_domain(shard)
    require(gate["status"]=="PASS"and gate["schema"]=="hepta.runtime.python-json-items.actual-gate.v2"
        and gate["source"]==identity and gate["shard"]==shard and gate["new_original_calls"]==domain["semantic_cases"]
        and gate["new_native_calls"]==domain["semantic_cases"]+domain["private_native_calls"]
        and gate["new_compiler_calls"]==gate["application_replays"]==0 and gate["whole_runtime_replaced"]is False,
        "complete decoder producer scope")
    expected=[("source-check",60),("build-fetch",60),("build-unpack",180),("build-read-build",180),("runtime-source",60),("full-read",180)]
    values=processes(work/"processes",gate["processes"],expected)
    old_source=origin["source"];old_work=Path(origin["work"]);python=origin["python"]
    commands=[[python,"-I","-S","-B",str(Path(old_source)/"scripts/gate.py"),"check","--work",str(old_work),
        "--source-manifest-sha256",identity["manifest"]["sha256"],"--shard",str(shard)]]
    for action in("fetch","unpack","read-build"):
        commands.append([python,"-I","-S","-B",str(Path(old_source)/"scripts/reuse.py"),action,
            "--source",old_source,"--work",str(old_work/"build-input"),"--kind","build"])
    commands.append([python,"-I","-S","-B",str(Path(old_source)/"scripts/runtime.py"),"--output",str(old_work/"original-runtime")])
    commands.append([python,"-I","-S","-B",str(Path(old_source)/"scripts/read_main.py"),"--source",old_source,
        "--application",str(old_work/"application"),"--runtime",str(old_work/"runtime"),
        "--original-runtime",str(old_work/"original-runtime"),"--admission",str(old_work/"admission/ADMISSION.json")])
    require(all(r["argv"]==cmd and r["cwd"]==old_source for r,cmd in zip(gate["processes"],commands)),
        "all exact original producer commands")
    checked=dict(status="PYTHON_JSON_ITEMS_ACTUAL_SOURCE_PASS",source=identity,domain=cases.domain(),selected=domain,
        new_original_calls=domain["semantic_cases"],new_native_calls=domain["semantic_cases"]+domain["private_native_calls"],
        application_calls=0)
    require(values["source-check"]==gate["source_check"]==decode(owned(work,"SOURCE_CHECK.json").read_bytes())==checked,
        "complete actual frozen source/domain admission")
    bound=decode(owned(source,"BUILD_INPUT.json").read_bytes())
    fetched=dict(status="PASS",zip={k:bound["artifact"][k]for k in("bytes","sha256")},native_or_rust_executions=0)
    recovered=read_archives.verify(source,work/"build-input","build")
    require(values["build-fetch"]==gate["upstream"]["fetch"]==fetched
        and values["build-unpack"]==gate["upstream"]["unpack"]==recovered,"complete reused build archive")
    build=decode(canonical(verify_build(source,work/"build-input",module)))
    guard=decode(owned(work,"BUILD_ADMISSION.json").read_bytes())
    require(guard==values["build-read-build"]==gate["upstream"]["read-build"]and guard["evidence"]==build,
        "complete retained zero-application build admission")
    references=saved_guard(guard,{old_source:tree(source),str(old_work/"build-input/download"):tree(work/"build-input/download"),
        str(old_work/"build-input/original"):tree(work/"build-input/original")})
    runtime=work/"runtime";original_runtime=work/"original-runtime"
    runtime_value=read_runtime.verify(source,original_runtime)
    require(runtime_value==values["runtime-source"]==gate["original_runtime"],"complete actual original runtime custody")
    artifact=work/"build-input/original/restored/run/artifact";artifacts,bundle=read_capture.runtime_files(artifact)
    expected_runtime={p:dict(**pin(owned(artifact,p)),mode=owned(artifact,p).stat().st_mode&0o777)
        for p in set(artifacts)|{"build/module.json"}}
    expected_admission=dict(status="FULL_ARCHIVE_ADMISSION_PASS",source=identity,runtime=expected_runtime,
        original_runtime=pin(original_runtime/"RUNTIME.json"),build_binding=bound,build_proof=pin(work/"BUILD_ADMISSION.json"),
        new_compiler_calls=0,new_application_calls=0)
    admission=work/"admission/ADMISSION.json"
    require(decode(admission.read_bytes())==gate["admission"]==expected_admission
        and list(admission.parent.iterdir())==[admission],"complete actual runtime admission")
    application=work/"application"
    require(decode(owned(application,"CAPTURE.json").read_bytes())==gate["application"],"entire actual worker custody")
    actual=read_capture.verify(source,application,runtime,original_runtime,admission)
    primary=decode(owned(work,"READONLY.json").read_bytes())
    require(primary==values["full-read"]and primary["evidence"]==gate["actual"]==actual,"entire actual result comparison")
    references+=saved_guard(primary,{old_source:tree(source),str(old_work/"application"):tree(application),
        str(old_work/"runtime"):tree(runtime),str(old_work/"original-runtime"):tree(original_runtime),
        str(old_work/"admission"):tree(admission.parent)})
    physical=None
    if shard==0:
        require(gate["controls"]==decode(owned(work/"controls","CONTROLS.json").read_bytes()),"entire physical gate binding")
        physical=controls.verify(source,application,runtime,original_runtime,admission,work/"controls",actual)
    else:require(gate["controls"]is None and not(work/"controls").exists(),"controls occur only in their frozen shard")
    return dict(status="COMPLETE_UPLOADED_PYTHON_JSON_ITEMS_EVIDENCE_PASS",actual=actual,upstream_build=build,
        recovered_build_archive=recovered,physical=physical,saved_primary_guard_file_references=references,
        new_application_calls=0,physical_controls_reexecuted=False,whole_runtime_replaced=False)
