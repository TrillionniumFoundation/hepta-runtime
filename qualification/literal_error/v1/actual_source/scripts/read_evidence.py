"""Independent complete producer evidence join; never executes applications."""
from pathlib import Path
from common import canonical,decode,owned,pin,require,source_evidence
from guard_refs import tree,saved_guard
from reuse import processes,prepare_build,verify_build
import cases,read_archives,read_capture,controls
def prepare(source,work):
    _,module=prepare_build(source,work/"build-input")
    cases.validate()
    return module
def verify(source,work,module):
    source,work=map(Path,(source,work));identity=source_evidence(source)
    gate=decode(owned(work,"GATE.json").read_bytes());origin=decode(owned(work,"ORIGIN.json").read_bytes())
    require(gate["status"]=="PASS"and gate["schema"]=="hepta.runtime.literal-error.actual-gate.v1"
        and gate["source"]==identity and gate["new_original_calls"]==435 and gate["new_native_calls"]==23591
        and gate["reused_original_cases"]==21901 and gate["new_compiler_calls"]==gate["legacy_original_reexecutions"]
            ==gate["application_replays"]==0 and gate["whole_runtime_replaced"]is False,"complete literal producer scope")
    expected=[("source-check",60),("build-fetch",60),("build-unpack",180),("build-read",180),
        ("legacy-fetch",60),("legacy-unpack",180),("legacy-source",60),("legacy-read",180),("full-read",180)]
    values=processes(work/"processes",gate["processes"],expected);old_source=origin["source"];old_work=Path(origin["work"])
    commands=[]
    commands.append([origin["python"],"-I","-S","-B",str(Path(old_source)/"scripts/gate.py"),"check",
        "--work",str(old_work),"--source-manifest-sha256",identity["manifest"]["sha256"]])
    for kind in("build","legacy"):
        for action in("fetch","unpack"):
            commands.append([origin["python"],"-I","-S","-B",str(Path(old_source)/"scripts/reuse.py"),action,
                "--source",old_source,"--work",str(old_work/(kind+"-input")),"--kind",kind])
        commands.append([origin["python"],"-I","-S","-B",str(Path(old_source)/"scripts/reuse.py"),
            "read-build"if kind=="build"else"check-legacy","--source",old_source,
            "--work",str(old_work/(kind+"-input")),"--kind",kind])
        if kind=="legacy":
            commands.append([origin["python"],"-I","-S","-B",str(old_work/"legacy-input/original/restored/source/scripts/driver.py"),
                "verify","--work",str(old_work/"legacy-input/original/restored/run"),"--source-manifest-sha256",
                decode(owned(source,"LEGACY_INPUT.json").read_bytes())["manifest_sha256"]])
    commands.append([origin["python"],"-I","-S","-B",str(Path(old_source)/"scripts/read_main.py"),
        "--source",old_source,"--application",str(old_work/"application"),"--runtime",str(old_work/"runtime"),
        "--legacy",str(old_work/"legacy-input/original/restored/run/capture"),
        "--admission",str(old_work/"admission/ADMISSION.json")])
    require(len(commands)==len(gate["processes"])and all(r["argv"]==cmd and r["cwd"]==old_source
        for r,cmd in zip(gate["processes"],commands)),"every exact complete pure producer command")
    checked=dict(status="LITERAL_ACTUAL_SOURCE_PASS",source=identity,domain=cases.validate(),
        new_original_calls=435,new_native_calls=23591,legacy_original_reexecutions=0,application_calls=0)
    require(values["source-check"]==gate["source_check"]==decode(owned(work,"SOURCE_CHECK.json").read_bytes())==checked,
        "complete frozen source/domain admission")
    recovered={}
    for kind in("build","legacy"):
        bound=decode(owned(source,"BUILD_INPUT.json"if kind=="build"else"LEGACY_INPUT.json").read_bytes())
        upstream=gate["upstream"][kind]
        fetched=dict(status="PASS",zip={k:bound["artifact"][k]for k in("bytes","sha256")},native_or_rust_executions=0)
        restored=read_archives.verify(source,work/(kind+"-input"),kind);recovered[kind]=restored
        require(values[kind+"-fetch"]==upstream["fetch"]==fetched
            and values[kind+"-unpack"]==upstream["unpack"]==restored,"complete two upstream archive recoveries")
    build=decode(canonical(verify_build(source,work/"build-input",module)))
    build_guard=decode(owned(work,"BUILD_ADMISSION.json").read_bytes())
    require(build_guard==values["build-read"]==gate["upstream"]["build"]["read"]
        and build_guard["evidence"]==build,"complete build admission before applications")
    references=saved_guard(build_guard,{old_source:tree(source),
        str(old_work/"build-input/download"):tree(work/"build-input/download"),
        str(old_work/"build-input/original"):tree(work/"build-input/original")})
    legacy_root=work/"legacy-input/original/restored";legacy=legacy_root/"run/capture"
    legacy_guard=decode(owned(work,"LEGACY_ADMISSION.json").read_bytes())
    legacy_value=legacy_guard["evidence"];legacy_binding=decode(owned(source,"LEGACY_INPUT.json").read_bytes())
    require(values["legacy-source"]==gate["upstream"]["legacy"]["source"]==
        dict(status="COMPLETE_FROZEN_LEGACY_SOURCE_PASS",source_manifest=legacy_binding["manifest_sha256"],
            source_files=34,new_application_calls=0),"complete retained legacy source gate")
    require(legacy_guard==values["legacy-read"]==gate["upstream"]["legacy"]["read"]
        and legacy_value["status"]=="PATH_ERROR_COMPLETE_PASS"and legacy_value["comparison"]["original_cases"]==21901
        and legacy_value["comparison"]["native_cases"]==21901 and legacy_value["comparison"]["controls"]["calls"]==1074
        and legacy_value["source"]["manifest"]==pin(owned(legacy_root/"source","SOURCE_MANIFEST.json"))
        and legacy_value["source"]["files"]==34 and legacy_value["native_or_original_replayed"]is False,
        "full retained old diagnostic qualification without replay")
    old_legacy=old_work/"legacy-input/original/restored"
    references+=saved_guard(legacy_guard,{str(old_legacy/"source"):tree(legacy_root/"source"),
        str(old_legacy/"run/capture"):tree(legacy),str(old_legacy/"run/controls"):tree(legacy_root/"run/controls")})
    require(decode(owned(legacy_root/"run","GATE.json").read_bytes())["status"]=="PASS","qualified legacy producer gate")
    runtime=work/"runtime";artifact=work/"build-input/original/restored/run/artifact"
    artifacts,bundle=read_capture.runtime_files(artifact)
    expected_runtime={p:dict(**pin(owned(artifact,p)),mode=owned(artifact,p).stat().st_mode&0o777)
        for p in set(artifacts)|{"build/formatter.json"}}
    expected_admission=dict(status="FULL_ARCHIVE_ADMISSION_PASS",source=identity,legacy_identity=legacy_value["source"],
        runtime=expected_runtime,build_binding=decode(owned(source,"BUILD_INPUT.json").read_bytes()),
        legacy_binding=legacy_binding,build_proof=pin(work/"BUILD_ADMISSION.json"),
        legacy_proof=pin(work/"LEGACY_ADMISSION.json"),new_compiler_calls=0,new_legacy_original_calls=0)
    admission=work/"admission/ADMISSION.json"
    require(decode(admission.read_bytes())==gate["admission"]==expected_admission
        and list((work/"admission").iterdir())==[admission],"exact original admission identities and four-file runtime")
    application=work/"application"
    require(decode(owned(application,"CAPTURE.json").read_bytes())==gate["application"],"complete actual application custody")
    actual=read_capture.verify(source,application,runtime,legacy,legacy_value["source"],expected_runtime)
    primary=decode(owned(work,"READONLY.json").read_bytes())
    require(primary==values["full-read"]and primary["evidence"]==gate["actual"]==actual,"entire new actual result")
    references+=saved_guard(primary,{old_source:tree(source),str(old_work/"application"):tree(application),
        str(old_work/"runtime"):tree(runtime),str(old_work/"admission"):tree(admission.parent),
        str(old_legacy/"run/capture/original"):tree(legacy/"original"),
        str(old_legacy/"run/capture/processes"):tree(legacy/"processes")})
    require(decode(owned(work/"controls","CONTROLS.json").read_bytes())==gate["controls"],"complete control gate binding")
    physical=controls.verify(source,application,runtime,legacy,admission,work/"controls",actual)
    return dict(status="COMPLETE_UPLOADED_LITERAL_ERROR_EVIDENCE_PASS",actual=actual,upstream_build=build,
        recovered_archives=recovered,physical=physical,retained_primary_guard_full_file_references=references,
        retained_primary_guard_probes=33,retained_physical_guard_probes=110,new_application_calls=0,
        whole_runtime_replaced=False)
