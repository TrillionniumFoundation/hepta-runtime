"""Join every completed boundary process/archive/tree/guard without execution."""
from pathlib import Path
from common import canonical,decode,owned,pin,require,source_evidence
from guard_refs import tree,saved_guard
from reuse import processes,prepare_build,verify_build
import cases,read_archives,read_boundary,original_input
def prepare(source,work):
    _,module=prepare_build(source,work/"build-input")
    cases.total();original_input.prepare(source,work/"profile-input",
        decode(owned(work,"ORIGIN.json").read_bytes())["group"])
    return module
def verify(source,work,module):
    source,work=map(Path,(source,work));identity=source_evidence(source)
    gate=decode(owned(work,"GATE.json").read_bytes());origin=decode(owned(work,"ORIGIN.json").read_bytes())
    group=origin["group"];domain=cases.domain(group);old=Path(origin["work"]);oldsource=Path(origin["source"])
    require(gate["status"]=="PASS"and gate["schema"]=="hepta.runtime.python-json-value.boundary-gate.v1"
        and gate["source"]==identity and gate["group"]==group and gate["native_calls"]==domain["native_calls"]
        and gate["new_original_calls"]==gate["new_compiler_calls"]==gate["application_replays"]==0,
        "complete native-only boundary producer identity")
    rows=gate["processes"]
    expected=[("source-check",60),("build-fetch",60),("build-unpack",180),("build-read-build",180),
        ("profile-fetch",60),("profile-unpack",180),("profile-read",180),("native",60),("full-read",180)]
    values=processes(work/"processes",rows,expected);python=origin["python"]
    commands=[[python,"-I","-S","-B",str(oldsource/"scripts/driver.py"),"check","--work",str(old),
        "--group",group,"--source-manifest-sha256",identity["manifest"]["sha256"]]]
    for action in("fetch","unpack","read-build"):
        commands.append([python,"-I","-S","-B",str(oldsource/"scripts/reuse.py"),action,"--source",str(oldsource),
            "--work",str(old/"build-input"),"--kind","build"])
    for action in("fetch","unpack","read"):
        commands.append([python,"-I","-S","-B",str(oldsource/"scripts/original_input.py"),action,"--source",str(oldsource),
            "--work",str(old/"profile-input"),"--group",group])
    commands.append([python,"-I","-S","-B",str(oldsource/"scripts/native_capture.py"),"--group",group,
        "--capture",str(old/"runtime"),"--output",str(old/"native")])
    commands.append([python,"-I","-S","-B",str(oldsource/"scripts/read_main.py"),"--source",str(oldsource),
        "--work",str(old),"--group",group])
    require(all(r["argv"]==cmd and r["cwd"]==str(oldsource)for r,cmd in zip(rows,commands)),
        "every exact actual bounded boundary producer command")
    pre=decode(owned(work/"admission","processes/processes.json").read_bytes())
    require(pre==rows[:8],"full immutable pre-read boundary process table")
    expected_pre={"processes.json"}
    for row in pre:
        for name in("stdout","stderr"):
            key=row[name]["file"];expected_pre.add(key)
            a=owned(work/"processes",key);b=owned(work/"admission/processes",key)
            require(a.read_bytes()==b.read_bytes()and a.stat().st_mode&0o777==b.stat().st_mode&0o777,
                "whole immutable pre-read process streams and modes")
    require({p.name for p in(work/"admission/processes").iterdir()}==expected_pre,"complete immutable process set")
    checked=dict(status="JSON_VALUE_BOUNDARY_SOURCE_PASS",source=identity,domain=domain,total=cases.total(),application_calls=0)
    require(values["source-check"]==gate["source_check"]==decode(owned(work,"SOURCE_CHECK.json").read_bytes())==checked,
        "complete frozen source and previously unexecuted native boundary domain")
    for name in("ORIGIN.json","BUILD_ADMISSION.json","PROFILE_ADMISSION.json"):
        a=owned(work,name);b=owned(work/"admission",name)
        require(a.read_bytes()==b.read_bytes()and a.stat().st_mode&0o777==b.stat().st_mode&0o777,
            "every immutable boundary admission copy")
    bound=decode(owned(source,"BUILD_INPUT.json").read_bytes())
    fetched=dict(status="PASS",zip={k:bound["artifact"][k]for k in("bytes","sha256")},native_or_rust_executions=0)
    recovered=read_archives.verify(source,work/"build-input","build")
    require(values["build-fetch"]==gate["upstream"]["fetch"]==fetched
        and values["build-unpack"]==gate["upstream"]["unpack"]==recovered,"all reused build archive bytes")
    build=decode(canonical(verify_build(source,work/"build-input",module)))
    guard=decode(owned(work,"BUILD_ADMISSION.json").read_bytes())
    require(guard==values["build-read-build"]==gate["upstream"]["read-build"]and guard["evidence"]==build,
        "entire zero-application native build admission")
    references=saved_guard(guard,{str(oldsource):tree(source),str(old/"build-input/download"):tree(work/"build-input/download"),
        str(old/"build-input/original"):tree(work/"build-input/original")})
    profile=original_input.verify(source,work/"profile-input",group)
    profile_binding=original_input.binding(source,group)
    fetched_profile=dict(status="PASS",zip={k:profile_binding["artifact"][k]for k in("bytes","sha256")},native_or_rust_executions=0)
    profile_guard=decode(owned(work,"PROFILE_ADMISSION.json").read_bytes())
    require(values["profile-fetch"]==gate["profiles"]["fetch"]==fetched_profile
        and values["profile-unpack"]==gate["profiles"]["unpack"]==profile["archive"]
        and values["profile-read"]==gate["profiles"]["read"]==profile_guard and profile_guard["evidence"]==profile,
        "all saved original profile bytes and zero-replay admission")
    artifact=work/"build-input/original/restored/run/artifact";files,bundle=read_boundary.runtime_files(artifact)
    runtime={p:dict(**pin(owned(artifact,p)),mode=owned(artifact,p).stat().st_mode&0o777)
        for p in set(files)|{"build/module.json"}}
    admission=dict(source=identity,domain=domain,runtime=runtime,build_proof=pin(work/"admission/BUILD_ADMISSION.json"),
        profile_proof=pin(work/"admission/PROFILE_ADMISSION.json"),new_original_calls=0)
    require(admission==gate["admission"]==decode(owned(work/"admission","ADMISSION.json").read_bytes()),
        "exact byte-bound copied runtime and application admission")
    require({p.name for p in(work/"admission").iterdir()}==
        {"ORIGIN.json","BUILD_ADMISSION.json","PROFILE_ADMISSION.json","ADMISSION.json","processes"},
        "complete immutable admission set")
    require(gate["native"]==values["native"]==decode(owned(work/"native","CAPTURE.json").read_bytes()),
        "actual worker identity and full output custody")
    actual=read_boundary.verify(source,work,group)
    primary=decode(owned(work,"READONLY.json").read_bytes())
    require(primary==values["full-read"]and primary["evidence"]==gate["comparison"]==actual,
        "complete independently repeated pure boundary comparison")
    mapping={str(oldsource):tree(source)}
    for name in("build-input","profile-input","runtime","native","admission"):mapping[str(old/name)]=tree(work/name)
    references+=saved_guard(primary,mapping)
    return dict(status="COMPLETE_UPLOADED_JSON_VALUE_BOUNDARY_EVIDENCE_PASS",group=group,actual=actual,
        upstream_build=build,recovered_build_archive=recovered,retained_original_profile=profile,
        saved_primary_guard_file_references=references,new_application_calls=0,application_replays=0)
