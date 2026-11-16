"""Complete offline admission of the current original handler and actual SDK wires."""
from pathlib import Path
import gzip, json, stat, struct, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import common as c
PREPARED={}
INSTALLED={"batch_edit","directory_create","directory_move","effective_config","execution_shadow_admit",
    "file_move","host_list","text_editor","view","weight_bellman_plan","workdir"}

def prepare(package):
    package=Path(package).absolute();key=str(package)
    if key in PREPARED:return PREPARED[key]
    c.source_check(package)
    sys.path.insert(0,str(package/"source"));sys.path.insert(0,str(package/"public"))
    import configured_common,public_domain,public_common,read_public_configured
    old=c.source_module("configured_retained_original_reader",package/"source/retained/pipeline/policy_base/reference/verify.py")
    PREPARED[key]=(configured_common,public_domain,public_common,read_public_configured,old)
    return PREPARED[key]

def selected(body,mask):
    result=dict(body)
    result["tools"]=[tool for tool in body["tools"] if tool["name"] in INSTALLED
        and (tool["name"]!="batch_edit" or mask&1) and (tool["name"]!="weight_bellman_plan" or mask&2)]
    return result

def verify_build(package,original,output,*,expected_roots,expected_parent):
    component,domain,shared,public,old=prepare(package)
    c.source_check(package)
    previous=old.verify(original)
    r=c.Reader(output);report=r.document("result.json")
    c.need(report["schema"]=="hepta.runtime.configured-catalog-sdk-build.v1"
        and report["status"]=="FRESH_CURRENT_SDK_EXECUTION_COMPLETE","fresh additive SDK result")
    c.need(report["target_commit"]==c.TARGET and report["target_tree"]==c.TREE
        and report["package"]==c.pin(c.regular(package/"PACKAGE.json")),"fresh original source identity")
    c.need(report["roots"]==expected_roots,"source/producer roots independently bound")
    for key in ("pid","parent_pid","pgid"):c.need(type(report[key])is int and report[key]>0,"observer process identity")
    c.need(report["pid"]==expected_parent["pid"] and report["parent_pid"]==expected_parent["parent_pid"]
        and report["pgid"]==expected_parent["pgid"],"actual outer process custody")
    c.need(report["same_ci_reference_target_reused"] is True and report["original_functions_unchanged"] is True
        and report["public_handler_requests"]==0,"same-CI locked reference build boundary")
    c.need(all(report[key] is False for key in c.FALSE_FLAGS),"qualification scope")
    c.need(type(report["elapsed_ns"])is int and 0<report["elapsed_ns"]<=300_000_000_000,"additive outer build deadline")
    target=expected_roots["target"];origin=expected_roots["output"];old_origin=expected_roots["original"]
    command=["cargo","build","--locked","--example","hia_configured_public","--example","hia_configured_projection"]
    build,streams=c.process(r,"build-sdk-observers",command=command,cwd=target,timeout=180,parent=report)
    c.need(b"Compiling hepta-runtime" in streams["stderr"],"actual added observer compilation")
    env={"RUSTUP_TOOLCHAIN":"1.95.0","CARGO_TARGET_DIR":old_origin+"/cargo-target","CARGO_BUILD_JOBS":"2",
        "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0","CARGO_ENCODED_RUSTFLAGS":"","LC_ALL":"C",
        "PYTHONDONTWRITEBYTECODE":"1"}
    c.need(build["controlled_environment"]==env and report["build_process"]==build,"controlled Cargo invocation")
    mapping={"hia_configured_public":"public_reference.rs","hia_configured_projection":"configured_projection.rs"}
    c.need(set(report["binaries"])==set(mapping) and set(report["observer_sources"])==set(mapping),"exact additive observers")
    for name,source in mapping.items():
        row=report["binaries"][name]
        c.need(row["origin"]==old_origin+"/cargo-target/debug/examples/"+name
            and row["saved"]==name+".elf","compiled executable provenance")
        binary=r.raw(row["saved"],row["pin"])
        c.need(binary.startswith(b"\x7fELF\x02") and stat.S_IMODE((output/row["saved"]).stat().st_mode)==0o500,"complete executable")
        c.need(report["observer_sources"][name]==c.pin(c.regular(package/"ci"/source)),"exact Rust observer bytes")
    input_raw=r.raw("projection.input.bin")
    replay,replay_streams=c.process(r,"sdk-projection",command=[origin+"/hia_configured_projection.elf"],
        cwd=target,timeout=60,parent=report,stdin=input_raw,empty_stderr=True)
    c.need(replay["controlled_environment"]==env and report["replay_process"]==replay,"actual SDK replay custody")
    output_raw=replay_streams["stdout"];index=r.document("projection-index.json")
    iat=oat=sequence=0;actual=[];wire_rows=[]
    for profile in (None,*range(8)):
        label="profile-disabled" if profile is None else "profile-"+str(profile)
        observation=c.read_json(original/"processes"/(label+".stdout"))
        flags=0 if profile is None else 1|(profile<<1)
        for case in observation["list_cases"]:
            modern=int(case["protocol_version"] is not None and case["protocol_version"]>="2026-07-28")
            raw=case["result_wire"].encode();body=c.parse(raw)
            for mask in range(4):
                expected=selected(body,mask)
                for policy in (0,2 if modern else 1):
                    packet=b"HCATSP02"+struct.pack("<7Q",sequence,flags,modern,policy,len(raw),mask,0)+raw
                    c.need(input_raw[iat:iat+len(packet)]==packet,"complete original projection input")
                    iat+=len(packet)
                    c.need(output_raw[oat:oat+8]==b"HCATSD02","SDK output frame")
                    header=struct.unpack_from("<7Q",output_raw,oat+8)
                    c.need(header[:5]==(sequence,flags,modern,policy,len(expected["tools"]))
                        and header[6]==mask,"actual typed serializer output association")
                    size=header[5];wire=output_raw[oat+64:oat+64+size]
                    c.need(len(wire)==size,"complete SDK body")
                    oat+=64+size
                    if policy==0:c.need(c.parse(wire)==expected,"all typed Tool and result fields preserved")
                    else:
                        fragment=component.projected_asset(package/"source",modern,flags,mask)
                        c.need(fragment.startswith(b',"result":') and fragment.endswith(b"}"),"catalog fragment framing")
                        c.need(wire==fragment[len(b',"result":'):-1],"exact current SDK peer-policy bytes")
                        wire_rows.append({"sequence":sequence,"flags":flags,"mask":mask,"modern":modern,"wire":c.pin(wire)})
                    actual.append({"sequence":sequence,"profile":profile,"flags":flags,
                        "protocol_version":case["protocol_version"],"cursor_case":case["cursor_case"],
                        "modern":modern,"policy":policy,"installed":mask,"input":c.pin(packet)})
                    sequence+=1
    c.need(sequence==report["projection_records"]==1728 and actual==index and iat==len(input_raw)
        and oat==len(output_raw),"complete original/mask/SDK input and output domain")
    r.complete()
    return {"status":"COMPLETE_CURRENT_CONFIGURED_SDK_READONLY_PASS","direct_original":previous,
        "actual_sdk_records":1728,"typed_records":864,"peer_wire_records":864,"records":wire_rows,
        "files":r.files,"binaries":report["binaries"],"process_launches":0,"native_execution":False,"rust_execution":False}

def verify_public(package,original,build,output,*,expected_parent,expected_origin,expected_binary,native):
    component,domain,shared,public,old=prepare(package)
    c.source_check(package)
    r=c.Reader(output);report=r.document("result.json")
    c.need(report["schema"]=="hepta.runtime.configured-catalog-public-original.v1"
        and report["status"]=="ACTUAL_ORIGINAL_CAPTURE","actual public original completion")
    c.need(report["package"]==c.pin(c.regular(package/"PACKAGE.json")) and report["binary"]==expected_binary
        and report["binary_origin"]==expected_origin,"current public executable identity")
    for key in ("pid","parent_pid","pgid"):c.need(type(report[key])is int and report[key]>0,"public observer PID")
    c.need(all(report[key]==expected_parent[key] for key in ("pid","parent_pid","pgid")),"public observer actual process binding")
    c.need(report["pid"]==report["pgid"] and type(report["original_deadline_seconds"])is int
        and report["original_deadline_seconds"]==180 and type(report["elapsed_ns"])is int
        and 0<report["elapsed_ns"]<=180_000_000_000,"unchanged public replay deadline")
    c.need(all(report[key] is False for key in c.FALSE_FLAGS) and report["tool_body_executions"]==0,"public catalog-only scope")
    c.need(report["actual_list_handler_calls"]==162 and report["sdk_unsupported_version_errors"]==54
        and len(report["processes"])==9 and len(report["observed"])==216,"complete public SDK domain")
    c.need(r.document("DOMAIN.json")==domain.domain() and r.document("binary-before.json")==expected_binary,"frozen public corpus")
    pids=[];observed=[];list_calls=0
    native=Path(native);all_rows=domain.rows()
    for index,flags in enumerate(domain.FLAGS):
        prefix=f"profile-{index}";folder=prefix+"/process"
        identity=r.document(prefix+"/process-identity.json");receipt=r.document(folder+"/capture-process.json")
        c.need(report["processes"][index]=={"profile_index":index,"flags":flags,"process":receipt,"identity":identity},"complete process record")
        c.need(identity["profile_index"]==index and identity["flags"]==flags and identity["binary"]==expected_binary,"actual configured process")
        c.need(type(identity["pid"])is int and identity["pid"]>0 and identity["pid"] not in pids,"distinct original process")
        pids.append(identity["pid"])
        c.need(identity["parent_pid"]==report["pid"] and identity["pgid"]==report["pgid"],"actual process ownership")
        c.need(type(receipt["exit_code"])is int and receipt["exit_code"]==0 and receipt["timed_out"] is False
            and receipt["failure_cleanup_requested"] is False and receipt["unconsumed_stdout_bytes"]==0
            and receipt["exchanges"]==26 and type(receipt["timeout_seconds"])is int
            and receipt["timeout_seconds"]==60,"original complete stdio and clean EOF")
        public.number(receipt["elapsed_seconds"],180)
        c.need(receipt["environment"]=={"PATH":"","LC_ALL":"C"},"original controlled stdio environment")
        cwd=receipt["cwd"];command=receipt["command"]
        c.need(type(cwd)is str and Path(cwd).is_absolute(),"recorded fixture cwd")
        if flags:c.need(command==[expected_origin,"--runtime-config",cwd+"/config.json"]
            and Path(cwd).name=="profile-"+str(flags>>1),"exact configured invocation")
        else:c.need(command==[expected_origin] and Path(cwd).name=="workspace","exact unconfigured invocation")
        before=r.document(prefix+"/fixture-before.json");after=r.document(prefix+"/fixture-after.json")
        public.snapshot_check(before,r,prefix+"/fixture",False);public.fixture_before(before,flags,str(Path(cwd).parent))
        public.snapshot_check(after,r,prefix+"/fixture",True)
        before_by={row["path"]:row for row in before};after_by={row["path"]:row for row in after}
        for name,row in before_by.items():
            c.need(name in after_by,"owned configuration path retained")
            if stat.S_ISREG(row["mode"]):c.need(row==after_by[name],"complete configuration input unchanged")
        handler_raw=r.raw(prefix+"/handler-observations.jsonl")
        handler_rows=[c.parse(raw) for raw in handler_raw.splitlines()]
        saved_path=("profile-"+str(flags>>1) if flags else "workspace")+"/catalog-observations.jsonl"
        c.need(r.raw(prefix+"/fixture/"+saved_path)==handler_raw and len(handler_rows)==18,"complete actual handler observer stream")
        original_label="profile-disabled" if not flags else "profile-"+str(flags>>1)
        direct=c.read_json(original/"processes"/(original_label+".stdout"))
        direct_map={(row["protocol_version"],row["cursor_case"]):row["result_wire"] for row in direct["list_cases"]}
        streams={name:gzip.decompress(r.raw(folder+"/"+name+".bin.gz")) for name in ("stdin","stdout","stderr")}
        for name,raw in streams.items():c.need(c.pin(raw)==receipt[name],"complete original "+name)
        c.need(streams["stderr"]==b"","original SDK stderr")
        exchanges=r.document(folder+"/exchanges.json");c.need(len(exchanges)==26,"all SDK exchanges")
        init,initialized=domain.initialization(index)
        init_raw=r.raw(prefix+"/initialize.input.bin");init_reply=r.raw(prefix+"/initialize.output.bin")
        initialized_raw=r.raw(prefix+"/initialized.input.bin")
        c.need(init_raw==init and initialized_raw==initialized,"full initialization input")
        c.need(c.regular(native/prefix/"initialize.input.bin")==init
            and c.regular(native/prefix/"initialized.input.bin")==initialized
            and c.regular(native/prefix/"initialize.output.bin")==init_reply,"complete actual initialization equality")
        inputs=[init,initialized];outputs=[init_reply+b"\n"];reply_index=0
        wanted=[(init,[init_reply]),(initialized,[])]
        for case in (row for row in all_rows if row["profile_index"]==index):
            wire=r.raw(prefix+f'/request-{case["sequence"]:03d}.bin')
            raw=r.raw(prefix+f'/response-{case["sequence"]:03d}.bin')
            c.need(wire==case["wire"] and c.regular(native/prefix/f'request-{case["sequence"]:03d}.bin')==wire
                and c.regular(native/prefix/f'response-{case["sequence"]:03d}.bin')==raw,
                "complete native/current-original request and response")
            if case["connection_accepts"]:
                observation=handler_rows[reply_index];reply_index+=1;list_calls+=1
                request=c.parse(wire);params=request.get("params") or {}
                resolved=case["protocol_version"] or "2024-11-05"
                c.need(observation["sequence"]==reply_index-1 and observation["before"]=={
                    "id":case["sequence"],"meta":params.get("_meta",{}),"protocol_version":resolved,
                    "cursor":params.get("cursor")},"actual current SDK RequestContext and cursor")
                original_wire=direct_map[(resolved,case["cursor_case"])]
                c.need(observation["original_result_wire"]==original_wire,"actual unmodified handler versus direct reference")
                typed=selected(c.parse(original_wire),1)
                c.need(c.parse(observation["installed_result_wire"])==typed,"full installed typed result")
                response=c.parse(raw);peer=dict(typed)
                if not case["modern"]:peer.pop("resultType")
                c.need(response=={"jsonrpc":"2.0","id":case["sequence"],"result":peer},"actual SDK policy applied to typed result")
            else:c.need(raw==domain.unsupported_wire(case),"complete actual unsupported-version error")
            wanted.append((wire,[raw]));inputs.append(wire);outputs.append(raw+b"\n")
            observed.append({key:value for key,value in case.items() if key!="wire"}|{"input":c.pin(wire),"output":c.pin(raw)})
        c.need(reply_index==18,"all and only accepted handler calls")
        for ordinal,(exchange,(wire,replies)) in enumerate(zip(exchanges,wanted,strict=True)):
            c.need(type(exchange["number"])is int and exchange["number"]==ordinal
                and type(exchange["timeout_seconds"])is int and exchange["timeout_seconds"]==60,
                "original request ordinal/deadline")
            public.number(exchange["elapsed_seconds"],60)
            c.need(exchange["requested_bytes"]==exchange["written_bytes"]==len(wire)
                and exchange["request_sha256"]==c.sha(wire) and exchange["responses"]==[c.pin(x) for x in replies]
                and exchange["error"] is None,"complete actual exchange bytes")
        c.need(streams["stdin"]==b"".join(inputs) and streams["stdout"]==b"".join(outputs),"full original process streams")
    c.need(observed==report["observed"] and list_calls==162,"complete original observation sequence")
    r.complete()
    return {"status":"COMPLETE_CURRENT_PUBLIC_CONFIGURED_READONLY_PASS","processes":9,"catalog_requests":216,
        "original_list_handler_calls":162,"sdk_errors":54,"all_exchanges":234,"responses":225,
        "complete_native_original_wire_equal":True,"files":r.files,"process_launches":0,
        "native_execution":False,"rust_execution":False,"tool_body_executions":0,"whole_runtime_replaced":False}
