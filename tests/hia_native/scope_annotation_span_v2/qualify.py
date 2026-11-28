"""Read complete source, compiler, native, control and original evidence only."""
from pathlib import Path
import hashlib
import gzip
import struct
from build import MODULES, verify_source
from cases import cases, domain, frame
from controls import plan, INITIAL, STATE, PENDING, CONSTRUCTOR, SECOND
from read_capture import (SHA, PACK, WORD, CALL, GROW, PacketStream, file_pin, jsonlines,
                         lifecycle, observation, parse, physical, pin, read, require, retained_observation)
from original_reader import original_evidence, process_evidence
from parallel_reader import read_workers

ROOT = Path(__file__).resolve().parent
COMPILER = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
COMPILER_COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"


def build_evidence(folder, source_sha):
    folder = Path(folder)
    report = parse(read(folder/"BUILD.json"))
    require(report["source_manifest_sha256"] == source_sha and report["semantic_execution"] is False
            and report["whole_runtime_qualified"] is False, "build source/scope differs")
    require(set(report["members"]) == set(MODULES), "four-owner build domain differs")
    bootstrap = parse(read(folder/"bootstrap/bootstrap.json"))
    require(bootstrap["schema"] == "hepta.runtime.native-bootstrap.v1" and bootstrap["generation_sha256"] == COMPILER
            and bootstrap["dependency"]["commit"] == COMPILER_COMMIT
            and bootstrap["qualification"] == "development_fixed_point"
            and bootstrap["matching_source_cold_qualified"] is False, "compiler custody or scope differs")
    for name in ("B1","B2","B3"):
        require(file_pin(folder/"bootstrap"/(name+".image.bin")) == dict(bytes=673413,sha256=COMPILER), "retained compiler generation differs")
    compiler_files=bootstrap["dependency"]["files"]
    require({p.relative_to(folder/"compiler-source").as_posix() for p in (folder/"compiler-source").rglob("*") if p.is_file()}==set(compiler_files),"compiler source closure differs")
    for name,expected in compiler_files.items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts and SHA(read(folder/"compiler-source"/name))==expected,"actual retained compiler source changed")
    require(SHA(read(folder/"compiler-source/examples/hia_bootstrap/selfhost.hepta"))==bootstrap["compiler_source_sha256"],"bootstrap compiler source differs")
    images = {}
    for name in MODULES:
        row = report["members"][name]
        require(row["manifest"] == "modules/"+name+"/manifest.json", "module manifest path differs")
        path = folder/row["manifest"]
        raw = read(path)
        require(SHA(raw) == row["manifest_sha256"], "compiled module manifest changed")
        manifest = parse(raw)
        source = read(ROOT/"native"/(name+".hepta"))
        require(manifest["name"] == name and manifest["source"] == name+".hepta" and manifest["source_sha256"] == SHA(source), "module source binding differs")
        require(read(path.parent/manifest["source"]) == source == read(path.parent/"module.input.bin"), "actual compiler input differs from frozen HIA")
        require(manifest["compiler_sha256"] == COMPILER and manifest["compiler_commit"] == COMPILER_COMMIT
                and manifest["qualification"] == "development_fixed_point" and manifest["standalone"] is None
                and manifest["buffer_profile"] == "batch-plan.v1"
                and manifest["abi"] == "hepta.runtime.borrowed-bytes.linux-x86_64.v1", "compiler or entry ABI differs")
        require((manifest["input_capacity"],manifest["output_capacity"],manifest["workspace_capacity"]) == (536870912,1073741824,1207959552), "span admission profile differs")
        image = read(path.parent/manifest["image"])
        require(manifest["image"] == "module.image.bin" and SHA(image) == manifest["image_sha256"], "actual HIA module changed")
        receipt = parse(read(path.parent/"module.receipt.json"))
        build = parse(read(path.parent/"build.json"))
        require(build["compile_receipt"] == receipt and build["compiler_dependency"] == bootstrap["dependency"], "actual compilation custody differs")
        require(receipt["status"] == "returned" and receipt["abi_status"] == 0 and receipt["source_unchanged"] is True
                and receipt["forbidden_compiler_modules_loaded"] == [] and receipt["format"] == "flat-x86-64", "compiler did not return with strict custody")
        require(receipt["artifact_sha256"] == receipt["image_sha256"] == COMPILER
                and receipt["input_bytes"] == len(source) and receipt["input_sha256"] == receipt["source_sha256"] == SHA(source)
                and receipt["core_u32"] == receipt["result_u64"] == receipt["produced_bytes"] == len(image)
                and receipt["produced_sha256"] == SHA(image), "compiler input/output receipt differs")
        stdout=parse(read(path.parent/"module.stdout.log"))
        keys={"abi_status","core_u32","forbidden_compiler_modules_loaded","image_sha256","limits","loader_operations",
              "native_elapsed_ns","output_sha256","output_unchanged","result_u64","return_encoding","source_sha256",
              "source_unchanged","status","workspace_header"}
        require(set(stdout)==keys and stdout=={k:receipt[k] for k in keys},"actual compiler stdout differs from receipt")
        full = read(path.parent/"module.output.bin")
        require(SHA(full) == receipt["output_sha256"] and len(full) == receipt["limits"]["output_capacity"]
                and full[:len(image)] == image and read(path.parent/"module.stderr.log") == b"", "complete actual compiler output differs")
        require(full[len(image):]==b"\xa5"*(len(full)-len(image)),"compiler modified unused complete output tail")
        images[name] = pin(image)
    return dict(status="PASS",images=images,compiler_sha256=COMPILER,
                fresh_bootstrap=report["compiler_bootstrap"] == "fresh pinned B1=B2=B3 on CI",
                matching_source_cold_qualified=False)


def native_evidence(folder, build, source_sha):
    folder = Path(folder)
    report = parse(read(folder/"CAPTURE.json"))
    frozen = parse(read(ROOT/"DOMAIN.json"))
    require(domain() == frozen, "frozen semantic domain differs from original generator")
    require(report["status"] == "COMPLETE_NATIVE_CAPTURE" and report["source_unchanged"] is True
            and report["original_execution"] is False and report["whole_runtime_replaced"] is False
            and report["source_manifest_sha256"] == source_sha and report["build_sha256"] == SHA(read(build/"BUILD.json"))
            and report["domain_sha256"] == SHA(read(ROOT/"DOMAIN.json")), "native source/domain/build differs")
    require(report["cases"] == len(frozen["cases"]) and report["sessions"] == 4*report["cases"], "complete semantic case domain changed")
    # Check complete stream identities before the expensive physical proof.
    # Accepted evidence still reaches every original per-case and buffer check.
    for name,expected_bytes,expected_sha in (
            ("inputs.bin.gz",frozen["input_bytes"],frozen["input_sha256"]),
            ("observed.bin.gz",report["observed_bytes"],report["observed_sha256"])):
        file_pin(folder/name)
        digest,count = hashlib.sha256(),0
        with gzip.open(folder/name,"rb") as stream:
            while block := stream.read(1<<20):
                digest.update(block);count += len(block)
        require(count == expected_bytes and digest.hexdigest() == expected_sha,
                "complete native stream identity differs: "+name)
    buffers,calls,sessions,growth,handoffs = physical(folder,report)
    lifecycle(folder,buffers,calls,sessions,growth,handoffs)
    require(buffers.physical_bytes == report["physical_buffer_bytes"] and len(buffers.rows) == report["unique_buffer_chunks"], "complete physical capture size differs")
    indices = jsonlines(folder/"cases.jsonl")
    require(len(indices) == report["cases"], "case ledger domain differs")
    case_sessions = {}
    for session in sessions.values():
        case_sessions.setdefault(session["case"],[]).append(session)
    require(set(case_sessions) == {row["label"] for row in indices}, "session case domain differs")
    actual_rows, recovery_bytes, next_call = {}, {}, 1
    with PacketStream(folder/"inputs.bin.gz") as inputs, PacketStream(folder/"observed.bin.gz") as outputs:
        for expected,row in zip(cases(),indices,strict=True):
            require((row["index"],row["label"],row["group"]) == (expected["index"],expected["label"],expected["group"]), "case ordering differs")
            request = inputs.take()
            raw = outputs.take()
            require(request == frame(expected) and pin(request) == dict(bytes=row["input_bytes"],sha256=row["input_sha256"]), "complete semantic request differs")
            require(raw is not None and pin(raw) == dict(bytes=row["observed_bytes"],sha256=row["observed_sha256"]), "complete semantic observation differs")
            require(row["first_call"] == next_call and row["last_call"] >= next_call, "actual case calls overlap or skip")
            selected = calls[row["first_call"]-1:row["last_call"]]
            require(selected and all(c["case"] == row["label"] for c in selected), "actual calls cross case boundary")
            owned = case_sessions[row["label"]]
            require(len(owned) == 4 and {s["owner"] for s in owned} ==
                    {"scope_annotation_span","serde_json_span","serde_error_span","text_result_constructor"},
                    "case does not own exactly the four declared HIA sessions")
            by_owner = {s["owner"]:s for s in owned}
            require(all(c["session"] in {s["session"] for s in owned} for c in selected),
                    "actual case borrowed another case's session")
            require(all(s["workspace_capacity"] == 0 for s in owned)
                    and by_owner["scope_annotation_span"]["output_capacity"] == max(65600,64+len(request))
                    and by_owner["scope_annotation_span"]["admission"] ==
                        dict(policy="complete-request-span-plus-header", input_bytes=len(request),
                             input_sha256=SHA(request), capacity=max(65600,64+len(request)))
                    and all(by_owner[name]["output_capacity"] == 64 and by_owner[name]["admission"] is None
                            for name in ("serde_error_span","text_result_constructor")),
                    "initial semantic session capacities differ")
            admission = by_owner["serde_json_span"]["admission"]
            require(type(admission) is dict and row["first_call"] <= admission["issued_call"] <= row["last_call"]
                    and calls[admission["issued_call"]-1]["session"] == by_owner["scope_annotation_span"]["session"],
                    "Value initial output is not bound to this actual owner")
            require(selected[0]["owner"] == selected[-1]["owner"] == "scope_annotation_span", "case starts or ends outside actual owner")
            require(all(read(folder/c["folder"]/"input.bin") == request for c in selected if c["owner"] == "scope_annotation_span"), "continued owner input changed")
            require(retained_observation(buffers,selected[-1]) == raw, "observation not copied from actual complete HIA buffers")
            result = observation(raw)
            for key,value in dict(expected_kind=result["kind"],expected_category=result["category"],
                    expected_wire_bytes=len(result["wire"]),expected_fallback=result["fallback"],expected_warning=result["warnings"]).items():
                require(key not in expected or expected[key] == value, "source-contract expected metadata differs: "+row["label"]+" "+key)
            require((row["response_bytes"],row["annotation_bytes"],row["wire_bytes"],row["warning_bytes"]) == tuple(len(result[k]) for k in ("response","annotation","wire","warning")), "indexed complete spans differ")
            actual_rows[row["label"]] = pin(raw)
            if row["label"] in ("baseline-empty-00","effect-search-missing-0"):
                recovery_bytes[row["label"]] = raw
            next_call = row["last_call"]+1
        input_pin,output_pin = inputs.finish(),outputs.finish()
    require(next_call == len(calls)+1 and input_pin["count"] == output_pin["count"] == report["cases"], "unadmitted native call or observation")
    require({k:input_pin[k] for k in ("bytes","sha256")} == dict(bytes=frozen["input_bytes"],sha256=frozen["input_sha256"])
            == dict(bytes=report["input_bytes"],sha256=report["input_sha256"]), "full semantic input stream differs")
    require({k:output_pin[k] for k in ("bytes","sha256")} == dict(bytes=report["observed_bytes"],sha256=report["observed_sha256"]), "full native result stream differs")
    return dict(status="PASS",cases=report["cases"],groups=frozen["groups"],native_calls=len(calls),
                physical_buffer_bytes=buffers.physical_bytes,unique_buffer_chunks=len(buffers.rows),
                input=input_pin,output=output_pin),recovery_bytes


def controls_evidence(folder, build, source_sha, semantic):
    folder = Path(folder)
    report = parse(read(folder/"CAPTURE.json"))
    frozen = parse(read(ROOT/"CONTROL_DOMAIN.json"))
    require(frozen == plan(), "frozen private boundary domain changed")
    require(report["status"] == "COMPLETE_NATIVE_CONTROLS" and report["source_unchanged"] is True
            and report["original_execution"] is False and report["whole_runtime_replaced"] is False
            and report["source_manifest_sha256"] == source_sha and report["build_sha256"] == SHA(read(build/"BUILD.json"))
            and report["control_domain_sha256"] == SHA(read(ROOT/"CONTROL_DOMAIN.json")), "control source/build differs")
    require([r["name"] for r in report["refusals"]] == frozen["refusals"] and [r["name"] for r in report["recoveries"]] == frozen["recoveries"], "private refusal/recovery domain changed")
    require([r["name"] for r in report["child_refusals"]] == frozen["child_refusals"],"constructor capacity refusal domain changed")
    buffers,calls,sessions,growth,handoffs = physical(folder,report)
    lifecycle(folder,buffers,calls,sessions,growth,handoffs,baselines=report["baselines"],refusals=report["refusals"])
    expectations = control_expectations(buffers,report["baselines"])
    require(buffers.physical_bytes == report["physical_buffer_bytes"] and len(buffers.rows) == report["unique_buffer_chunks"], "control complete physical capture size differs")
    for row in report["refusals"]:
        call = calls[row["call"]-1]
        wanted = expectations[row["name"]]
        require(row["baseline"] == wanted["baseline"] and row["expected_code"] == wanted["code"]
                and row["patches"] == wanted["patches"] and read(folder/call["folder"]/"input.bin") == wanted["input"],
                "named refusal no longer exercises its exact frozen boundary")
        require(call["case"] == row["name"] and call["input"]["sha256"] == row["input_sha256"]
                and call["return_code"] == row["expected_code"] and call["return_code"] in (0xffffffff,0xfffffff8,0xfffffffe)
                and call["workspace_before"] == call["workspace_after"] and call["output_before"] == call["output_after"], "actual refusal modified caller bytes or differs")
    for row in report["recoveries"]:
        require(Path(row["file"]).name == row["file"], "recovery path escapes custody")
        raw = read(folder/row["file"])
        call = calls[row["last_call"]-1]
        require(pin(raw) == dict(bytes=row["bytes"],sha256=row["sha256"]) and raw == semantic[row["semantic_label"]]
                and raw == retained_observation(buffers,call), "actual recovery differs from full semantic original-comparison case")
    baselines={r["name"]:r for r in report["baselines"]}
    for row,capacity in zip(report["child_refusals"],(0,31,63),strict=True):
        call=calls[row["call"]-1]
        state=baselines[row["owner_baseline"]]["buffer"]
        head=buffers.span(state,0,352)
        request=buffers.span(state,WORD(head,136),WORD(head,296))
        require(call["owner"]=="text_result_constructor" and call["case"]==row["name"]
                and row["output_capacity"]==call["output_capacity"]==capacity and call["workspace_capacity"]==0
                and row["expected_code"]==call["return_code"]==frozen["child_expected_codes"][row["name"]]
                == (0xfffffffe if capacity < 32 else GROW)
                and read(folder/call["folder"]/"input.bin")==request and SHA(request)==row["request_sha256"]
                and call["workspace_before"]==call["workspace_after"],
                "actual constructor short-output boundary differs")
        if capacity < 32:
            require(call["output_before"]==call["output_after"],"capacity refusal changed complete output")
        else:
            before=buffers.span(call["output_before"])
            after=buffers.span(call["output_after"])
            require(after==b"HGRWS002"+PACK(1,16384+len(request)-64,0)+before[32:],
                    "constructor growth frame or untouched output tail differs")
    for kind in (1,2):
        require(any(calls[r["after_call"]-1]["owner"]=="text_result_constructor" and r["kind"]==kind for r in growth),
                "original constructor workspace/output growth domain omitted")
    return dict(status="PASS",refusals=len(report["refusals"]),recoveries=len(report["recoveries"]),
                child_refusals=len(report["child_refusals"]),native_calls=len(calls),physical_buffer_bytes=buffers.physical_bytes)


def control_expectations(buffers, baselines):
    """Bind each named negative case to its independently specified bytes."""
    values={r["name"]:buffers.span(r["buffer"]) for r in baselines}
    originals={r["label"]:r for r in cases()}
    empty=frame(originals["baseline-empty-00"])
    change=lambda raw,at,value:raw[:at]+value+raw[at+len(value):]
    result={}
    def add(name,base,patches=(),request=empty,code=0xfffffff8):
        require(name not in result,"duplicate control expectation")
        result[name]=dict(baseline=base,patches=[dict(at=at,hex=raw.hex()) for at,raw in patches],input=request,code=code)
    invalid=[empty[:47],change(empty,0,b"BADFRAME"),change(empty,8,PACK(3)),change(empty,16,PACK(2)),
             change(empty,24,PACK(2)),change(empty,40,PACK(1)),change(empty,32,PACK(3)),change(empty,48,b"\xff"),
             change(change(empty,8,PACK(2)),24,PACK(0))]
    for name,request in zip(INITIAL,invalid,strict=True):add(name,"fresh",request=request,code=0xffffffff)
    for name,patches in zip(STATE,(((0,b"BADSTATE"),),((0,b"HSCAWS02"),(8,PACK(5))),((0,b"HSCAWS02"),(16,PACK(0xffffffffffffffff)))),strict=True):
        add(name,"fresh",patches)
    pending=values["value-completed"];query,reply=WORD(pending,136),WORD(pending,144)
    requests=[change(empty,48,b"[]"),change(empty,16,PACK(1)),change(empty,24,PACK(1)),change(change(empty,8,PACK(2)),24,PACK(1))]
    mutations=[(24,PACK(0)),(32,PACK(0)),(40,PACK(0)),(128,PACK(0)),(136,PACK(0)),(144,PACK(0)),
               (256,b"BADACTIO"),(264,PACK(0)),(272,PACK(3)),(280,PACK(1)),(288,PACK(0)),(296,PACK(0)),
               (304,PACK(0)),(312,PACK(0)),(320,PACK(0)),(320,PACK(2)),(328,PACK(1<<32)),(344,PACK(1)),
               (query,b"BADQUERY"),(query+24,b"[]"),(reply,b"BADREPLY"),(reply+8,PACK(2)),(reply+16,PACK(0)),(reply+24,PACK(1)),(16384+48,b"[")]
    for name,request in zip(PENDING[:4],requests,strict=True):add(name,"value-completed",request=request)
    for name,patch in zip(PENDING[4:],mutations,strict=True):add(name,"value-completed",(patch,))
    constructed=values["constructor-completed"];query,reply,capacity=WORD(constructed,136),WORD(constructed,160),WORD(constructed,176)
    mutations=[(query+16,PACK(1)),(query+24,PACK(1)),(query+40,PACK(1)),(reply,b"BADREPLY"),(reply+8,PACK(1)),
               (reply+24,PACK(1)),(reply+32,PACK(63)),(reply+40,PACK(capacity)),(reply+56,PACK(1)),(320,PACK(0)),(query+64,b"["),(328,PACK(0xfffffffe)),(328,PACK(GROW))]
    for name,patch in zip(CONSTRUCTOR,mutations,strict=True):add(name,"constructor-completed",(patch,))
    for capacity in (0,31,63):
        name="short-output-"+str(capacity);add(name,name,code=0xfffffffe)
    second=values["second-value-completed"];reply=WORD(second,144)
    request=frame(originals["effect-search-missing-0"])
    for name,patches in zip(SECOND,(((reply+32,b"["),),((reply+8,PACK(1)),(reply+16,PACK(0))),((320,PACK(0)),)),strict=True):
        add(name,"second-value-completed",patches,request=request)
    require(list(result)==plan()["refusals"],"exact refusal expectation domain changed")
    return result


def process_custody(output, source_sha):
    gate=parse(read(output/"GATE.json"))
    require(gate["source_manifest_sha256"]==source_sha and gate["whole_runtime_replaced"] is False,"gate source or scope differs")
    records=parse(read(output/"gate-processes/processes.json"))
    require([r["name"] for r in records[:3]]==["native-build","native-domain","native-controls"],"actual native process domain differs")
    source=Path(gate["execution_source_root"]);destination=Path(gate["execution_output_root"])
    for row in records[:3]:
        process_evidence(row,output/"gate-processes",name=row["name"],timeout=180)
        require(row["cwd"]==str(source) and row["stdin"] is None and row["stderr"]["bytes"]==0,"native process environment/custody differs")
    for row,script,folder in zip(records[1:3],("run_native.py","controls.py"),("native","controls"),strict=True):
        require(Path(row["argv"][0]).is_absolute() and row["argv"][1:]==["-I","-B",str(source/script),"--build",str(destination/"build/BUILD.json"),"--output",str(destination/folder)],"actual native command differs")
        capture=parse(read(output/folder/"CAPTURE.json"))
        require(capture["execution_pid"]==row["pid"],"native capture belongs to another process")
    return dict(status="PASS",native_processes=3,native_domain_timeout_seconds=180,native_controls_timeout_seconds=180)


def reader_controls_evidence(output, *, original=False, baseline=None, semantic=None):
    if original:
        from original_evidence_controls import NAMES
        folder,name="original-reader-controls","original-evidence-controls"
        status="ORIGINAL_READER_CONTROLS_PASS"
    else:
        from evidence_controls import NAMES
        folder,name="reader-controls","native-evidence-controls"
        status="READER_CONTROLS_PASS"
    report=parse(read(output/folder/"result.json"))
    require(report["status"]==status and report["native_processes_executed"]==report["original_processes_executed"]==0,
            "reader controls did not finish without implementation execution")
    require(tuple(r["name"] for r in report["controls"])==NAMES and all(r["status"]=="REFUSED" for r in report["controls"]),"reader negative domain changed")
    require([r["name"] for r in report["relocations"]]==["one","two"],"physical reader relocation domain changed")
    for row in report["relocations"]:
        require(row["status"]=="PASS" and row["same_complete_source_and_artifact_identity"] is True
                and row["processes_executed"]==0 and row["files"]==len(report["admitted_files"]),"relocated reader evidence incomplete")
        if not original:
            require(Path(row["proof_file"]).name==row["proof_file"],"relocation proof path differs")
            raw=gzip.decompress(read(output/folder/row["proof_file"]))
            require(pin(raw)==row["proof"],"complete relocation guard proof changed")
            proof=parse(raw)
            require(len(proof["probes"])==row["guard_refusals"]==12 and proof["before"]==proof["after"]
                    and len(proof["before"])==row["unchanged_entries"]
                    and proof["native_or_rust_executions"]==proof["reader_writes"]==0,"relocation guard differs")
    snapshots=[] if original else report["mutable_input_snapshots"]
    require(original or snapshots==["GATE.json","gate-processes/processes.json"],"mutable custody snapshot domain differs")
    for name_,identity in report["admitted_files"].items():
        require(not Path(name_).is_absolute() and ".." not in Path(name_).parts,"admitted reader path escapes custody")
        retained=output/folder/"inputs"/name_ if name_ in snapshots else output/name_
        require(file_pin(retained)==identity,"actual admitted reader input changed")
    if not original:
        initial=parse(read(output/folder/"inputs/GATE.json"));current=parse(read(output/"GATE.json"))
        for key in ("schema","source_manifest_sha256","domain_sha256","native_only","execution_source_root","execution_output_root","whole_runtime_replaced"):
            require(initial[key]==current[key],"gate custody changed after reader controls")
        earlier=parse(read(output/folder/"inputs/gate-processes/processes.json"))
        current=parse(read(output/"gate-processes/processes.json"))
        require(earlier==current[:len(earlier)],"recorded pre-control process prefix changed")
        require(report["source_manifest_sha256"]==SHA(read(ROOT/"SOURCE_MANIFEST.json")),"reader control source differs")
    records=parse(read(output/"gate-processes/processes.json"))
    selected=[r for r in records if r["name"]==name]
    require(len(selected)==1,"reader control process domain differs")
    row=process_evidence(selected[0],output/"gate-processes",name=name,timeout=180,expected_pid=report["execution"]["pid"])
    require(row["parent_pid"]==report["execution"]["parent_pid"] and row["cwd"]==report["execution"]["cwd"],"reader control process attribution differs")
    old_source=Path(row["cwd"])
    destination=Path(parse(read(output/"GATE.json"))["execution_output_root"])
    tail=(["--runtime",str(old_source)] if original else [])+["--capture",str(destination),"--output",str(destination/folder)]
    script="original_evidence_controls.py" if original else "evidence_controls.py"
    require(Path(row["argv"][0]).is_absolute() and row["argv"][1:]==["-I","-B",str(old_source/script)]+tail,"actual reader control command differs")
    require(row["stderr"]["bytes"]==0,"reader control stderr is nonempty")
    actual=parse(read(output/"gate-processes"/row["stdout"]["file"]))
    require(actual["status"]==status and actual["controls"]==len(NAMES) and actual["relocations"]==2
            and actual["native_processes_executed"]==0,"actual reader control summary differs")
    if not original:
        require(baseline is not None and semantic is not None,"parallel reader requires the full current baseline")
        require(report["python_reader_workers"]==actual["python_reader_workers"]==2
                and report["execution"]["pgid"]==row["pgid"]
                and 0<=report["elapsed_seconds"]<=row["elapsed_seconds"]<180
                and report["execution"]["finished_monotonic_ns"]-report["execution"]["started_monotonic_ns"]
                ==round(report["elapsed_seconds"]*1e9),
                "parallel readers escaped their actual enclosing parent")
        require(file_pin(output/folder/"inputs/BASELINE.json")==report["baseline"]
                and file_pin(output/folder/"worker-processes.json")==report["worker_processes"],
                "parallel reader complete baseline or process receipt changed")
        workers=read_workers(output/folder,report["source_manifest_sha256"],baseline,NAMES,
                             expected_parent=report["execution"],semantic=semantic,
                             expected_files=report["admitted_files"],
                             expected_roots=dict(source_root=str(old_source),capture_root=str(destination),
                                                 output_root=str(destination/folder)))
        joined={control["name"]:control for worker in workers for control in worker["controls"]}
        require(report["controls"]==[joined[name] for name in NAMES]
                and report["relocations"]==[worker["relocations"][0] for worker in workers]
                and report["post_refusal"]==[worker["post_refusal"][0] for worker in workers],
                "parent reader report differs from complete actual worker reports")
    return dict(status="PASS",refusals=len(NAMES),relocations=2,admitted_files=len(report["admitted_files"]),
                native_or_rust_executions=0)


def verify(output, *, full, require_controls=False):
    output = Path(output)
    source_sha = verify_source()
    custody = process_custody(output,source_sha)
    build = build_evidence(output/"build",source_sha)
    native,semantic = native_evidence(output/"native",output/"build",source_sha)
    controls = controls_evidence(output/"controls",output/"build",source_sha,semantic)
    result = dict(status="COMPLETE_NATIVE_SPAN_CAPTURE_PASS",source_manifest_sha256=source_sha,
                  build=build,native=native,controls=controls,process_custody=custody,original_qualified=False,
                  public_handler_qualified=False,whole_runtime_replaced=False)
    if full:
        result["original"] = original_evidence(output/"original",output/"native",source_root=ROOT)
        result.update(status="COMPLETE_ORIGINAL_COMPARISON_SPAN_ANNOTATION_PASS",original_qualified=True)
    if require_controls:
        result["native_reader_controls"]=reader_controls_evidence(
            output,baseline=dict(native=native,controls=controls,build=build),semantic=semantic)
        if full:
            result["original_reader_controls"]=reader_controls_evidence(output,original=True)
    return result
