"""Strict read-only admission of the private current-target annotation evidence."""
from collections import Counter
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "tests/hia_native/scope_annotation/"
SOURCE_FILES = (
    "native/scope_annotation.hepta", "native/scope_annotation.composition.json", "native/scope_annotation_component.json",
    ".github/workflows/hia-scope-annotation.yml", "scripts/archive_hia_scope_annotation.py",
    "native/scope_annotation_abi.md", "native/serde_json.hepta", "native/serde_error.hepta", "native/typed_result_json.hepta",
    "scripts/hia_native_build.py", "scripts/hia_native_loader.py",
    "native/text_result_constructor.hepta", "native/text_result_constructor_abi.md",
    "native/text_result_constructor.composition.json", "scripts/author_text_result_constructor.py",
    "scripts/text_result_constructor.pseudo",
    "scripts/hia_native_scope_annotation_build.py", "scripts/hia_native_scope_annotation_qualification.py",
    "scripts/qualify_hia_scope_annotation.py",
    *(PREFIX+n for n in ("author.py", "source.py.txt", "cases.py", "native_transport.py", "run_native.py", "build_native.py",
        "controls.py", "extract_reference.py", "rust_reference.py", "evidence_controls.py", "original_evidence_controls.py",
        "verify_readonly.py",
        "reference/main.rs", "reference/Cargo.toml", "reference/extraction.json", "reference/sdk-sources.json",
        "reference/target/Cargo.toml", "reference/target/Cargo.lock", "reference/target/src/mcp/runtime/caller_scope.rs",
        "reference/sdk/src/model.rs", "reference/sdk/src/model/content.rs")),
)
EXPECTED = dict(cases=444, native_calls=2484, typed_comparisons=330,
    input_bytes=28506356, input_sha256="f20ccb00d303c554963f3ed2e3b4cae743496b9c6cfddb34e296d0f0b96137f7",
    output_bytes=26245510, output_sha256="c39477b3d329a747fee82b6c5e9d8e0940d6d553379d21b460a19bbbb9295fa0",
    call_capture_bytes=243098725, call_capture_sha256="b0faa193b9d6893faf40e0f33e38197f98f229e4acdfd2fe23e369f5684b34b3")
OWNER_COUNTS = {"scope_annotation": 1299, "serde_json": 444, "serde_error": 80, "typed_result_json": 330, "text_result_constructor": 331}
CONTROL_BASES = {
    "constructor-pending": (268435456, "094d3c0774f024547ea73eed211aca9abe4b1632573804ebb12735f48066f65f", 65600, None),
    "initial": (268435456, "a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484", 65600, 0xCC),
    "pending": (268435456, "d93dbd551d1536cc182cb895b528514eb9b1eade0900d805c3362c10deb0b274", 65600, 0xCC),
    "short-output": (268435456, "a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484", 63, 0xCE),
    "short-workspace": (268435455, "27a96dec923fd3692eb0ea6fda07cecd6a84ccb3339c5bdca607e6773071b664", 128, 0xCE),
}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PACK = lambda *values: struct.pack("<"+"Q"*len(values), *values)
UNPACK = lambda raw: struct.unpack("<"+"Q"*(len(raw)//8), raw)


def require(value, message):
    if not value:
        raise ValueError(message)


def pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "duplicate JSON metadata field")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON metadata")))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+"\n").encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=SHA(raw))


@contextmanager
def opened(path):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "evidence/source path crosses a symbolic link")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "input is not a private ordinary file")
        yield stream
        after = os.fstat(stream.fileno())
        identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        require(identity(before) == identity(after), "input changed during read")


def read(path, maximum=32 << 20):
    with opened(path) as stream:
        raw = stream.read(maximum+1)
    require(len(raw) <= maximum, "bounded input exceeds admitted size")
    return raw


def file_pin(path):
    digest = hashlib.sha256(); count = 0
    with opened(path) as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk); count += len(chunk)
    return dict(bytes=count, sha256=digest.hexdigest())


def source_evidence(root=ROOT):
    root = Path(root).resolve(strict=True)
    files = {name: pin(read(root/name)) for name in SOURCE_FILES}
    sys.path.insert(0, str(root/"scripts"))
    sys.path.insert(0, str(root/PREFIX))
    from hia_native_scope_annotation_build import source_evidence as native_sources
    from extract_reference import extract, CARGO, LOCK_SHA, TARGET_SHA
    checked = native_sources(root)
    for name, expected in checked["files"].items():
        require(files[name] == expected, "native source closure changed")
    target = root/PREFIX/"reference/target"
    original = read(target/"src/mcp/runtime/caller_scope.rs")
    require(SHA(original) == TARGET_SHA and SHA(read(target/"Cargo.lock")) == LOCK_SHA, "target reference changed")
    generated, extraction = extract(original)
    require(read(root/PREFIX/"reference/main.rs") == generated, "source-extracted reference changed")
    require(read(root/PREFIX/"reference/Cargo.toml") == CARGO, "reference Cargo manifest changed")
    proof = parse(read(root/PREFIX/"reference/extraction.json"))
    require(proof["extracted"] == extraction and proof["source_sha256"] == SHA(generated), "extraction receipt differs")
    sdk = parse(read(root/PREFIX/"reference/sdk-sources.json"))
    require(set(sdk) == {"src/model.rs", "src/model/content.rs"}, "SDK dependency source set differs")
    for name, row in sdk.items():
        raw = read(root/PREFIX/"reference/sdk"/name)
        require(pin(raw) == {k: row[k] for k in ("bytes", "sha256")}, "SDK constructor dependency differs")
        blob = hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        require(blob == row["git_blob"] and row["ref"] == "rmcp-v3.9.0", "SDK source attribution differs")
    composition = parse(read(root/"native/scope_annotation.composition.json"))
    require(composition["source_sha256"] == files["native/scope_annotation.hepta"]["sha256"], "composition source differs")
    require(composition["target"]["sha256"] == TARGET_SHA and composition["public_handler_qualified"] is False,
            "annotation target/scope changed")
    require(composition["author_sha256"] == files[PREFIX+"author.py"]["sha256"]
            and composition["dsl_sha256"] == files[PREFIX+"source.py.txt"]["sha256"], "annotation author source differs")
    child = composition["constructor_child"]
    require(child["source_sha256"] == files["native/text_result_constructor.hepta"]["sha256"]
            and (child["is_error"], child["policy"], child["actual_complete_wire_budget_bytes"]) == (0, 0, 65536),
            "annotation does not use the admitted current constructor")
    constructor = parse(read(root/"native/text_result_constructor.composition.json"))
    require(constructor["source_sha256"] == child["source_sha256"]
            and constructor["author_sha256"] == files["scripts/author_text_result_constructor.py"]["sha256"]
            and constructor["dsl_sha256"] == files["scripts/text_result_constructor.pseudo"]["sha256"],
            "shared constructor composition differs")
    require(composition["import_changes"] == constructor["import_changes"] == ["direct function/call relocation only"],
            "source import transformation differs")
    component = parse(read(root/"native/scope_annotation_component.json"))
    require(component["target_commit"] == composition["target"]["commit"]
            and component["target_blob"] == composition["target"]["blob"]
            and component["target_function_sha256"] == extraction["annotate"]["sha256"], "component target identity differs")
    require((component["actual_corpus_cases"], component["wire_boundary_cases"], component["native_calls"],
            component["native_control_cases"], component["native_reader_refusals"], component["original_reader_refusals"])
            == (444,48,2484,39,25,12), "component qualification domains differ")
    require(all(component[name] is False for name in ("caller_authority_resolution_qualified", "public_handler_qualified",
            "production_activated", "whole_runtime_replaced", "old_stack_removal_qualified")), "component scope inflated")
    return dict(schema="hepta.scope-annotation.qualification-sources.v1", files=files, count=len(files),
                sha256=SHA(encoded(files)))


class PacketStream:
    def __init__(self, path, *, compressed=True, maximum=132 << 20):
        self.path = Path(path); self.compressed = compressed; self.maximum = maximum
        self.digest = hashlib.sha256(); self.bytes = 0; self.count = 0

    def __enter__(self):
        self.guard = opened(self.path); self.file = self.guard.__enter__()
        self.stream = gzip.GzipFile(fileobj=self.file, mode="rb") if self.compressed else self.file
        return self

    def take(self):
        head = self.stream.read(8)
        if not head:
            return None
        require(len(head) == 8, "truncated packet header")
        size = UNPACK(head)[0]
        require(0 < size <= self.maximum, "packet extent exceeds domain")
        raw = self.stream.read(size)
        require(len(raw) == size, "truncated packet body")
        self.digest.update(head); self.digest.update(raw); self.bytes += 8+size; self.count += 1
        return raw

    def finish(self):
        require(self.take() is None, "unclaimed packet after the declared domain")
        return dict(bytes=self.bytes, sha256=self.digest.hexdigest(), count=self.count)

    def __exit__(self, *args):
        if self.compressed:
            self.stream.close()
        self.guard.__exit__(*args)


def observation(raw):
    require(raw is not None and len(raw) >= 32 and raw[:8] == b"HSCASR01", "observation frame differs")
    response_size, annotation_size, wire_size = UNPACK(raw[8:32])
    require(len(raw) == 32+response_size+annotation_size+wire_size and response_size >= 64, "observation extents differ")
    response = raw[32:32+response_size]
    annotation = raw[32+response_size:32+response_size+annotation_size]
    wire = raw[-wire_size:] if wire_size else b""
    require(response[:8] == b"HSCANR01", "response tag differs")
    kind, count, wire_count, category, annotation_count, zero1, zero2 = UNPACK(response[8:64])
    require(count == response_size-64 and (wire_count, annotation_count) == (wire_size, annotation_size), "response extents differ")
    require((kind, category) in ((0, 0), (1, 1), (1, 2), (1, 3)) and zero1 == zero2 == 0, "response discriminant differs")
    require((category in (0, 3)) == bool(wire), "budget serialization presence differs")
    if category == 0:
        require(response[64:] == annotation and wire_size <= 65536, "successful text/budget differs")
    elif category == 3:
        require(wire_size > 65536 and response[64:] == b"scoped metadata wire response exceeds 64 KiB; reduce result page limit", "budget refusal differs")
    elif category == 2:
        require(response[64:] == b"metadata response unavailable", "object refusal differs")
    if wire:
        require(wire.startswith(b'{"resultType":"complete","content":[{"type":"text","text":')
                and wire.endswith(b'}],"isError":false}'), "actual constructor wire order differs")
        require(parse(wire) == {"resultType": "complete", "content": [{"type": "text", "text": annotation.decode()}], "isError": False},
                "actual complete constructor value differs")
    return response, annotation, wire, kind, category


def call(raw):
    require(raw is not None and len(raw) >= 64 and raw[:8] == b"HSCALL01", "call frame differs")
    case, step, owner, code, input_size, output_size, workspace_size = UNPACK(raw[8:64])
    require(owner in (1, 2, 3, 4, 5) and code <= 0xffffffff, "call owner/status differs")
    require(len(raw) == 64+input_size+output_size+workspace_size, "call extents differ")
    return dict(case=case, step=step, owner=owner, code=code, input=raw[64:64+input_size],
                output=raw[64+input_size:64+input_size+output_size], workspace=raw[-workspace_size:] if workspace_size else b"")


def process_evidence(process, folder, *, name, timeout, expected_pid=None):
    require(process["name"] == name and process["timeout_seconds"] == timeout, "process name/deadline differs")
    require(process["exit_code"] == 0 and process["timed_out"] is False and process["completed"] is True,
            "process did not complete successfully")
    require(type(process["pid"]) is int and process["pid"] > 0 and process["pgid"] == process["pid"], "owned process identity differs")
    if expected_pid is not None:
        require(process["pid"] == expected_pid, "native execution PID differs from its actual process")
    require(type(process["elapsed_seconds"]) in (int, float) and 0 <= process["elapsed_seconds"] < timeout,
            "process exceeded its declared deadline")
    require(type(process["parent_pid"]) is int and process["parent_pid"] > 0, "process parent identity differs")
    for stream in ("stdout", "stderr"):
        relative = process[stream]["file"]
        require(Path(relative).name == relative, "process stream path escapes custody")
        require(file_pin(folder/relative) == {k: process[stream][k] for k in ("bytes", "sha256")}, "process stream changed")
    return process


def native_process_command(process, script, directory):
    argv=process["argv"]
    original_root=Path(process["cwd"])
    require(len(argv)==8 and Path(argv[0]).is_absolute() and Path(argv[0]).name.startswith("python"),"native Python process command differs")
    require(argv[1:4]==[str(original_root/PREFIX/script),"--runtime",str(original_root)]
            and argv[4]=="--build" and argv[6]=="--output","source-declared native command differs")
    original_output=Path(argv[7])
    require(original_output.is_absolute() and original_output.name==directory
            and argv[5]==str(original_output.parent/"native-build/scope-annotation-build.json"),"native artifact custody path differs")


def native_evidence(build_manifest, directory, *, source_root=ROOT, process=None, process_folder=None):
    root = Path(source_root).resolve(strict=True)
    sys.path[:0] = [str(root/"scripts"), str(root/PREFIX)]
    from hia_native_scope_annotation_build import verify_build
    from cases import cases, input_frame
    from native_transport import QUERY, REPLY, REGION, CONSTRUCTOR_REPLY, CALL, INVALID
    build_manifest = Path(build_manifest).resolve(strict=True)
    verify_build(build_manifest, source_root=root)
    directory = Path(directory).resolve(strict=True)
    report = parse(read(directory/"result.json"))
    require(report["schema"] == "hepta.scope-annotation.actual-native.v1" and report["status"] == "HIA_NATIVE_PASS", "native report incomplete")
    require(report["build_sha256"] == SHA(read(build_manifest)), "native build receipt differs")
    require(report["production_activated"] is False and report["whole_runtime_replaced"] is False
            and report["original_execution_qualified"] is False and report["full_child_workspace_capture"] is False,
            "native scope inflated")
    rows = cases()
    require(len(rows) == len(report["cases"]) == EXPECTED["cases"], "corpus case set differs")
    previous_output = bytes(65600); sequence = 0; counts = Counter(); index_count = 0; typed_count = 0
    exclusions = []
    first_observation = None
    with PacketStream(directory/"inputs.bin.gz") as inputs, PacketStream(directory/"native.bin.gz") as results, PacketStream(directory/"calls.bin.gz") as calls:
        for row, recorded in zip(rows, report["cases"], strict=True):
            framed = input_frame(row)
            require(inputs.take() == framed, "complete original input stream differs")
            observed = results.take()
            response, annotation, wire, kind, category = observation(observed)
            if first_observation is None:
                first_observation = response+wire
            stats = dict(index=row["index"], label=row["label"], input_bytes=len(framed), input_sha256=SHA(framed),
                response_bytes=len(response), response_sha256=SHA(response), annotation_bytes=len(annotation), annotation_sha256=SHA(annotation),
                wire_bytes=len(wire), wire_sha256=SHA(wire), kind=kind, category=category, first_call=index_count)
            for key, value in (("expected_wire_bytes", len(wire)), ("expected_kind", kind), ("expected_category", category)):
                require(key not in row or row[key] == value, "explicit semantic edge differs")
            step = 0

            def take(owner):
                nonlocal step, index_count
                item = call(calls.take())
                require((item["case"], item["step"], item["owner"]) == (row["index"], step, owner), "call order/ownership differs")
                step += 1; index_count += 1
                counts[{1:"scope_annotation", 2:"serde_json", 3:"serde_error", 4:"typed_result_json", 5:"text_result_constructor"}[owner]] += 1
                return item

            children = [1] + ([2] if category == 1 else [3] if wire else [])
            for child in children:
                item = take(1)
                require(item["input"] == framed and item["code"] == CALL, "caller did not issue the declared actual child")
                require(item["output"] == previous_output and len(item["workspace"]) == 352, "caller published a partial result or control capture differs")
                state = item["workspace"]
                require(state[:8] == b"HSCANW01" and UNPACK(state[8:16])[0] == child, "caller phase differs")
                sequence += 1
                if child == 3:
                    wanted = b"HRTCRQ01"+PACK(1,0,0,len(annotation),0,0,0)+annotation
                    reply,capacity = CONSTRUCTOR_REPLY,REGION+64
                    owner = 5
                    require(UNPACK(state[72:80])[0] == len(annotation), "constructor annotation extent differs")
                else:
                    wanted = (b"HSJVAL01" if child == 1 else b"HSJERQ01")+PACK(1,len(framed)-48)+framed[48:]
                    reply,capacity = REPLY,REGION if child == 1 else 1024
                    owner = child+1
                action = state[256:352]
                require(action == b"HSCAA001"+PACK(sequence,child,0,QUERY,len(wanted),reply,capacity,0,0,0,0),
                    "exact native child action differs")
                returned = take(owner)
                require(returned["input"] == wanted and returned["workspace"] == b"", "child input/capture domain differs")
                if child == 1 and category == 1:
                    require(returned["code"] == INVALID and returned["output"] == b"", "parser refusal differs")
                elif child == 3:
                    require(returned["code"] == 64 and returned["output"] == b"HRTCRS01"+PACK(0,0,0,64,len(wire),0,0)+wire,
                        "complete shared constructor descriptor and wire differ")
                else:
                    require(returned["code"] == len(returned["output"]) and returned["code"] < 0xffff0000,
                        "actual child result incomplete")
                    if child == 1:
                        require((returned["output"][:1] == b"{") == bool(wire), "Value root kind differs")
                    else:
                        require(returned["output"][:8] == b"HSJERR01" and returned["output"][64:] == response[64:],
                            "actual diagnostic text differs")
            terminal = take(1)
            require(terminal["input"] == framed and terminal["code"] == len(response), "terminal call differs")
            require(terminal["output"] == response+previous_output[len(response):], "complete owned output buffer differs")
            require(len(terminal["workspace"]) == 352 and UNPACK(terminal["workspace"][8:24]) == (0, sequence), "terminal lifecycle differs")
            previous_output = terminal["output"]
            if wire:
                projection = json.dumps(dict(resultType="complete",content=[dict(type="text",text=annotation.decode())],isError=False),
                    sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                if len(projection) <= 8 << 20:
                    typed = take(4)
                    require(typed["input"] == b"HRTYP001"+PACK(1,len(projection))+projection and typed["output"] == wire
                            and typed["code"] == len(wire) and typed["workspace"] == b"", "independent typed serialization differs")
                    typed_count += 1
                else:
                    exclusions.append(row["index"])
            stats["call_count"] = step
            require(recorded == stats, "native case receipt differs from complete streams")
        input_pin, result_pin, call_pin = inputs.finish(), results.finish(), calls.finish()
    require(counts == OWNER_COUNTS and index_count == EXPECTED["native_calls"] and typed_count == EXPECTED["typed_comparisons"], "actual HIA call set differs")
    require(report["owner_calls"] == OWNER_COUNTS and report["native_calls"] == index_count and report["typed_comparisons"] == typed_count, "reported call set differs")
    require(exclusions == [442] and [r["index"] for r in report["typed_profile_exclusions"]] == exclusions, "typed domain exclusions differ")
    for stream, actual in (("input", input_pin), ("output", result_pin), ("call_capture", call_pin)):
        for suffix in ("bytes", "sha256"):
            name = stream+"_"+suffix
            require(report[name] == EXPECTED[name] == actual[suffix], "complete stream identity differs: "+name)
    if process is not None:
        require(process_folder is not None, "missing process stream custody")
        process_evidence(process, Path(process_folder), name="native-corpus", timeout=180, expected_pid=report["execution"]["pid"])
        native_process_command(process,"run_native.py","native")
        require(process["parent_pid"] == report["execution"]["parent_pid"] and process["cwd"] == report["execution"]["cwd"], "native process attribution differs")
    return dict(schema="hepta.scope-annotation.native-evidence.v1", status="PASS", build_sha256=SHA(read(build_manifest)),
        cases=len(rows), native_calls=index_count, owner_calls=dict(counts), typed_comparisons=typed_count,
        input=input_pin, output=result_pin, calls=call_pin,
        first_response_and_wire_sha256=SHA(first_observation), actual_process_custody=process is not None,
        artifact_sha256={name:file_pin(directory/name)["sha256"] for name in ("result.json","inputs.bin.gz","native.bin.gz","calls.bin.gz")},
        public_handler_qualified=False, whole_runtime_replaced=False)


def workspace_pin(path, patches=()):
    digest = hashlib.sha256(); total = 0
    with opened(path) as file, gzip.GzipFile(fileobj=file, mode="rb") as stream:
        while raw := stream.read(1 << 20):
            if patches:
                part = bytearray(raw)
                for at, value in patches:
                    left=max(at,total); right=min(at+len(value),total+len(raw))
                    if left<right:
                        part[left-total:right-total]=value[left-at:right-at]
                raw = part
            digest.update(raw); total += len(raw)
    return dict(bytes=total, sha256=digest.hexdigest())


def controls_evidence(build_manifest, directory, *, source_root=ROOT, process=None, process_folder=None):
    root = Path(source_root).resolve(strict=True)
    sys.path.insert(0,str(root/PREFIX))
    from controls import NAMES
    from native_transport import request, QUERY, REGION, CONSTRUCTOR_REPLY
    directory=Path(directory).resolve(strict=True)
    report=parse(read(directory/"result.json"))
    require(report["schema"]=="hepta.scope-annotation.actual-controls.v1" and report["status"]=="HIA_CONTROLS_PASS", "control report incomplete")
    require(report["build_sha256"]==SHA(read(build_manifest)), "control build differs")
    require(tuple(r["label"] for r in report["controls"])==NAMES, "native control domain differs")
    require(report["public_handler_qualified"] is False and report["original_execution_qualified"] is False
            and report["whole_runtime_replaced"] is False, "control scope inflated")
    bases={};artifacts={"result.json":file_pin(directory/"result.json")["sha256"]}
    for row in report["bases"]:
        name=row["name"]
        require(name in CONTROL_BASES and name not in bases, "control base set differs")
        expected_size,expected_sha,output_size,fill=CONTROL_BASES[name]
        require((row["workspace_bytes"],row["workspace_sha256"],row["output_bytes"])==(expected_size,expected_sha,output_size),"exact original control base differs")
        require(workspace_pin(directory/(name+".workspace.gz"))==dict(bytes=row["workspace_bytes"],sha256=row["workspace_sha256"]), "complete workspace base changed")
        require(file_pin(directory/(name+".output.bin"))==dict(bytes=row["output_bytes"],sha256=row["output_sha256"]), "control output base changed")
        wanted_output = (read(directory/"output-capacity-recovery.bin")[:262]+bytes(65600-262)
            if fill is None else bytes([fill])*output_size)
        require(read(directory/(name+".output.bin")) == wanted_output,"original output fill differs")
        for suffix in (".workspace.gz",".output.bin"):
            artifacts[name+suffix]=file_pin(directory/(name+suffix))["sha256"]
        bases[name]=row
    require(set(bases)==set(CONTROL_BASES), "missing full control base")
    valid=request(b"{}")
    changed=lambda at,raw:valid[:at]+raw+valid[at+len(raw):]
    invalid_inputs={"input-short":valid[:47],"input-magic":b"?"+valid[1:],
        "input-op":changed(8,PACK(2)),"input-auth":changed(16,PACK(2)),"input-search":changed(24,PACK(2)),
        "input-reserved":changed(40,PACK(1)),"input-length":changed(32,PACK(1)),
        "input-utf8":request(b'"\xff"'),"input-above-eight-mib":request(b" "*((8<<20)+1)),
        "pending-input":request(b"[]")}
    state=int.from_bytes(b"HSCANW01","little")
    required_patches={"state-magic":[(0,PACK(1))],"state-phase":[(0,PACK(state,3))],
        "state-sequence":[(0,PACK(state,0,(1<<64)-1))],"pending-snapshot":[((1<<20)+48,b"[]")],
        "pending-query":[(QUERY+24,b"[]")],"pending-ack":[(320,PACK(2))],"pending-query-size":[(296,PACK(0))],
        "pending-reply-capacity":[(312,PACK(REGION-1))],"pending-reserved":[(280,PACK(1))],
        "pending-code-width":[(320,PACK(1,1<<32))],
        "constructor-query-byte":[(QUERY+64,b"[")], "constructor-query-policy":[(QUERY+24,PACK(1))],
        "constructor-response-policy":[(CONSTRUCTOR_REPLY+24,PACK(1))],
        "constructor-response-extent":[(CONSTRUCTOR_REPLY+40,PACK(REGION+1))],
        "constructor-ack":[(320,PACK(12))]}
    total=0
    for index,row in enumerate(report["controls"]):
        if "files_prefix" in row:
            require(row["files_prefix"]=="control-"+str(index) and row["base"] in bases, "control file/owner differs")
            name=row["files_prefix"]
            for suffix in (".input.bin",".before.bin",".after.bin"):
                artifacts[name+suffix]=file_pin(directory/(name+suffix))["sha256"]
            require(file_pin(directory/(name+".input.bin"))==dict(bytes=row["input_bytes"],sha256=row["input_sha256"]), "control full input differs")
            require(read(directory/(name+".input.bin"))==invalid_inputs.get(row["label"],valid),"native control input domain changed")
            before=read(directory/(name+".before.bin"));after=read(directory/(name+".after.bin"))
            require(before==after and pin(before)==dict(bytes=row["output_bytes"],sha256=row["output_sha256"]), "refusal changed full output")
            patches=[];end=0
            for patch in sorted(row["patches"],key=lambda v:v["at"]):
                at=patch["at"];raw=bytes.fromhex(patch["bytes"])
                require(type(at)is int and end<=at and 0<len(raw)<=32 and at+len(raw)<=row["workspace_bytes"], "invalid control buffer patch")
                patches.append((at,raw));end=at+len(raw)
            require(patches==required_patches.get(row["label"],[]),"native continuation mutation domain changed")
            actual=workspace_pin(directory/(row["base"]+".workspace.gz"),patches)
            require(actual==dict(bytes=row["workspace_bytes"],sha256=row["workspace_before_sha256"])
                    and actual["sha256"]==row["workspace_after_sha256"], "complete refusal workspace differs")
            require(row["output_unchanged"] is True and row["workspace_unchanged"] is True, "refusal atomicity not observed")
            wanted=0xffffffff if row["label"].startswith("input-") else 0xfffffffe if row["label"].startswith("short-") else 0xfffffff8
            require(row["code"]==wanted, "native control return differs")
            total+=2*row["workspace_bytes"]
        elif "constructor_observation" in row:
            declared = {
                "constructor-workspace-growth": (512,16581,1,13,"981e0498ba314df2289c1d6591d03b53193bad85bd92f0452c532219f43eee5f"),
                "constructor-output-growth": (32,16582,2,17,"fb8f4380d38eb4f51481afd613b499f9a927fa23770f5a40c4b906192b5f7157"),
                "constructor-small-output": (31,16582,0,21,"a1c9cc8bdce31ff74ee9a55d54b0bdbc72ff59ec61b514108bd7b1bcc1a67976"),
            }
            require(row["label"] in declared,"undeclared constructor capacity control")
            output_size,work_size,kind,sequence,state_sha = declared[row["label"]]
            child_code = 0xffffffd0 if kind else 0xfffffffe
            require((row["child_output_capacity"],row["child_workspace_capacity"],row["growth_kind"],row["actual_child_code"])
                    == (output_size,work_size,kind,child_code),"actual constructor capacity domain differs")
            require(row["code"] == 0xfffffffe and row["output_unchanged"] is True and row["phase_reset"] is True,
                    "constructor capacity was published as a result")
            retained = row["constructor_observation"]
            require(set(retained) == {"request","child-before","child-after","child-work-before","child-work-after",
                    "owner-before","owner-after","state-before","state-after"},"constructor observation set differs")
            buffers = {}
            for field,metadata in retained.items():
                name = row["label"]+"."+field+".bin"
                require(metadata["file"] == name,"constructor observation custody differs")
                raw = read(directory/name)
                require(pin(raw) == {k:metadata[k] for k in ("bytes","sha256")},"constructor complete buffer changed")
                buffers[field] = raw; artifacts[name] = SHA(raw)
            recovered = read(directory/"output-capacity-recovery.bin")
            annotation = recovered[64:262]
            require(buffers["request"] == b"HRTCRQ01"+PACK(1,0,0,198,0,0,0)+annotation,
                    "constructor control input differs")
            before = bytes([0xA6])*output_size
            required = 16582 if kind == 1 else 355
            after = b"HGRWS002"+PACK(kind,required,0)+before[32:] if kind else before
            require(buffers["child-before"] == before and buffers["child-after"] == after,
                    "actual complete growth descriptor/tail differs")
            require(buffers["child-work-before"] == bytes(work_size),"constructor pre-call workspace differs")
            expected_work = ("032982084e9553e9853e96266e2fc03e034ed7e757178293437d76c8e6040ea1"
                    if kind == 2 else SHA(bytes(work_size)))
            require(len(buffers["child-work-after"]) == work_size and SHA(buffers["child-work-after"]) == expected_work,
                    "constructor complete post-call workspace differs")
            full_output = recovered[:262]+bytes(65600-262)
            require(buffers["owner-before"] == buffers["owner-after"] == full_output,
                    "capacity refusal changed complete caller output")
            old = buffers["state-before"]
            require(len(old) == 352 and SHA(old) == state_sha and UNPACK(old[8:24]) == (3,sequence),
                    "constructor caller state before acknowledgement differs")
            after_state = bytearray(old)
            struct.pack_into("<Q",after_state,8,0)
            struct.pack_into("<QQ",after_state,320,sequence,child_code)
            require(buffers["state-after"] == bytes(after_state),"constructor refusal did not reset exactly the declared lifecycle")
        elif "retained" in row:
            require(row["retained"]==row["label"]+".bin", "recovery capture path differs")
            raw=read(directory/row["retained"]);artifacts[row["retained"]]=SHA(raw)
            require(SHA(raw)==row["sha256"]=="886f9ec0e24d3d35b1d6b6dbf9c81a502d105b60b5a8282a1c36e21148a4324b"
                    and row["code"]==262 and len(raw)==553, "actual recovery capture differs")
            require(raw[:8]==b"HSCANR01" and UNPACK(raw[8:64])==(0,198,291,0,198,0,0), "recovery response metadata differs")
            require(parse(raw[262:])=={"resultType":"complete","content":[{"type":"text","text":raw[64:262].decode()}],"isError":False}, "recovery constructor differs")
        else:
            require(row["label"] in ("child-capacity","output-capacity-after-serialization") and row["code"]==0xfffffffe
                    and row["output_unchanged"] is True and row["phase_reset"] is True, "actual capacity control differs")
            if row["label"]=="child-capacity":require(row["actual_child_code"]==0xfffffffe,"actual child capacity differs")
    require(total==report["full_refusal_workspace_bytes_hashed"]==14495514622,"full control workspace domain changed")
    if process is not None:
        process_evidence(process,Path(process_folder),name="native-controls",timeout=180,expected_pid=report["execution"]["pid"])
        native_process_command(process,"controls.py","controls")
        require(process["parent_pid"]==report["execution"]["parent_pid"] and process["cwd"]==report["execution"]["cwd"],"control process attribution differs")
    return dict(schema="hepta.scope-annotation.control-evidence.v1",status="PASS",controls=len(NAMES),
        full_refusal_workspace_bytes_hashed=total,artifact_sha256=artifacts,actual_process_custody=process is not None,
        public_handler_qualified=False,whole_runtime_replaced=False)


def compare_original(native_directory, original_stdout):
    native_directory=Path(native_directory).resolve(strict=True)
    with PacketStream(native_directory/"native.bin.gz")as native,PacketStream(original_stdout,compressed=False)as original:
        for _ in range(EXPECTED["cases"]):
            left=native.take();right=original.take()
            require(left is not None and right==left,"unchanged original function differs from HIA")
            observation(right)
        first,second=native.finish(),original.finish()
    require(first==second and first["count"]==EXPECTED["cases"] and first["sha256"]==EXPECTED["output_sha256"],"complete original stream identity differs")
    return dict(schema="hepta.scope-annotation.actual-original-comparison.v1",status="PASS",**first,
        unchanged_annotate_calls=EXPECTED["cases"],separate_exact_prefix_observer_calls=EXPECTED["cases"],
        actual_target_constructor=True,production_activated=False,whole_runtime_replaced=False)


def original_evidence(directory,native_directory,*,source_root=ROOT):
    root=Path(source_root).resolve(strict=True)
    directory=Path(directory).resolve(strict=True)
    sys.path.insert(0,str(root/PREFIX))
    from extract_reference import TARGET_COMMIT,TARGET_SHA,LOCK_SHA,extract,CARGO
    reference=root/PREFIX/"reference"
    build=parse(read(directory/"build.json"))
    require(build["schema"]=="hepta.scope-annotation.actual-original-build.v1" and build["target_commit"]==TARGET_COMMIT
        and build["target_sha256"]==TARGET_SHA and build["target_lock_sha256"]==LOCK_SHA,"original target differs")
    require(build["actual_target_sdk_built"] is True and build["actual_target_sdk_executed"] is False
        and build["fresh_target_dir"] is True and build["production_activated"] is False and build["whole_runtime_replaced"] is False,
        "original build scope differs")
    generated,extracted=extract(read(reference/"target/src/mcp/runtime/caller_scope.rs"))
    require(read(directory/"reference-project/main.rs")==generated and read(directory/"reference-project/Cargo.toml")==CARGO,
        "compiled original source differs")
    require(build["source_sha256"]==SHA(generated) and build["cargo_sha256"]==SHA(CARGO)
        and build["extracted"]==extracted and build["profile"]=="exact target [profile.dev]","original extraction/profile differs")
    require(build["binary_file"]=="scope-annotation-original","original binary basename differs")
    require(file_pin(directory/build["binary_file"])==dict(bytes=build["binary_bytes"],sha256=build["binary_sha256"]),
        "executed original binary differs")
    require(build["rust_version"].splitlines()[0].startswith("rustc 1.95.0 ")
        and build["cargo_version"].splitlines()[0].startswith("cargo 1.95.0 "),"original toolchain differs")
    require(build["process_count"]==5,"fresh build process count differs")
    env=parse(read(directory/"reference-environment.json"))
    require(env==build["environment"] and env["cargo_encoded_rustflags_override"]=="","reference environment receipt differs")
    explicit=env["explicit_reference_environment"]
    for name in ("RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC_WRAPPER","CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
                 "CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","CARGO_BUILD_RUSTFLAGS"):
        require(explicit.get(name)=="","compiler wrapper/flags override survived")
    require(explicit["CARGO_BUILD_TARGET"]=="x86_64-unknown-linux-gnu","reference target differs")
    lock=read(directory/"reference-project/Cargo.lock")
    require(SHA(lock)==build["fixture_lock_sha256"],"compiled fixture lock differs")
    target_lock=read(reference/"target/Cargo.lock")
    originals={(p["name"],p["version"],p.get("source")):p.get("checksum")for p in tomllib.loads(target_lock.decode())["package"]if p.get("source")}
    wanted=[]
    for package in tomllib.loads(lock.decode())["package"]:
        if not package.get("source"):
            require(package["name"]=="scope-annotation-original","unbound local dependency")
            continue
        key=package["name"],package["version"],package["source"]
        require(originals.get(key)==package["checksum"],"registry dependency drifted from exact target lock")
        wanted.append({k:package[k]for k in ("name","version","source","checksum")})
    subset=parse(read(directory/"lock-subset.json"))
    require(subset["schema"]=="hepta.scope-annotation.target-lock-subset.v1" and subset["target_lock_sha256"]==LOCK_SHA
        and subset["fixture_lock_sha256"]==SHA(lock) and subset["retained_registry_packages"]==wanted,"registry subset differs")
    require(subset["all_retained_exactly_match_target"] is True and subset["actual_sdk_constructor_dependencies_match"] is True
        and subset["offline_resolution"] is True,"reference dependency custody not established")
    found,registry_artifacts=registry_evidence(directory,reference,subset,originals,wanted)
    return original_process_evidence(directory,native_directory,build,explicit,found,registry_artifacts,extracted)


def registry_evidence(directory,reference,subset,originals,wanted):
    found=set();artifacts={};sdk=False
    for package in subset["registry_source_verification"]:
        key=package["name"],package["version"],package["source"]
        require(key not in found and originals.get(key)==package["checksum"],"unbound/duplicate archived registry package")
        found.add(key)
        crate=package["name"]+"-"+package["version"]
        relative="registry/"+crate+".crate"
        require(package["archive_file"]==relative and Path(crate).name==crate,"crate path differs")
        raw=read(directory/relative,128<<20)
        require(SHA(raw)==package["checksum"]==package["archive_sha256"],"actual retained crate archive changed")
        artifacts[relative]=SHA(raw)
        files={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz")as archive:
            for member in archive.getmembers():
                parts=Path(member.name).parts
                require(parts and parts[0]==crate and not Path(member.name).is_absolute() and ".."not in parts,"crate member path escapes custody")
                if member.isdir():continue
                require(member.isfile(),"non-file crate member")
                name=str(Path(*parts[1:]));content=archive.extractfile(member).read()
                require(name not in files,"duplicate retained crate member")
                files[name]=SHA(content)
                if package["name"]=="rmcp"and name in ("src/model.rs","src/model/content.rs"):
                    require(content==read(reference/"sdk"/name),"actual constructor source differs from admitted dependency")
        require(files==package["source_files"] and len(files)==package["files_verified"],"complete registry source file inventory differs")
        if package["name"]=="rmcp":
            require(package["version"]=="3.9.0"and all(n in files for n in ("src/model.rs","src/model/content.rs")),"SDK source closure incomplete")
            sdk=True
    require(found=={(p["name"],p["version"],p["source"])for p in wanted}and sdk,"registry package set differs")
    return found,artifacts


def original_process_evidence(directory,native_directory,build,explicit,found,registry_artifacts,extracted):
    processes=parse(read(directory/"processes/processes.json"))
    expected=(("reference-target-head",30),("reference-rustc-version",60),("reference-cargo-version",60),
              ("reference-metadata",180),("reference-build",900),("original-replay",180))
    require([p["name"]for p in processes]==[n for n,_ in expected],"original process set differs")
    require(len({p["parent_pid"] for p in processes}) == 1, "fresh original process ownership differs")
    for process,(name,timeout)in zip(processes,expected,strict=True):
        process_evidence(process,directory/"processes",name=name,timeout=timeout)
    require(read(directory/"processes/reference-target-head.stdout").strip().decode()==build["target_commit"],"actual target checkout differs")
    require(read(directory/"processes/reference-rustc-version.stdout").decode()==build["rust_version"]
        and read(directory/"processes/reference-cargo-version.stdout").decode()==build["cargo_version"],"actual version output differs")
    require(processes[1]["argv"]==[explicit["RUSTC"],"--version","--verbose"],"actual rustc command differs")
    cargo=str(Path(explicit["RUSTC"]).parent/"cargo")
    require(processes[2]["argv"]==[cargo,"--version","--verbose"]
        and processes[3]["argv"]==[cargo,"metadata","--offline","--format-version","1"]
        and processes[4]["argv"]==[cargo,"build","--locked","--offline","--target","x86_64-unknown-linux-gnu","--bin","scope-annotation-original"],
        "actual locked original compile recipe differs")
    require(Path(processes[3]["cwd"]).name=="reference-project"and processes[3]["cwd"]==processes[4]["cwd"],"compile cwd differs")
    prior_root=Path(processes[3]["cwd"]).parent
    require(processes[5]["argv"]==[str(prior_root/"scope-annotation-original")],"actual replay binary differs")
    require(explicit["CARGO_TARGET_DIR"]==str(prior_root/"cargo-target"),"fresh Cargo target custody differs")
    metadata=parse(read(directory/"processes/reference-metadata.stdout"))
    actual_packages={(p["name"],p["version"],p["source"])for p in metadata["packages"]if p.get("source")}
    require(actual_packages==found,"actual Cargo metadata package set differs")
    require(metadata["target_directory"]==explicit["CARGO_TARGET_DIR"],"actual Cargo metadata target differs")
    replay=processes[-1]
    require(replay["stdin"]==dict(file="original-replay.stdin",bytes=EXPECTED["input_bytes"],sha256=EXPECTED["input_sha256"]),"complete replay stdin receipt differs")
    require(file_pin(directory/"processes/original-replay.stdin")==dict(bytes=EXPECTED["input_bytes"],sha256=EXPECTED["input_sha256"]),"complete actual replay stdin changed")
    require(replay["stderr"]["bytes"]==0,"original replay stderr is nonempty")
    comparison=compare_original(native_directory,directory/"processes/original-replay.stdout")
    return dict(schema="hepta.scope-annotation.original-evidence.v1",status="PASS",comparison=comparison,
        target_commit=build["target_commit"],target_file_sha256=build["target_sha256"],target_lock_sha256=build["target_lock_sha256"],
        binary_sha256=build["binary_sha256"],actual_processes=len(processes),retained_registry_packages=len(found),
        registry_artifact_sha256=registry_artifacts,source_extracted_annotate_sha256=extracted["annotate"]["sha256"],
        actual_target_constructor=True,exact_target_dev_profile=True,production_activated=False,whole_runtime_replaced=False)


def reader_controls_evidence(output, *, source_root=ROOT, original=False):
    root = Path(source_root).resolve(strict=True)
    output = Path(output).resolve(strict=True)
    sys.path.insert(0,str(root/PREFIX))
    if original:
        from original_evidence_controls import NAMES
        name, folder, process_folder = "original-evidence-controls", "original-reader-controls", "original-reader-processes"
        schema, status = "hepta.scope-annotation.original-reader-controls.v1", "ORIGINAL_READER_CONTROLS_PASS"
    else:
        from evidence_controls import NAMES
        name, folder, process_folder = "native-evidence-controls", "reader-controls", "reader-processes"
        schema, status = "hepta.scope-annotation.reader-controls.v1", "READER_CONTROLS_PASS"
    report = parse(read(output/folder/"result.json"))
    require(report["schema"] == schema and report["status"] == status, "evidence reader control report incomplete")
    require(report["native_processes_executed"] == report["original_processes_executed"] == 0,
            "read-only evidence controls executed an implementation")
    require(tuple(row["name"] for row in report["controls"]) == NAMES
            and all(row["status"] == "REFUSED" for row in report["controls"]), "strict refusal domain differs")
    require([row["name"] for row in report["relocations"]] == ["one","two"], "physical copy domain differs")
    for row in report["relocations"]:
        require(row["status"] == "PASS" and row["same_complete_source_and_artifact_identity"] is True
                and row["processes_executed"] == 0 and row["files"] == len(report["admitted_files"]),
                "independent physical reader incomplete")
    for name_, identity in report["admitted_files"].items():
        require(not Path(name_).is_absolute() and ".." not in Path(name_).parts, "reader input path escapes capture")
        require(file_pin(output/name_) == identity, "reader admitted file identity differs")
    processes = parse(read(output/process_folder/"processes.json"))
    require(len(processes) == 1, "read-only control process count differs")
    process = process_evidence(processes[0], output/process_folder, name=name, timeout=180,
        expected_pid=report["execution"]["pid"])
    require(process["parent_pid"] == report["execution"]["parent_pid"]
            and process["cwd"] == report["execution"]["cwd"], "reader process ownership differs")
    source = Path(process["cwd"])
    argv = process["argv"]
    script = "original_evidence_controls.py" if original else "evidence_controls.py"
    require(len(argv) == 8 and Path(argv[0]).is_absolute()
            and argv[1:4] == [str(source/PREFIX/script),"--runtime",str(source)]
            and argv[4] == "--capture" and argv[6] == "--output"
            and argv[7] == str(Path(argv[5])/folder), "reader source/capture command differs")
    actual = parse(read(output/process_folder/process["stdout"]["file"]))
    require(actual["status"] == status and actual["controls"] == len(NAMES) and actual["relocations"] == 2
            and actual["native_processes_executed"] == 0, "actual reader summary differs")
    if original:
        require(actual["original_processes_executed"] == 0, "original evidence reader executed Rust")
    return report
