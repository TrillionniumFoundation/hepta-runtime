"""Read full native/reference records. This module launches no processes."""
from __future__ import annotations
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import sys
sys.dont_write_bytecode = True
TRUSTED_PROFILE_BYTES = Path(__file__).resolve().with_name("source-profile.json").read_bytes()

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
COMPILER_TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
GENERATION = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
VERSIONS = [None, "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-27", "2026-07-28", "2026-08-01"]
PROFILES = ["disabled", *(str(i) for i in range(8))]
SOURCE_PINS = {"catalog-policy": ("native/catalog_policy.hepta", "7a95a957874c1ee21b6bc6be6b4b75c4f09a20e421c0ec67b1d13690fb4a5e2d", "standard"),
    "serde-json": ("native/serde_json.hepta", "ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18", "serde-json.v1"),
    "sdk-catalog-wide": ("native/sdk_catalog.hepta", "756f1c990a20a268a5ad0b4e4007382e7ace1f99cb5f0a9cd65b0d6b621ba181", "serde-json.v1")}

def need(condition, message):
    if not condition:
        raise ValueError("catalog evidence: " + message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate evidence JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite evidence JSON")))

class Reader:
    def __init__(self, root):
        self.root = Path(root).absolute()
        need(self.root.resolve(strict=True) == self.root, "physical root")
        self.files = {}

    def raw(self, relative, expected=None):
        path = Path(relative)
        need(not path.is_absolute() and path.parts and ".." not in path.parts, "relative owned file")
        path = self.root / path
        need(path.resolve(strict=True) == path, "no symlink source/artifact")
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular unaliased source/artifact")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            need((opened.st_dev, opened.st_ino, opened.st_size) == (before.st_dev, before.st_ino, before.st_size), "stable opened inode")
            raw = stream.read()
            after = os.fstat(stream.fileno())
        need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink) ==
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, 1), "stable complete read")
        identity = {"bytes": len(raw), "sha256": sha(raw)}
        if expected is not None:
            need(identity == expected, "complete file identity " + relative)
        self.files[relative] = identity
        return raw

    def document(self, relative):
        return parse(self.raw(relative))

    def compressed(self, relative, size=None):
        raw = self.raw(relative)
        decoded = gzip.decompress(raw)
        if size is not None:
            need(len(decoded) == size, "complete decompressed extent " + relative)
        return decoded

def frame(mode, flags, modern, body):
    return b"HCATCQ01" + struct.pack("<7Q", mode, flags, modern, len(body), 0, 0, 0) + body

def schema_body(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()

def node_count(value):
    if type(value) is dict:
        return 1 + sum(node_count(child) for child in value.values())
    if type(value) is list:
        return 1 + sum(node_count(child) for child in value)
    return 1

def source_check(source):
    reader = Reader(source)
    profile_raw = reader.raw("source-profile.json")
    need(profile_raw == TRUSTED_PROFILE_BYTES, "trusted verifier source-profile bytes")
    profile = parse(profile_raw)
    need(profile["schema"] == "hepta.runtime.catalog-policy-source.v2" and profile["target_commit"] == TARGET, "source profile")
    need(type(profile["files"]) is dict and profile["files"], "source closure")
    for name, pin in profile["files"].items():
        reader.raw(name, pin)
    for name, expected, _ in SOURCE_PINS.values():
        need(sha(reader.raw(name)) == expected, "fixed native owner " + name)
    asset = reader.document("declarations.json")
    need(set(asset) == {"schema", "target_commit", "raw_tool_wires", "runtime_tool_names", "weight_tool_names", "hia_tool_names"}, "declarations-only author input")
    need(asset["target_commit"] == TARGET, "declarations target")
    tools = [parse(raw) for raw in asset["raw_tool_wires"]]
    names = [tool["name"] for tool in tools]
    need(len(names) == 136 and names == sorted(set(names)), "136 exact sorted names")
    raw_input = ("[" + ",".join(asset["raw_tool_wires"]) + "]").encode()
    need(reader.raw("catalog-input.json") == raw_input, "raw declaration input")
    proof = reader.document("native/author-proof.json")
    need(proof["source_sha256"] == SOURCE_PINS["catalog-policy"][1] and proof["expected_result_input"] is False,
        "author source/result separation")
    for key, name in (("pseudo_sha256", "catalog_policy.pseudo"), ("author_sha256", "author_catalog_policy.py"), ("declarations_sha256", "declarations.json")):
        need(proof[key] == sha(reader.raw(name)), "actual author input " + name)
    need((proof["functions"], proof["blocks"], proof["operations"]) == (42, 435, 2890), "actual compiler bounds")
    return reader, asset, tools, raw_input

def build_check(build, source):
    reader = Reader(build)
    boot = reader.document("bootstrap/bootstrap.json")
    dependency = boot["dependency"]
    need(dependency["commit"] == COMPILER and dependency["tree"] == COMPILER_TREE and dependency["files"], "pinned compiler dependency")
    need(boot["qualification"] == "development_fixed_point" and boot["generation_sha256"] == GENERATION, "bootstrap scope")
    for name in ("B1", "B2", "B3"):
        need(sha(reader.raw("bootstrap/" + name + ".image.bin")) == GENERATION, "complete native compiler generation")
    modules = {}
    for name, (source_name, expected_source, profile) in SOURCE_PINS.items():
        prefix = "modules/" + name + "/"
        manifest_raw = reader.raw(prefix + "manifest.json")
        manifest = parse(manifest_raw)
        need(manifest["name"] == name and manifest["source_sha256"] == expected_source and manifest["compiler_commit"] == COMPILER,
            "native module/source identity")
        need(manifest["compiler_sha256"] == GENERATION and manifest.get("buffer_profile", "standard") == profile and manifest["standalone"] is None, "native module capacity/ABI profile")
        caps = (8 << 20, 8 << 20, 32 << 20) if profile == "standard" else (16 << 20, 64 << 20, 256 << 20)
        need(tuple(manifest[name] for name in ("input_capacity", "output_capacity", "workspace_capacity")) == caps,
            "exact declared three-buffer maxima")
        source_raw = reader.raw(prefix + manifest["source"])
        need(source_raw == (Path(source) / source_name).read_bytes() and sha(source_raw) == expected_source, "actual compiler input source")
        need(reader.raw(prefix + "module.input.bin") == source_raw, "complete compile input")
        image = reader.raw(prefix + "module.image.bin")
        output = reader.raw(prefix + "module.output.bin")
        receipt = reader.document(prefix + "module.receipt.json")
        request = reader.document(prefix + "module.request.json")
        compiled = reader.document(prefix + "build.json")
        need(compiled["compile_receipt"] == receipt and compiled["compiler_dependency"] == dependency, "actual compilation provenance")
        need(manifest["image_sha256"] == sha(image) == receipt["produced_sha256"], "full native image")
        need(receipt["input_sha256"] == receipt["source_sha256"] == expected_source and receipt["input_bytes"] == len(source_raw), "compile source receipt")
        need(receipt["status"] == "returned" and receipt["source_unchanged"] is True and receipt["abi_status"] == 0,
            "native compiler completed")
        need(receipt["forbidden_compiler_modules_loaded"] == [] and receipt["return_encoding"] == "zero-extended-u32", "native-only compiler child")
        need(receipt["core_u32"] == receipt["result_u64"] == receipt["produced_bytes"] == len(image), "exact compiled image extent")
        need(receipt["artifact_sha256"] == receipt["image_sha256"] == GENERATION and request["image_sha256"] == GENERATION, "actual fixed B3")
        need(receipt["output_sha256"] == sha(output) and len(output) == 1048576 and output[:len(image)] == image and output[len(image):] == bytes((0xA5,)) * (len(output)-len(image)), "complete compiler output and tail")
        need(reader.raw(prefix + "module.stderr.log") == b"", "native compiler stderr")
        stdout = reader.document(prefix + "module.stdout.log")
        stdout_fields = ("abi_status", "core_u32", "forbidden_compiler_modules_loaded", "image_sha256",
            "limits", "loader_operations", "native_elapsed_ns", "output_sha256", "output_unchanged",
            "result_u64", "return_encoding", "source_sha256", "source_unchanged", "status", "workspace_header")
        need(type(stdout) is dict and set(stdout) == set(stdout_fields), "complete native compiler stdout fields")
        expected_stdout = {key: receipt[key] for key in stdout_fields}
        need(json.dumps(stdout, sort_keys=True, separators=(",", ":")) ==
             json.dumps(expected_stdout, sort_keys=True, separators=(",", ":")),
             "native compiler stdout/receipt custody")
        need(request["source_sha256"] == expected_source and request["workspace_fill"] == 0 and request["workspace_size"] == request["capacity"] == 1048576, "native compiler request bounds")
        need(Path(request["source"]).name == "module.input.bin" and Path(request["output"]).name == "module.output.bin" and Path(request["image"]).name == "B3.image.bin", "original compiler path roles")
        header = receipt["workspace_header"]
        need(header["40"] == 0 and header["48"] == 2 and header["56"] == len(image) and header["0"] == len(source_raw), "native compiler complete phase")
        modules[name] = {"manifest_sha256": sha(manifest_raw), "source_sha256": expected_source,
            "image_sha256": sha(image), "image_bytes": len(image)}
    return reader, modules

def read_call(reader, row, expected_input, expected_prefix):
    need(row["prefix"] == expected_prefix, "fixed native call identity")
    wire = reader.compressed(expected_prefix + ".input.gz", len(expected_input))
    need(wire == expected_input and row["input_sha256"] == sha(wire), "complete actual native request")
    out = reader.compressed(expected_prefix + ".output.gz", row["output_capacity"])
    work = reader.compressed(expected_prefix + ".workspace.gz", row["workspace_capacity"])
    need(row["output_sha256"] == sha(out) and row["workspace_sha256"] == sha(work), "complete native mutable records")
    need(type(row["code"]) is int and 0 <= row["code"] <= 4294967295, "u32 native return")
    return out, work

def policy_calls(reader, rows, wire, prefix, expected_count):
    need(len(rows) == 3, "complete workspace/output growth and success sequence")
    mode, flags, modern = struct.unpack_from("<3Q", wire, 8)
    count = node_count(parse(wire[64:]))
    required = 16384 + 96 * count
    need(rows[0]["workspace_capacity"] == 16384 and rows[0]["output_capacity"] == 64, "initial owned capacities")
    successful = None
    final_extent = rows[-1]["code"]
    for index, row in enumerate(rows):
        out, work = read_call(reader, row, wire, prefix + "-call-" + str(index))
        need(out[:8] == b"HCATCR01", "policy response magic")
        status, offset, size, tools, got_flags, got_modern, zero = struct.unpack_from("<7Q", out, 8)
        need((got_flags, got_modern, zero) == (flags, modern, 0), "policy context custody")
        need(struct.unpack_from("<Q", work, 0)[0] == count and struct.unpack_from("<Q", work, 16)[0] == 0,
            "full parsed node count/error")
        if index == 0:
            need((status, offset, size, tools, row["code"]) == (2, 0, required, 0, 64), "exact workspace growth")
            need(struct.unpack_from("<Q", work, 8)[0] == 0, "counting pass only")
        else:
            need(row["workspace_capacity"] == required and struct.unpack_from("<Q", work, 8)[0] == 1, "exact AST workspace")
            need(struct.unpack_from("<Q", work, 80)[0] == final_extent, "whole sizing/write cursor")
            if index == 1:
                need((row["output_capacity"], status, offset, size, tools, row["code"]) == (64, 3, 0, final_extent, 0, 64), "exact output growth")
            else:
                need(row["output_capacity"] == final_extent and (status, offset, size, tools) == (0, 64, final_extent - 64, expected_count), "complete successful output")
                need(struct.unpack_from("<Q", work, 88)[0] == 1, "whole output publication pass")
                successful = out[64:]
        need(out[row["code"]:] == bytes((0xA7,)) * (len(out) - row["code"]), "unaltered output tail")
    return successful

def reference_module(source):
    path = Path(source) / "reference/verify.py"
    spec = importlib.util.spec_from_file_location("catalog_original_readonly", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def controls_check(source, controls):
    source_check(source)
    spec = importlib.util.spec_from_file_location("catalog_fixed_controls", Path(source) / "qualify_controls.py")
    corpus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(corpus)
    reference = reference_module(source)
    reader = Reader(controls)
    result = reader.document("result.json")
    need(result["schema"] == "hepta.runtime.catalog-policy-controls.v1" and result["status"] == "PASS", "controls completion")
    rows = corpus.cases()
    need(len(rows) == len(result["records"]) == result["cases"] == result["actual_native_calls"] == 403, "fixed complete403 controls")
    previous_output = None
    previous_workspace = None
    for index, (case, row) in enumerate(zip(rows, result["records"], strict=True)):
        retained = case["label"].startswith("same-session-")
        need((row["label"], row["outcome"], row["same_session"]) == (case["label"], case["outcome"], retained), "control case identity")
        need((row["output_capacity"], row["workspace_capacity"]) == (case["output_capacity"], case["workspace_capacity"]), "control exact capacities")
        out, work = read_call(reader, row, case["wire"], f"control-{index:03d}")
        before_out = previous_output if retained and previous_output is not None else bytes((0xA7,)) * len(out)
        before_work = previous_workspace if retained and previous_workspace is not None else bytes((0x59,)) * len(work)
        want, semantic = corpus.expected(case, reference)
        code = row["code"]
        if want in (4294967295, 4294967294):
            need(code == want and out == before_out and work == before_work, "atomic invalid frame/output refusal")
        elif want == 64:
            need(code == 64 and out[:64] == semantic and out[64:] == before_out[64:], "exact framed refusal and output custody")
            if case["outcome"] == "workspace":
                need(work == before_work, "short workspace unchanged")
        else:
            need(64 <= code <= len(out) and out[:8] == b"HCATCR01" and struct.unpack_from("<7Q", out, 8) == (0,64,code-64,1,0,0,0), "control successful frame")
            need(parse(out[64:code]) == semantic and out[code:] == before_out[code:], "full policy control semantics/tail")
        if retained:
            previous_output, previous_workspace = out, work
    need(result["ordinary_target_domain_unchanged"] is True and result["fresh_original_build"] is False and result["whole_runtime_replaced"] is False,
        "separate additive control scope")
    return {"status":"PASS", "cases":403, "actual_native_calls":403, "process_launches":0, "files":reader.files}

def evidence_controls_check(source, build, native, evidence):
    reader=Reader(evidence)
    result=reader.document('result.json')
    labels=('missing-schema-row','wrong-native-call-count','missing-distinct-shape','wrong-cursor-attribution',
        'source-byte-change','forged-profile','rehashed-node-count','rehashed-request','rehashed-sdk-kind',
        'whole-wire-extra-byte','rehashed-compiler-tail','rehashed-compiler-stdout','admitted-symlink','admitted-hardlink','admitted-fifo')
    need(result['schema']=='hepta.runtime.catalog-policy-evidence-controls.v1' and result['status']=='PASS', 'evidence control completion')
    need(result['admissions']==3 and result['refusals']==15 and result['actual_native_launches']==result['actual_rust_launches']==0,
        'read-only evidence control scope')
    need(result['independent_file_copies'] is True and result['all_owned_snapshot_fixtures_retired'] is True,
        'independent retired source/artifact snapshots')
    need([row['label'] for row in result['records']]==list(labels),'fixed full refusal inventory')
    roots={'source':Reader(source),'build':Reader(build),'native':Reader(native)}
    for row in result['records']:
        label=row['label'];need(row['status']=='REFUSED' and row['message'] and row['error_type'] in ('ValueError','AssertionError','KeyError','RuntimeError','OSError'), 'actual recorded refusal')
        need(reader.document(label+'/refusal.json')==row,'whole refusal record')
        need(len(row['paths'])==len(row['after']) and row['paths'],'complete mutation files')
        for index,(path,after) in enumerate(zip(row['paths'],row['after'],strict=True)):
            root,relative=path.split('/',1);need(root in roots and after['path']==path,'owned mutation path')
            before=reader.compressed(label+f'/before-{index}.gz')
            need(before==roots[root].raw(relative),'complete before bytes from admitted original')
            if after['type']=='regular':
                changed=reader.compressed(label+f'/after-{index}.gz',after['bytes'])
                need(sha(changed)==after['sha256'] and after['nlink'] in (1,2),'complete changed bytes/link custody')
                if label=='admitted-hardlink':need(changed==before and after['nlink']==2,'actual alias refusal fixture')
            elif after['type']=='symlink':need(label=='admitted-symlink' and after['target']=='declarations.json','actual symlink refusal fixture')
            else:need(label=='admitted-fifo' and stat.S_ISFIFO(after['mode']),'actual FIFO refusal fixture')
    return {'status':'PASS','admissions':3,'refusals':15,'process_launches':0,'files':reader.files}

def verify(source, build, native, original, *, verify_original=True):
    sources, asset, tools, raw_input = source_check(source)
    builds, modules = build_check(build, source)
    reference = reference_module(source)
    original_summary = reference.verify(Path(original)) if verify_original else None
    originals = Reader(original)
    observations = {}
    for profile in PROFILES:
        value = originals.document(f"processes/profile-{profile}.stdout")
        need(value["target_commit"] == TARGET, "current original target")
        for key in ("raw_tool_wires", "runtime_tool_names", "weight_tool_names", "hia_tool_names"):
            need(value[key] == asset[key], "new original declarations equal implementation input")
        need([(row["protocol_version"], row["cursor_case"]) for row in value["list_cases"]] ==
             [(version, cursor) for version in VERSIONS for cursor in range(3)], "original complete context matrix")
        observations[profile] = value
    reader = Reader(native)
    result = reader.document("result.json")
    need(result["schema"] == "hepta.runtime.catalog-policy-development.v2" and result["status"] == "PASS", "native completion")
    need(result["target_commit"] == TARGET and all(result[key] is False for key in ("fresh_original_build", "whole_runtime_replaced", "production_activated", "old_stack_removal_qualified")), "native/retained original scope")
    need((result["actual_handler_cases"], result["ordinary_schema_cases"], result["frozen_schema_cases"], result["unique_catalog_abi_shapes"], result["catalog_native_calls"], result["native_calls"]) == (216,119,17,18,90,498), "exact independent case/call counts")
    need(len(result["rows"]) == 352 and len(result["shapes"]) == 18, "complete native row inventory")
    frozen = set(asset["hia_tool_names"]) | reference.FROZEN
    ordinary_count = 0
    frozen_count = 0
    for index, (tool, row) in enumerate(zip(tools, result["rows"][:136], strict=True)):
        is_frozen = tool["name"] in frozen
        need(row["domain"] == ("frozen-schema" if is_frozen else "ordinary-schema") and row["index"] == index and row["name"] == tool["name"], "exact schema row")
        expected = copy.deepcopy(tool["inputSchema"])
        if not is_frozen:
            for value in expected.values():
                reference.strip_null(value)
            reference.strip_noise(expected)
        expected_raw = json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        need(reader.raw(f"schema-{index:03d}.expected") == expected_raw, "complete original-derived schema")
        wire = frame(3 if is_frozen else 2, 0, 0, schema_body(tool["inputSchema"]))
        body = policy_calls(reader, row["calls"], wire, f"schema-{index:03d}", 1)
        need(parse(body) == expected, "full actual schema semantics")
        ordinary_count += int(not is_frozen)
        frozen_count += int(is_frozen)
    shapes = {}
    for index, row in enumerate(result["shapes"]):
        name = f"shape-{index:02d}"
        flags = 0 if index < 2 else 1 | ((index // 2 - 1) << 1)
        modern = index % 2
        wire = frame(1, flags, modern, raw_input)
        need((row["name"], row["flags"], row["modern"], row["input_sha256"]) == (name, flags, modern, sha(wire)), "fixed distinct request shape")
        body = policy_calls(reader, row["calls"], wire, name, row["count"])
        need(reader.compressed(name + ".policy-json.gz") == body, "complete policy payload")
        serde_input = b"HSJVAL01" + struct.pack("<2Q", 1, len(body)) + body
        serde_out, _ = read_call(reader, row["serde"], serde_input, name + "-serde")
        code = row["serde"]["code"]
        need(0 < code <= len(serde_out) and serde_out[code:] == bytes((0xA7,)) * (len(serde_out)-code), "complete canonical output and tail")
        canonical = serde_out[:code]
        need(reader.compressed(name + ".canonical-json.gz") == canonical and parse(canonical) == parse(body), "actual serde Value boundary")
        sdk_input = b"HRRSP001" + struct.pack("<2Q", 4, len(canonical)) + canonical
        sdk_out, _ = read_call(reader, row["sdk"], sdk_input, name + "-sdk")
        code = row["sdk"]["code"]
        need(sdk_out[:8] == b"HRRPO001" and struct.unpack_from("<7Q", sdk_out, 8) == (4,0,64,code-64,0,0,0), "target SDK typed catalog result")
        need(64 < code <= len(sdk_out) and sdk_out[code:] == bytes((0xA7,)) * (len(sdk_out)-code), "complete SDK output and tail")
        typed = sdk_out[64:code]
        need(reader.compressed(name + ".typed-json.gz") == typed, "complete typed result payload")
        need(wire not in shapes, "all18 requests byte-distinct")
        shapes[wire] = (name, typed, row["count"])
    for ordinal, row in enumerate(result["rows"][136:]):
        profile = PROFILES[ordinal // 24]
        index = ordinal % 24
        original_case = observations[profile]["list_cases"][index]
        flags = 0 if profile == "disabled" else 1 | (int(profile) << 1)
        modern = int(original_case["protocol_version"] in ("2026-07-28", "2026-08-01"))
        wire = frame(1, flags, modern, raw_input)
        shape, typed, count = shapes[wire]
        need(row["domain"] == "actual-handler" and row["profile"] == profile and row["case"] == index,
            "all216 actual handler contexts")
        need(row["protocol_version"] == original_case["protocol_version"] and row["cursor_case"] == original_case["cursor_case"], "actual context/cursor retained")
        need(row["shape"] == shape and row["abi_input_sha256"] == sha(wire), "equivalence by complete ABI byte equality")
        expected = original_case["result_wire"].encode()
        need(reader.compressed(f"catalog-{profile}-{index:02d}.expected.gz") == expected == typed, "entire actual handler wire")
        need(row["tool_count"] == count == original_case["tool_count"] and row["wire_bytes"] == len(typed) and row["wire_sha256"] == sha(typed), "complete result size/count")
    need((ordinary_count, frozen_count) == (119,17), "both schema domains complete")
    return {"schema": "hepta.runtime.catalog-policy-readonly.v2", "status": "PASS", "process_launches": 0,
        "target_commit": TARGET, "actual_handler_comparisons": 216, "ordinary_schemas":119, "frozen_schemas":17,
        "distinct_abi_inputs":18, "actual_native_calls":498, "modules":modules,
        "source_files":sources.files, "build_files":builds.files, "native_files":reader.files,
        "original_observations":originals.files, "original_reader":original_summary,
        "whole_runtime_replaced":False, "production_activated":False, "old_stack_removal_qualified":False}

def main():
    p = argparse.ArgumentParser()
    for name in ("source", "build", "native", "original"):
        p.add_argument("--"+name, type=Path, required=True)
    p.add_argument("--receipt",type=Path)
    args=p.parse_args()
    result=verify(args.source,args.build,args.native,args.original)
    if args.receipt:
        args.receipt.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in {"source_files","build_files","native_files","original_observations","original_reader"}},sort_keys=True))

if __name__=="__main__":
    main()
