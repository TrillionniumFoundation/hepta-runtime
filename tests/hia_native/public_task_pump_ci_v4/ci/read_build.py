"""Read compiler custody, every fresh member, and all three actual packed entries.

This module never invokes a compiler, native image, assembler, or Rust binary.
prepare() imports the frozen reader dependencies before a caller installs its
read-only audit guard. verify_build() only reads existing artifacts.
"""
from pathlib import Path
import argparse
import ast
import ctypes
import hashlib
import importlib
import json
import stat
import struct
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import files, pin, require
from source_check import source

COMPILER = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
PORT_PIN = "2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1"
PROFILES = {"standard": (8<<20, 8<<20, 32<<20),
    "history.v1": (128<<20, 128<<20, 256<<20),
    "serde-json.v1": (16<<20, 64<<20, 256<<20),
    "sdk-message-target.v1": (32<<20, 64<<20, 256<<20)}
LOADED = {}

def raw(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), "nonregular evidence: " + str(path))
    return path.read_bytes()

def doc(path):
    return json.loads(raw(path))

def sha(value):
    return hashlib.sha256(value).hexdigest()

def prepare(package):
    package = Path(package).resolve(strict=True)
    key = str(package)
    if key in LOADED:
        return LOADED[key]
    graph = package/"graph/source"
    worker = package/"port/worker-source/tests/hia_native/blocking_worker"
    sys.path[:0] = [str(graph/"scripts"), str(package/"port/recipe"), str(worker)]
    builder = importlib.import_module("public_nine_build")
    require(Path(builder.__file__).resolve() == graph/"scripts/public_nine_build.py",
            "foreign graph builder import")
    port = importlib.import_module("port_build_evidence")
    custody = importlib.import_module("worker_compiler_custody")
    importlib.import_module("worker_build_evidence")
    qualifier = importlib.import_module("qualify_port")
    tree = ast.parse(raw(graph/"scripts/public_nine_build.py"))
    function = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == "build_runtime_mcp")
    result = next(x.value for x in function.body if isinstance(x, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == "result" for t in x.targets))
    require(isinstance(result, ast.Dict), "frozen graph result declaration differs")
    literal, keys = {}, set(builder.FALSE_FLAGS)
    for key_node, value_node in zip(result.keys, result.values, strict=True):
        if key_node is None:
            continue
        name = ast.literal_eval(key_node)
        keys.add(name)
        try:
            literal[name] = ast.literal_eval(value_node)
        except (ValueError, TypeError):
            pass
    for flag in builder.FALSE_FLAGS:
        literal[flag] = False
    value = (builder, port, custody, qualifier, literal, keys)
    LOADED[key] = value
    return value

def compile_module(worker, folder, name, body, profile, dependency, custody):
    manifest = doc(folder/"manifest.json")
    produced = raw(folder/"module.image.bin")
    require(raw(folder/(name+".hepta")) == body, "compiled source copy differs: " + name)
    expected = {"schema": "hepta.runtime.native-module.v1", "name": name,
        "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1", "target": "linux-x86_64",
        "compiler_commit": COMMIT, "compiler_sha256": COMPILER,
        "source": name+".hepta", "source_sha256": sha(body),
        "image": "module.image.bin", "image_sha256": sha(produced),
        "input_capacity": PROFILES[profile][0], "output_capacity": PROFILES[profile][1],
        "workspace_capacity": PROFILES[profile][2], "qualification": "development_fixed_point",
        "standalone": None}
    if profile != "standard":
        expected["buffer_profile"] = profile
    require(manifest == expected, "complete module manifest differs: " + name)
    receipt = custody.compile_receipt(worker, folder, "module",
        raw(worker/"build/bootstrap/B3.image.bin"), body, "module.image.bin", "flat-x86-64")
    require(doc(folder/"build.json") == {"compile_receipt": receipt,
        "compiler_dependency": dependency, "whole_runtime_replaced": False},
        "complete actual compile receipt differs: " + name)
    require(produced and len(produced) <= 1<<20 and not produced.startswith(b"\x7fELF"),
            "flat module extent differs")
    return manifest, produced

def object_text_and_symbols(obj):
    require(obj[:16] == b"\x7fELF\x02\x01\x01" + bytes(9), "object ELF identity")
    require(struct.unpack_from("<HHI", obj, 16) == (1, 62, 1), "object architecture/type")
    shoff, = struct.unpack_from("<Q", obj, 40)
    entsize, count, names_index = struct.unpack_from("<HHH", obj, 58)
    require(entsize == 64 and count > 0 and shoff + count*64 <= len(obj), "object section extent")
    sections = [struct.unpack_from("<IIQQQQIIQQ", obj, shoff+i*64) for i in range(count)]
    require(names_index < count, "object section name table")
    for row in sections:
        if row[1] != 8:
            require(row[4] + row[5] <= len(obj), "object complete section extent")
        require(row[1] not in (4, 9) or row[5] == 0, "object contains relocations")
    names_row = sections[names_index]
    names = obj[names_row[4]:names_row[4]+names_row[5]]
    section_names = [names[r[0]:names.index(0, r[0])].decode() for r in sections]
    index = section_names.index(".text")
    row = sections[index]
    body = obj[row[4]:row[4]+row[5]]
    symbols = {}
    for table in sections:
        if table[1] != 2:
            continue
        require(table[9] == 24 and table[5] % 24 == 0 and table[6] < count, "object symbol extent")
        strings = sections[table[6]]
        data = obj[strings[4]:strings[4]+strings[5]]
        for at in range(table[4], table[4]+table[5], 24):
            name, info, other, section, value, size = struct.unpack_from("<IBBHQQ", obj, at)
            if section == index:
                key = data[name:data.index(0, name)].decode()
                require(value <= len(body), "object text symbol outside body")
                if key:
                    require(key not in symbols or symbols[key] == value, "ambiguous object symbol")
                    symbols[key] = value
    require("_start" in symbols, "actual text entry missing")
    return body, symbols

def boundary_process(folder, label, command, origin, limit):
    record = doc(folder/(label+".process.json"))
    expected = {"name": label, "command": command, "cwd": origin,
        "timeout_seconds": limit, "exit_code": 0, "timed_out": False,
        "stdout": pin(folder/(label+".stdout")), "stderr": pin(folder/(label+".stderr"))}
    require(set(record) == set(expected)|{"elapsed_seconds"}, "boundary receipt schema differs")
    require(all(record[k] == v and type(record[k]) is type(v) for k, v in expected.items()),
            "boundary process command/status differs: " + label)
    require(type(record["elapsed_seconds"]) in (int, float) and 0 <= record["elapsed_seconds"] <= limit,
            "boundary process deadline differs: " + label)
    require(raw(folder/(label+".stderr")) == b"", "boundary process stderr differs: " + label)
    return record

def descriptor(path):
    return {"path": str(path), **pin(path)}

def verify_build(package, build, manifest_sha256):
    package, build = Path(package).resolve(strict=True), Path(build).resolve(strict=True)
    admitted = source(package, manifest_sha256)
    builder, port_reader, custody, qualifier, literal_fields, result_keys = prepare(package)
    origin = doc(build/"BUILD_ORIGIN.json")
    require(origin["manifest_sha256"] == manifest_sha256 and origin["source_admission"] == admitted,
            "build package admission differs")
    require(origin["fresh_direct_members"] == 92 and origin["packed_hia_members"] == 8
            and origin["same_ci_member_reuse_entries"] == ["journal", "trace"],
            "build ownership claim differs")
    original_out, original_package = Path(origin["output"]), Path(origin["package"])
    require(original_out.is_absolute() and original_package.is_absolute() and Path(origin["hepta"]).is_absolute(),
            "actual build origins are not absolute")
    graph = package/"graph/source"
    worker, port = build/"worker", build/"port/build-v3"
    port_proof = port_reader.verify_build(port, package/"port/source", worker, package/"port/worker-source")
    port_sources = qualifier.source_evidence(package/"port", PORT_PIN)
    worker_record = doc(worker/"native-build.json")
    require(worker_record["fresh_bootstrap"] is True and worker_record["reused_verified_bootstrap"] is False,
            "this CI must build the worker bootstrap freshly")
    dependency = doc(worker/"build/bootstrap/bootstrap.json")["dependency"]
    require(sha(raw(worker/"build/bootstrap/B3.image.bin")) == COMPILER, "actual compiler differs")
    fresh = {}
    names = set()
    for name, source_name, profile in builder.MEMBERS:
        module = "task-pump-" + name.replace("_", "-")
        folder = build/"production/modules"/module
        body = raw(graph/"native"/(source_name+".hepta"))
        manifest, image = compile_module(worker, folder, module, body, profile, dependency, custody)
        row = {"name": name, "source": "native/"+source_name+".hepta", "source_sha256": sha(body),
            "manifest": str(original_out/"production/modules"/module/"manifest.json"),
            "manifest_sha256": pin(folder/"manifest.json")["sha256"], "image_sha256": sha(image),
            "image_bytes": len(image), "buffer_profile": profile, "fresh_compile": True}
        require(name not in fresh, "duplicate graph member")
        fresh[name] = {"row": row, "image": image, "module": module, "manifest": manifest}
        names.add(module)
    require(len(fresh) == 92, "frozen direct member count differs")
    require(doc(build/"same-ci-members.json") == {n: x["row"]["manifest"] for n, x in fresh.items()},
            "same-CI leaf reuse paths differ")
    authority_names = ["authority", "authority_record", "authority_kdf", "rf_sha", "authority_aead",
                       "authority_nonce", "authority_scope", "authority_entropy", "authority_loader"]
    authority = doc(graph/"native/caller_owner_export_profile.json")["members"]
    require(len(authority) == 9, "authority local profile count differs")
    for expected, name in zip(authority, authority_names, strict=True):
        require(all(fresh[name]["row"][key] == expected[key] for key in
                    ("source_sha256", "image_sha256", "image_bytes")), "fixed authority member differs")
    images = {n: x["image"] for n, x in fresh.items()}
    images["bellman_port"] = raw(port/"bellman-port-packed.elf")
    require(doc(graph/"native/bellman_port_component.json")["executable"] ==
        {"bytes": len(images["bellman_port"]), "sha256": sha(images["bellman_port"])},
        "graph packed capability binding differs")
    extra = {slot: name for slot, name in enumerate(builder.EXTRA) if name is not None}
    extra[57] = "bellman_port"
    ordered = list(dict.fromkeys([*extra.values(), *fresh]))
    require(len(ordered) == 93 and ordered[-5:] == builder.FENCE, "physical order/fence range differs")
    index = {name: i for i, name in enumerate(ordered)}
    configuration = dict(zip(builder.CONFIG_SYMBOLS, builder.CONFIG, strict=True))
    configuration.update({name: name for name in builder.FENCE})
    source_binding = builder.source_check(graph)
    entries = {}
    for label in ("production", "journal", "trace"):
        directory, folder = build/label, build/label/"task-pump"
        original_directory = original_out/label
        original_folder = original_directory/"task-pump"
        m = doc(folder/"manifest.json")
        require(set(m) == result_keys, "graph manifest schema/key set differs: " + label)
        for key, value in literal_fields.items():
            require(type(m[key]) is type(value) and m[key] == value, "graph fixed declaration differs: " + key)
        require(m["members"] == [dict(x["row"], fresh_compile=(label == "production"))
                for x in fresh.values()], "graph exact member/source/reuse set differs: " + label)
        require(m["source_root"] == str(original_package/"graph/source")
                and m["build_root"] == str(original_directory)
                and m["manifest_path"] == str(original_folder/"manifest.json"),
                "actual graph source/build origins differ")
        require(m["source_binding"] == source_binding, "actual graph source closure differs")
        boundary_names = [builder.BASE, builder.TRANSPORT, *builder.BOUNDARIES]
        require(m["boundary_sources"] == {n: source_binding["files"][n]["sha256"] for n in boundary_names},
                "mechanical source boundary differs")
        require(m["physical_images"] == 93 and m["runtime_hia_images"] == 100
                and m["physical_image_members"] == ordered, "packed physical member set differs")
        require(m["compiler_commit"] == COMMIT and m["compiler_image_sha256"] == COMPILER,
                "graph compiler identity differs")
        require(m["config_table"] == builder.CONFIG and m["extra_table"] == builder.EXTRA
                and m["view_table"] == builder.VIEW and m["fence_table"] == builder.FENCE
                and len(m["extra_table"]) == 59, "fixed descriptor tables differ")
        private, traced = label != "production", label == "trace"
        require(m["private_task_pump_fixture"] is private and m["private_task_pump_trace"] is traced
                and m["fixed_journal_fd"] == (3 if private else None)
                and m["fixed_host_trace_fd"] == (4 if traced else None)
                and m["journal_fd_caller_owned"] is private,
                "fixed process capability entry differs")
        require(m["private_instance_fixture"] is False and m["fixture_sessions"] is None
                and m["fixture_pseudo_selectors"] == [] and m["actual_fixture_private_selectors"] is False,
                "public entry gained fixture selectors")
        require(m["packed_capabilities"] == {"57": {"sources": port_sources, "build": port_proof,
            "package": str(original_package/"port"), "build_root": str(original_out/"port/build-v3"),
            "worker_build_root": str(original_out/"worker"), "runtime_hia_images": 8,
            "elf_bytes": len(images["bellman_port"]), "elf_sha256": sha(images["bellman_port"])}},
                "complete packed capability evidence differs")
        require(files(directory/"bootstrap") == files(worker/"build/bootstrap"),
                "graph bootstrap is not the same CI fresh compiler")
        module_names = {"wide-elf-linker", "wide-image-pack"} | (names if label == "production" else set())
        require({p.name for p in (directory/"modules").iterdir()} == module_names,
                "unexpected compiled or reused module directories")
        compile_module(worker, directory/"modules/wide-elf-linker", "wide-elf-linker",
            raw(worker/"compiler-source/examples/hia_bootstrap/elf_static_linker.hepta"),
            "standard", dependency, custody)
        compile_module(worker, directory/"modules/wide-image-pack", "wide-image-pack",
            raw(graph/"native/runtime_mcp_image_packer.hepta"), "history.v1", dependency, custody)
        assembly = builder.adapter_source(graph, private_pump_fixture=private, private_pump_trace=traced).encode()
        require(raw(folder/"combined.S") == assembly and m["assembled_source_sha256"] == sha(assembly),
                "complete actual mechanical assembly differs")
        obj = raw(folder/"bridge.o")
        require(m["object_sha256"] == sha(obj), "actual assembler object differs")
        body, symbols = object_text_and_symbols(obj)
        prefix = raw(folder/"linked-prefix.elf")
        require(len(prefix) >= 256+len(body) and prefix[256:256+len(body)] == body,
                "actual HIA linker complete text differs")
        require(prefix[:16] == b"\x7fELF\x02\x01\x01"+bytes(9)
                and struct.unpack_from("<HHI", prefix, 16) == (2, 62, 1),
                "linked prefix ELF identity")
        require(struct.unpack_from("<QQQ", prefix, 24) == (0x4000e8, 64, 0)
                and struct.unpack_from("<IHHHHHH", prefix, 48) == (0,64,56,3,0,0,0),
                "linked prefix executable layout differs")
        segments = [struct.unpack_from("<IIQQQQQQ", prefix, 64+i*56) for i in range(3)]
        require(segments[0] == (1,5,0,0x400000,0x400000,256+len(body),256+len(body),4096),
                "linked executable segment differs")
        require(segments[1] == (1,6,len(prefix),0x400000+len(prefix),0x400000+len(prefix),0,0,4096),
                "linked mutable segment differs")
        require(segments[2] == (0x6474e551,6,0,0,0,0,0,16), "executable stack policy differs")
        link_input = b"HIALNK01"+struct.pack("<3Q",1,6,0)+b"_start"+struct.pack("<Q",len(obj))+obj
        require(raw(folder/"link.input.bin") == link_input, "full HIA linker input differs")
        link = doc(folder/"link.receipt.json")
        link_expected = {"actual_return":len(prefix), "fresh_compile":True,
            "manifest":str(original_directory/"modules/wide-elf-linker/manifest.json"),
            "manifest_sha256":pin(directory/"modules/wide-elf-linker/manifest.json")["sha256"],
            "input_bytes":len(link_input), "input_sha256":sha(link_input),
            "output_bytes":len(prefix), "output_sha256":sha(prefix),
            "output_capacity":8<<20, "workspace_capacity":32<<20, "pinned_linker_source_unchanged":True}
        require(set(link) == set(link_expected)|{"elapsed_seconds"}
                and all(type(link[k]) is type(v) and link[k] == v for k,v in link_expected.items())
                and type(link["elapsed_seconds"]) in (int,float) and link["elapsed_seconds"] >= 0,
                "actual HIA linker receipt differs")
        require(m["link"] == link, "graph linker receipt association")
        patches = []
        for name, image in configuration.items():
            patches.append((2,256+symbols[name+"_call_displacement"],index[image]))
        for slot, image in extra.items():
            patches.append((1,256+symbols["grow_fixture_images"]+slot*8,index[image]))
        for slot, image in enumerate(builder.VIEW):
            patches.append((1,256+symbols["runtime_grow_view_images"]+slot*8,index[image]))
        tables = (
            ("runtime_text_create_images",("lc_spec","lc_read","lc_path","lc_mkdir","lc_write","key","cache")),
            ("runtime_text_body_images",("tb_body","lc_read","key","tb_lock","tb_edit","tb_match","tb_history",
                                        "tb_atomic","cache","tb_render","tb_unlink","view_error")),
            ("runtime_authority_images",authority_names))
        for symbol, members in tables:
            for slot, image in enumerate(members):
                patches.append((1,256+symbols[symbol]+slot*8,index[image]))
        patched_bytes = set()
        for kind, at, number in patches:
            width = 8 if kind == 1 else 4
            require(256 <= at and at+width <= 256+len(body) and prefix[at:at+width] == bytes(width),
                    "fixed patch placeholder changed")
            for position in range(at, at+width):
                require(position not in patched_bytes, "overlapping fixed patch")
                patched_bytes.add(position)
        pieces = [images[name] for name in ordered]
        pack_input = (b"HIAIMG02"+struct.pack("<4Q",len(prefix),len(pieces),len(patches),0)+prefix
            +b"".join(struct.pack("<Q",len(image)) for image in pieces)
            +b"".join(struct.pack("<3Q",*patch) for patch in patches)+b"".join(pieces))
        require(raw(folder/"pack.input.bin") == pack_input, "complete actual HIA pack input differs")
        executable, positions = bytearray(prefix), []
        for image in pieces:
            executable += bytes((-len(executable))%16)
            positions.append(len(executable))
            executable += image
        text_end = len(executable)
        executable += bytes((-len(executable))%4096)
        for kind, at, number in patches:
            if kind == 1:
                struct.pack_into("<Q",executable,at,0x400000+positions[number])
            else:
                struct.pack_into("<I",executable,at,positions[number]-at-4)
        struct.pack_into("<QQ",executable,96,text_end,text_end)
        struct.pack_into("<QQQ",executable,128,len(executable),0x400000+len(executable),0x400000+len(executable))
        expected_output = b"HIAIMR02"+struct.pack("<3Q",0,len(executable),0)+executable
        require(raw(folder/"pack.output.bin") == expected_output, "complete actual packed output differs")
        workcap = (64+len(pieces)*8+4095)&~4095
        workspace = bytearray(workcap)
        struct.pack_into("<QQ",workspace,8,text_end,len(executable))
        for i, position in enumerate(positions):
            struct.pack_into("<Q",workspace,64+i*8,position)
        require(raw(folder/"pack.workspace.bin") == workspace, "complete actual pack workspace differs")
        packed = doc(folder/"pack.receipt.json")
        image_paths = [str(original_out/"port/build-v3/bellman-port-packed.elf") if name == "bellman_port"
                       else str(original_out/"production/modules"/fresh[name]["module"]/"module.image.bin")
                       for name in ordered]
        expected_pack = {"fresh_compile":True,
            "manifest":str(original_directory/"modules/wide-image-pack/manifest.json"),
            "manifest_sha256":pin(directory/"modules/wide-image-pack/manifest.json")["sha256"],
            "input_bytes":len(pack_input),"input_sha256":sha(pack_input),
            "output_bytes":len(expected_output),"output_sha256":sha(expected_output),
            "actual_return":32,"output_capacity":len(expected_output),"workspace_capacity":workcap,
            "prefix_text_offset":256,"fixed_patches":[list(x) for x in patches],
            "image_offsets":positions,"image_sources":image_paths}
        require(set(packed) == set(expected_pack)|{"elapsed_seconds"}
                and all(type(packed[k]) is type(v) and packed[k] == v for k,v in expected_pack.items())
                and type(packed["elapsed_seconds"]) in (int,float) and packed["elapsed_seconds"] >= 0,
                "actual pack receipt differs")
        require(m["pack"] == packed, "graph pack receipt association")
        binary_name = "task-pump-fixture.elf" if private else "runtime-mcp.elf"
        binary = folder/binary_name
        require(raw(binary) == executable and m["elf"] == binary_name
                and m["elf_sha256"] == sha(executable) and m["elf_bytes"] == len(executable),
                "complete final executable differs")
        require(binary.stat().st_mode & 0o111, "final executable mode differs")
        origin_graph = str(original_package/"graph/source")
        processes = [
            boundary_process(folder,"assemble",["as","--64","-o",str(original_folder/"bridge.o"),
                str(original_folder/"combined.S")],origin_graph,60),
            boundary_process(folder,"relocations",["readelf","-r",str(original_folder/"bridge.o")],origin_graph,30),
            boundary_process(folder,"readelf",["readelf","-lW",str(original_folder/binary_name)],origin_graph,30)]
        require(m["boundary_processes"] == processes, "actual boundary processes differ")
        require(b"There are no relocations" in raw(folder/"relocations.stdout"), "relocation inspection differs")
        headers = raw(folder/"readelf.stdout")
        require(b"INTERP" not in headers and b"RWE" not in headers and b"GNU_STACK" in headers,
                "actual final segment inspection differs")
        require(type(m["elapsed_seconds"]) in (int,float) and m["elapsed_seconds"] >= 0,
                "graph elapsed observation differs")
        entries[label] = {"elf":descriptor(binary), "manifest":descriptor(folder/"manifest.json"),
            "runtime_hia_images":100, "direct_fresh_members":92 if label=="production" else 0,
            "same_ci_reused_members":0 if label=="production" else 92,
            "actual_link_and_pack":True, "complete_pack_input_output_workspace":True,
            "linker_capture_scope":"complete returned prefix; linker unused output/workspace not retained by frozen builder",
            "fixed_journal_fd":3 if private else None, "fixed_host_trace_fd":4 if traced else None}
    return {"status":"FRESH_PUMP_GRAPH_BUILD_READBACK_PASS", "source":admitted,
        "runtime_hia_images":100, "fresh_direct_members":92, "packed_hia_members":8,
        "physical_containers":93, "entries":entries, "packed_capability":port_proof,
        "fresh_bootstrap_once":True, "matching_source_cold_qualified":False,
        "public_wire_qualified":False, "async_qualified":False, "full_sdk_qualified":False,
        "native_or_rust_executed":False, "files_written":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("package","build"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--manifest-sha256",required=True)
    a=p.parse_args()
    prepare(a.package)
    print(json.dumps(verify_build(a.package,a.build,a.manifest_sha256),sort_keys=True))

if __name__=="__main__":
    main()
