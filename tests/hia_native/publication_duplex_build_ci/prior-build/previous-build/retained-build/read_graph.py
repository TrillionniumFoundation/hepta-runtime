"""Read all actual sources, compiler receipts, fixed tables, ELF and full pack buffers."""
from pathlib import Path
import ast,importlib,json,sys
sys.dont_write_bytecode=True
from read_primitives import *
import wait_native_fixture
HERE=Path(__file__).resolve().parent
LOADED={}
def descriptor(p):return {"path":str(p),**pin(p)}
def prepare(retained):
    retained=Path(retained).resolve(strict=True);key=str(retained)
    if key in LOADED:return LOADED[key]
    graph=retained/"capture/composition/source"
    package=graph/"runtime_support/bellman_port"
    sys.path[:0]=[str(graph/"scripts"),str(package/"recipe"),str(package/"worker-source/tests/hia_native/blocking_worker")]
    builder=importlib.import_module("public_nine_build")
    require(Path(builder.__file__).resolve()==graph/"scripts/public_nine_build.py","actual shared builder import")
    port_reader=importlib.import_module("port_build_evidence")
    custody=importlib.import_module("worker_compiler_custody")
    importlib.import_module("worker_build_evidence")
    qualifier=importlib.import_module("qualify_port")
    tree=ast.parse(raw(graph/"scripts/public_nine_build.py"))
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="build_runtime_mcp")
    result=next(n.value for n in function.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="result" for t in n.targets))
    literal,keys={},set(builder.FALSE_FLAGS)
    for k,v in zip(result.keys,result.values,strict=True):
        if k is None:continue
        name=ast.literal_eval(k);keys.add(name)
        try:literal[name]=ast.literal_eval(v)
        except (ValueError,TypeError):pass
    for flag in builder.FALSE_FLAGS:literal[flag]=False
    LOADED[key]=(builder,port_reader,custody,qualifier,literal,keys)
    return LOADED[key]
def source(retained):
    graph=Path(retained)/"capture/composition/source"
    index=doc(HERE/"SOURCE_INDEX.json")
    wanted={r["path"]:{k:r[k] for k in ("bytes","sha256")} for r in index["files"]}
    require(len(wanted)==486 and set(wanted)=={p.relative_to(graph).as_posix() for p in graph.rglob("*") if p.is_file()},"complete shared source inventory")
    for name,identity in wanted.items():require(pin(graph/name)==identity,"shared source bytes: "+name)
    require(pin(graph/"native/runtime_mcp_sources.json")==index["binding"],"shared source binding")
    return wanted
def verify(retained,fixture=None):
    retained=Path(retained).resolve(strict=True)
    graph=retained/"capture/composition/source";native=retained/"capture/native-build"
    source(retained)
    builder,port_reader,custody,qualifier,literal_fields,result_keys=prepare(retained)
    identity=doc(HERE/"SOURCE_INDEX.json");report=doc(native/"BUILD.json")
    require(report["status"]=="FRESH_COMBINED_PUBLICATION123_BUILD_PASS" and report["source_files"]==486 and report["direct_fresh_hia_images"]==115 and report["packed_fresh_hia_images"]==8,"actual combined source/build status")
    require(report["roles"]==identity["build_roles"],"three actual roles")
    require(report["public_qualified"] is False and report["shared_extract_wait_qualified"] is False and report["installed"] is False,"build-only scope")
    original_out=Path(identity["build_roles"]["public"]["manifest"]).parents[2]
    base_graph=Path(doc(native/"build-public/publication-public/manifest.json")["source_root"])
    worker,port=native/"worker",native/"port/build-v3"
    package=graph/"runtime_support/bellman_port"
    port_proof=port_reader.verify_build(port,package/"source",worker,package/"worker-source")
    port_sources=qualifier.source_evidence(package,PORT_PIN)
    wr=doc(worker/"native-build.json")
    require(wr["fresh_bootstrap"] is True and wr["reused_verified_bootstrap"] is False,"fresh actual compiler bootstrap")
    dependency=doc(worker/"build/bootstrap/bootstrap.json")["dependency"]
    require(sha(raw(worker/"build/bootstrap/B3.image.bin"))==COMPILER,"actual retained B3")
    fresh={};names=set()
    for name,source_name,profile in builder.MEMBERS:
        module="publication-public-"+name.replace("_","-")
        folder=native/"build-public/modules"/module
        body=raw(graph/"native"/(source_name+".hepta"))
        manifest,image=compile_module(worker,folder,module,body,profile,dependency,custody)
        row={"name":name,"source":"native/"+source_name+".hepta","source_sha256":sha(body),"manifest":str(original_out/"build-public/modules"/module/"manifest.json"),"manifest_sha256":pin(folder/"manifest.json")["sha256"],"image_sha256":sha(image),"image_bytes":len(image),"buffer_profile":profile,"fresh_compile":True}
        require(name not in fresh,"unique actual HIA member")
        fresh[name]={"row":row,"image":image,"module":module,"manifest":manifest};names.add(module)
    require(len(fresh)==115,"all115 direct receipts")
    authority_names=["authority","authority_record","authority_kdf","rf_sha","authority_aead","authority_nonce","authority_scope","authority_entropy","authority_loader"]
    authority=doc(graph/"native/caller_owner_export_profile.json")["members"]
    require(len(authority)==9,"authority source profile")
    for expected,name in zip(authority,authority_names,strict=True):require(all(fresh[name]["row"][k]==expected[k] for k in ("source_sha256","image_sha256","image_bytes")),"actual authority source/image")
    images={n:x["image"] for n,x in fresh.items()};images["bellman_port"]=raw(port/"bellman-port-packed.elf")
    require(doc(graph/"native/bellman_port_component.json")["executable"]=={"bytes":len(images["bellman_port"]),"sha256":sha(images["bellman_port"])},"actual packed8 component")
    extra={slot:name for slot,name in enumerate(builder.EXTRA) if name is not None};extra[57]="bellman_port"
    ordered=list(dict.fromkeys([*extra.values(),*fresh]));require(len(ordered)==116 and ordered[-5:]==builder.FENCE,"all116 actual containers")
    index={name:i for i,name in enumerate(ordered)}
    configuration=dict(zip(builder.CONFIG_SYMBOLS,builder.CONFIG,strict=True))
    configuration.update({name:name for name in builder.FENCE})
    configuration.update(text_publication_body="publisher_body",text_publication_codec="rf_sha",text_publication_errno="publisher_errno")
    source_binding=builder.source_check(graph);require(report["source"]==source_binding,"complete build source binding")
    entries={}
    rolemap={"production":"public","instances":"filesystem","trace":"trace"}
    labels=list(rolemap)
    fixture_bytes=None
    if fixture is not None:
        fixture=Path(fixture).resolve(strict=True)
        before,fixture_bytes,proof=wait_native_fixture.source(graph,builder)
        require(doc(fixture/"FIXTURE_SOURCE.json")==proof and raw(fixture/"before.S")==before and raw(fixture/"fixture.S")==fixture_bytes,"six-splice complete fixture source/inverse")
        labels.append("fixture")
    for label in labels:
        if label=="fixture":
            directory=fixture/"build";folder=directory/"wait-control"
            original_directory=Path(doc(folder/"manifest.json")["build_root"])
            require(original_directory==Path(doc(fixture/"ORIGIN.json")["build"]),"fixture build origin")
            original_folder=original_directory/"wait-control";original_graph=Path(doc(fixture/"ORIGIN.json")["source"])
            require(original_graph==Path(doc(fixture/"ORIGIN.json")["retained"])/"capture/composition/source","fixture exact restored source origin")
            port_origin=Path(doc(fixture/"ORIGIN.json")["retained"])/"capture/native-build/port/build-v3"
            worker_origin=Path(doc(fixture/"ORIGIN.json")["retained"])/"capture/native-build/worker"
            member_origin=Path(doc(fixture/"ORIGIN.json")["retained"])/"capture/native-build/build-public/modules"
        else:
            role=rolemap[label];directory=native/("build-"+role);folder=directory/("publication-"+role)
            original_directory=original_out/("build-"+role);original_folder=original_directory/("publication-"+role);original_graph=base_graph
            port_origin=original_out/"port/build-v3";worker_origin=original_out/"worker";member_origin=original_out/"build-public/modules"
            info=identity["build_roles"][role]
            require(pin(folder/"manifest.json")["sha256"]==info["manifest_sha256"] and pin(folder/Path(info["binary"]).name)=={"bytes":info["binary_bytes"],"sha256":info["binary_sha256"]},"frozen full entry identity")
        m = doc(folder/"manifest.json")
        require(set(m) == result_keys, "graph manifest schema/key set differs: " + label)
        for key, value in literal_fields.items():
            require(type(m[key]) is type(value) and m[key] == value, "graph fixed declaration differs: " + key)
        require(m["members"] == [dict(x["row"], manifest=str(member_origin/x["module"]/"manifest.json"), fresh_compile=(label == "production")) for x in fresh.values()], "graph exact member/source/reuse set differs: " + label)
        require(m["source_root"] == str(original_graph)
                and m["build_root"] == str(original_directory)
                and m["manifest_path"] == str(original_folder/"manifest.json"),
                "actual graph source/build origins differ")
        require(m["source_binding"] == source_binding, "actual graph source closure differs")
        instance = label == "instances"
        boundary_names = [builder.BASE, *(builder.FIXTURE_BOUNDARIES if instance else [builder.TRANSPORT]),
            *(n for n in builder.BOUNDARIES if not instance or not n.startswith("scripts/runtime_mcp_task_"))]
        require(m["boundary_sources"] == {n: source_binding["files"][n]["sha256"] for n in boundary_names},
                "mechanical source boundary differs")
        require(m["physical_images"] == 116 and m["runtime_hia_images"] == 123
                and m["physical_image_members"] == ordered, "packed physical member set differs")
        require(m["compiler_commit"] == COMMIT and m["compiler_image_sha256"] == COMPILER,
                "graph compiler identity differs")
        require(m["config_table"] == builder.CONFIG and m["extra_table"] == builder.EXTRA
                and m["view_table"] == builder.VIEW and m["fence_table"] == builder.FENCE
                and len(m["extra_table"]) == 69, "fixed descriptor tables differ")
        private, traced = label in ("trace", "fixture"), label in ("trace", "fixture")
        require(m["private_task_pump_fixture"] is private and m["private_task_pump_trace"] is traced
                and m["fixed_journal_fd"] == (3 if private else None)
                and m["fixed_host_trace_fd"] == (4 if traced else None)
                and m["journal_fd_caller_owned"] is private,
                "fixed process capability entry differs")
        require(m["private_instance_fixture"] is instance
                and m["fixture_sessions"] == (2 if instance else None)
                and m["fixture_pseudo_selectors"] == ([33,34,41,57,58,64] if instance else [])
                and m["actual_fixture_private_selectors"] is instance,
                "explicit private instance entry differs")
        require(m["task_registry_operation15_integrated"] is (not instance)
                and m["task_event_pump_integrated"] is (not instance)
                and m["async_eof_policy_owner"] == (None if instance else 58),
                "private instance transport was confused with the public task pump")
        require(m["packed_capabilities"] == {"57": {"sources": port_sources, "build": port_proof,
            "package": str(original_graph/"runtime_support/bellman_port"), "build_root": str(port_origin),
            "worker_build_root": str(worker_origin), "runtime_hia_images": 8,
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
        assembly = fixture_bytes if label=="fixture" else builder.adapter_source(graph, private_fixture=instance, private_pump_fixture=private, private_pump_trace=traced).encode()
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
            ("runtime_authority_images",authority_names),
            ("runtime_batch_body_images",("batch_body","batch_lock","key","tb_history","tb_atomic",
                "cache","lc_read","tb_lock","tb_edit","batch_plan","endpoint","batch_verify","batch_apply","batch_render")),
            ("runtime_extract_body_images",("extract_body","lc_read","key","tb_lock","tb_edit","extract_data",
                "tb_history","tb_atomic","cache","lc_path","lc_mkdir","view_error","endpoint","extract_line_verify")))
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
        image_paths = [str(port_origin/"bellman-port-packed.elf") if name == "bellman_port"
                       else str(member_origin/fresh[name]["module"]/"module.image.bin")
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
        binary_name = "filesystem-fixture.elf" if instance else "task-pump-fixture.elf" if private else "runtime-mcp.elf"
        binary = folder/binary_name
        require(raw(binary) == executable and m["elf"] == binary_name
                and m["elf_sha256"] == sha(executable) and m["elf_bytes"] == len(executable),
                "complete final executable differs")
        require(binary.stat().st_mode & 0o111, "final executable mode differs")
        origin_graph = str(original_graph)
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
            "runtime_hia_images":123, "direct_fresh_members":115 if label=="production" else 0,
            "same_ci_reused_members":0 if label=="production" else 115,
            "actual_link_and_pack":True, "complete_pack_input_output_workspace":True,
            "linker_capture_scope":"complete returned prefix; linker unused output/workspace not retained by frozen builder",
            "fixed_journal_fd":3 if private else None, "fixed_host_trace_fd":4 if traced else None,
            "private_instance_fixture":instance, "public_async_qualification_inherited":False}
    require(source(retained)=={r["path"]:{k:r[k] for k in ("bytes","sha256")} for r in identity["files"]},"source unchanged during full read")
    return {"status":"COMPLETE_SHARED123_GRAPH_AND_FIXTURE_READ_PASS","runtime_hia_images":123,"direct_original_fresh":115,"packed_hia_images":8,"physical_images":116,"descriptor_slots":69,"entries":entries,"fixture_added":fixture is not None,"source_binding":identity["binding"],"source_files":486,"complete_compile_receipts":True,"complete_pack_buffers":True,"actual_application_semantics_qualified":False,"native_or_rust_executed":False}
