"""Pure readback of the default 102-image build and every native link/pack byte."""
from pathlib import Path
import ast, json, math, struct, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import catalog_ci_support as c
import graph_read_support as support
PREPARED={}

def prepare(package):
    package=Path(package).absolute();key=str(package)
    if key in PREPARED:return PREPARED[key]
    c.source_check(package)
    old=ast.parse(c.regular(package/"ci/retained_graph_reader.py"))
    new=ast.parse(c.regular(package/"ci/graph_read_support.py"))
    oldf={n.name:n for n in old.body if isinstance(n,ast.FunctionDef)}
    newf={n.name:n for n in new.body if isinstance(n,ast.FunctionDef)}
    proof=c.read_json(package/"ci/GRAPH_READER_PROOF.json")
    c.need(c.pin(c.regular(package/"ci/retained_graph_reader.py"))=={
        k:proof["retained"][k] for k in ("bytes","sha256")},"qualified reader baseline")
    for name in ("compiler","bootstrap","object_layout","linked_prefix"):
        c.need(ast.dump(oldf[name],include_attributes=False)==ast.dump(newf[name],include_attributes=False),
            "unchanged complete compiler/layout check: "+name)
    sys.path.insert(0,str(package/"graph/scripts"))
    builder=c.source_module("configured_graph_admitted_builder",package/"graph/scripts/public_nine_build.py")
    PREPARED[key]=builder
    return builder

def verify(package,folder,*,expected_origin,expected_source,expected_manifest):
    builder=prepare(package);c.source_check(package)
    source=package/"graph";folder=Path(folder).absolute();r=c.Reader(folder)
    report=r.document("BUILD.json")
    c.need(report["schema"]=="hepta.runtime.public102-authority-batch.build.v1"
        and report["status"]=="NATIVE_BUILD_PASS" and report["physical_images"]==102
        and report["fresh_member_compiles"]==102 and report["checked_reused_members"]==0
        and report["fresh_hia_link_and_pack"] is True and report["default_public_entrypoint"] is True,
        "complete fresh default public build")
    c.need(report["bootstrap_reused"] is True,"same-CI qualified component B3 explicitly reused")
    for key in ("rust_executed","actual_target_handshake_compared","full_async_runtime_qualified",
            "full_sdk_qualified","independent_cold_qualified","production_activated","old_path_removed"):
        c.need(report[key] is False,"build scope: "+key)
    c.need(r.document("reuse.json")=={},"all runtime members freshly compiled")
    relative="build/public-authority-batch/manifest.json"
    raw=r.raw(relative,expected_manifest);m=c.parse(raw);out=folder/"build/public-authority-batch"
    producer=Path(expected_origin);producer_out=producer/"build/public-authority-batch"
    c.need(producer.is_absolute() and Path(expected_source).is_absolute(),"parent-bound build/source origins")
    c.need(report["manifest"]==m["manifest_path"]==str(producer/relative)
        and report["manifest_sha256"]==expected_manifest["sha256"]
        and m["build_root"]==str(producer/"build") and m["source_root"]==expected_source,"actual build producer binding")
    binding=builder.source_check(source)
    c.need(m["schema"]=="hepta.runtime.authority-batch-union-build.v1" and m["status"]=="PASS"
        and m["physical_images"]==102 and m["source_binding"]==binding
        and m["compiler_commit"]==support.COMMIT and m["compiler_image_sha256"]==support.GENERATION
        and m["private_instance_fixture"] is False and m["private_descriptor_base"]==8192
        and m["private_engine_bytes"]==16384,"actual fixed graph")
    for key in ("batch_public_route_qualified","full_sdk_qualified","full_136_route_qualified",
            "whole_runtime_replaced","old_path_removed","production_activated",
            "catalog_all_configuration_public_qualified","target_connection_public_semantics_qualified"):
        c.need(m[key] is False,"graph cannot assert semantic qualification")
    c.need(m["catalog_installed_capability_mask"]==1 and m["catalog_config_presence_child"]==6
        and m["catalog_config_presence_operation"]==3 and m["catalog_config_presence_phase"]==18
        and m["advertised_catalog_tools_by_runtime_presence"]=={"absent":7,"present":10}
        and len(builder.EXTRA)==57 and m["authority_slot"]==56,"actual installed catalog/config seam")
    c.need(m["extra_table"]==builder.EXTRA and m["config_table"]==builder.CONFIG
        and m["view_table"]==builder.VIEW and m["fence_table"]==builder.FENCE,"fixed caller table identity")
    dependency=c.read_json(package/"ci/COMPILER_INPUTS.json")
    def admitted(path):
        p=Path(path)
        c.need(p.is_absolute() and p.is_relative_to(producer),"artifact remains in owned build")
        return folder/p.relative_to(producer)
    def tracked(path):
        p=Path(path).absolute()
        c.need(p.is_relative_to(folder),"compiler reader stays inside current relocated build")
        return r.raw(p.relative_to(folder).as_posix())
    saved_regular,saved_json=support.regular,support.read_json
    support.regular=tracked;support.read_json=lambda p:c.parse(tracked(p))
    module_paths=set();images={};manifests={}
    try:
        support.bootstrap(folder/"build")
        boot=r.document("build/bootstrap/bootstrap.json")
        c.need(boot["dependency"]==dependency,"full 1080-source compiler/bootstrap closure")
        c.need(len(m["members"])==102,"exact runtime member count")
        for row,(name,stem,profile) in zip(m["members"],builder.MEMBERS,strict=True):
            c.need(row["name"]==name and row["source"]=="native/"+stem+".hepta"
                and row["buffer_profile"]==profile and row["fresh_compile"] is True,"fresh ordered member")
            path=admitted(row["manifest"]);module_paths.add(path.parent)
            c.need(c.sha(tracked(path))==row["manifest_sha256"],"complete member manifest")
            source_raw=c.regular(source/row["source"])
            image,manifest=support.compiler(path.parent,source_raw)
            c.need(r.document(path.parent.relative_to(folder).as_posix()+"/build.json")["compiler_dependency"]==dependency,
                "each compiler invocation's full source closure")
            c.need(manifest["source_sha256"]==row["source_sha256"]==c.sha(source_raw)
                and manifest.get("buffer_profile","standard")==profile
                and c.pin(image)=={"bytes":row["image_bytes"],"sha256":row["image_sha256"]},"actual member bytes/profile")
            images[name]=image;manifests[name]=row["manifest_sha256"]
        order=[]
        for name in [n for n in builder.EXTRA if n is not None]+[row[0] for row in builder.MEMBERS]:
            if name not in order:order.append(name)
        c.need(len(order)==102 and order==m["physical_image_members"],"exact physical image order")
        assembly=r.raw("build/public-authority-batch/combined.S")
        c.need(assembly==builder.adapter_source(source,private_fixture=False).encode()
            and c.sha(assembly)==m["assembled_source_sha256"],"complete regenerated GAS boundary")
        obj=r.raw("build/public-authority-batch/bridge.o")
        c.need(c.sha(obj)==m["object_sha256"],"complete assembler object")
        text,symbols=support.object_layout(obj)
        prefix=support.linked_prefix(text,symbols["_start"])
        c.need(r.raw("build/public-authority-batch/linked-prefix.elf")==prefix,"complete HIA ELF-linker result")
        c.need(r.raw("build/public-authority-batch/link.input.bin")==b"HIALNK01"+struct.pack("<3Q",1,6,0)
            +b"_start"+struct.pack("<Q",len(obj))+obj,"complete HIA linker input")
        for stage,expected_source in (("link",c.regular(package/"ci/elf_static_linker.hepta")),
                ("pack",c.regular(source/"native/runtime_mcp_image_packer.hepta"))):
            row=m[stage]
            c.need(r.document("build/public-authority-batch/"+stage+".receipt.json")==row
                and row["fresh_compile"] is True and type(row["elapsed_seconds"]) in (int,float)
                and math.isfinite(row["elapsed_seconds"]) and 0<=row["elapsed_seconds"]<180,
                "actual HIA link/pack process budget")
            path=admitted(row["manifest"]);module_paths.add(path.parent)
            c.need(c.sha(tracked(path))==row["manifest_sha256"],"actual native linker/packer manifest")
            support.compiler(path.parent,expected_source)
            c.need(r.document(path.parent.relative_to(folder).as_posix()+"/build.json")["compiler_dependency"]==dependency,
                "link/pack compiler full source closure")
            for stream in ("input","output"):
                name="linked-prefix.elf" if stage=="link" and stream=="output" else stage+"."+stream+".bin"
                c.need(c.pin(r.raw("build/public-authority-batch/"+name))=={
                    "bytes":row[stream+"_bytes"],"sha256":row[stream+"_sha256"]},"full native stage stream")
        c.need(m["link"]["actual_return"]==len(prefix) and m["link"]["output_capacity"]==8<<20
            and m["link"]["workspace_capacity"]==32<<20,"linker complete extent/capacities")
        indices={name:i for i,name in enumerate(order)};patches=[]
        for symbol,name in [*zip(builder.CONFIG_SYMBOLS,builder.CONFIG),*((n,n) for n in builder.FENCE)]:
            patches.append([2,256+symbols[symbol+"_call_displacement"],indices[name]])
        for slot,name in enumerate(builder.EXTRA):
            if name is not None:patches.append([1,256+symbols["grow_fixture_images"]+slot*8,indices[name]])
        tables=(("runtime_grow_view_images",builder.VIEW),
            ("runtime_text_create_images",["lc_spec","lc_read","lc_path","lc_mkdir","lc_write","key","cache"]),
            ("runtime_text_body_images",["tb_body","lc_read","key","tb_lock","tb_edit","tb_match","tb_history","tb_atomic","cache","tb_render","tb_unlink","view_error"]),
            ("runtime_authority_images",["authority","authority_record","authority_kdf","rf_sha","authority_aead","authority_nonce","authority_scope","authority_entropy","authority_loader"]),
            ("runtime_batch_body_images",["batch_body","batch_lock","key","tb_history","tb_atomic","cache","lc_read","tb_lock","tb_edit","batch_plan","endpoint","batch_verify","batch_apply","batch_render"]))
        for symbol,names in tables:
            for slot,name in enumerate(names):patches.append([1,256+symbols[symbol]+slot*8,indices[name]])
        c.need(m["pack"]["fixed_patches"]==patches,"complete fixed image patch list")
        packed=b"HIAIMG02"+struct.pack("<4Q",len(prefix),102,len(patches),0)+prefix
        packed+=b"".join(struct.pack("<Q",len(images[n])) for n in order)
        packed+=b"".join(struct.pack("<3Q",*p) for p in patches)+b"".join(images[n] for n in order)
        c.need(r.raw("build/public-authority-batch/pack.input.bin")==packed,"complete pack input and all 102 images")
        expected=bytearray(prefix);positions=[]
        for name in order:
            expected+=bytes((-len(expected))%16);positions.append(len(expected));expected+=images[name]
        text_end=len(expected);expected+=bytes((-len(expected))%4096)
        for kind,at,index in patches:struct.pack_into("<Q" if kind==1 else "<I",expected,at,
            4194304+positions[index] if kind==1 else positions[index]-at-4)
        struct.pack_into("<QQ",expected,96,text_end,text_end)
        struct.pack_into("<QQQ",expected,128,len(expected),4194304+len(expected),4194304+len(expected))
        c.need(m["pack"]["image_offsets"]==positions and m["pack"]["actual_return"]==32
            and m["pack"]["output_capacity"]==32+len(expected),"complete packed image layout")
        c.need(r.raw("build/public-authority-batch/pack.output.bin")==b"HIAIMR02"
            +struct.pack("<3Q",0,len(expected),0)+expected,"complete actual HIA pack output")
        workspace=bytearray((64+102*8+4095)&~4095);struct.pack_into("<QQ",workspace,8,text_end,len(expected))
        struct.pack_into("<102Q",workspace,64,*positions)
        c.need(r.raw("build/public-authority-batch/pack.workspace.bin")==workspace
            and m["pack"]["workspace_capacity"]==len(workspace),"complete pack workspace and tail")
        c.need(m["elf"]=="runtime-mcp.elf" and r.raw("build/public-authority-batch/runtime-mcp.elf")==expected
            and c.pin(expected)=={"bytes":m["elf_bytes"],"sha256":m["elf_sha256"]}
            and report["elf"]==str(producer_out/m["elf"])
            and report["elf_bytes"]==len(expected) and report["elf_sha256"]==c.sha(expected),"complete default executable")
        c.need([row["name"] for row in m["boundary_processes"]]==["assemble","relocations","readelf"],
            "all actual mechanical processes")
        commands={"assemble":["as","--64","-o",str(producer_out/"bridge.o"),str(producer_out/"combined.S")],
            "relocations":["readelf","-r",str(producer_out/"bridge.o")],
            "readelf":["readelf","-lW",str(producer_out/"runtime-mcp.elf")]}
        for row in m["boundary_processes"]:
            name=row["name"];limit=60 if name=="assemble" else 30
            c.need(row==r.document("build/public-authority-batch/"+name+".process.json")
                and row["command"]==commands[name] and row["cwd"]==expected_source
                and type(row["exit_code"])is int and row["exit_code"]==0 and row["timed_out"] is False
                and type(row["timeout_seconds"])is int and row["timeout_seconds"]==limit
                and type(row["elapsed_seconds"])in(int,float) and math.isfinite(row["elapsed_seconds"])
                and 0<=row["elapsed_seconds"]<limit,"actual boundary process command/deadline")
            for stream in ("stdout","stderr"):
                r.raw("build/public-authority-batch/"+name+"."+stream,row[stream])
            c.need(r.raw("build/public-authority-batch/"+name+".stderr")==b"","boundary diagnostic stream")
        c.need(r.raw("build/public-authority-batch/relocations.stdout")==b"\nThere are no relocations in this file.\n",
            "no unexpected linker relocations")
        headers=r.raw("build/public-authority-batch/readelf.stdout")
        c.need(b"INTERP" not in headers and b"RWE" not in headers and b"GNU_STACK" in headers,"actual ELF permissions")
        actual_modules={p.parent for p in (folder/"build/modules").glob("*/manifest.json")}
        c.need(actual_modules==module_paths and len(module_paths)==104,"exact 102 plus linker/packer compiler set")
    finally:
        support.regular,support.read_json=saved_regular,saved_json
    return {"status":"FRESH_CONFIGURED_DEFAULT102_BUILD_READONLY_PASS","fresh_runtime_members":102,
        "fresh_linker_packer":2,"runtime_images":102,"compiled_images":104,"manifest":expected_manifest,
        "elf":c.pin(expected),"manifest_relative":relative,"elf_relative":"build/public-authority-batch/runtime-mcp.elf",
        "source_binding":binding,"module_manifests":manifests,"files":r.files,
        "reader_process_launches":0,"native_execution":False,"rust_execution":False,"whole_runtime_replaced":False}
