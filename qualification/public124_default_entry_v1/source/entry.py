#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Prepare and read the actual default124 build; never execute target handlers."""
from pathlib import Path
import argparse,hashlib,json,shutil,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require
import readonly
import binary_root_successor
import binary_owners_successor
HERE=Path(__file__).resolve().parent
PUBLIC=dict(bytes=26247168,sha256="cfc51c7004da6dd45d7d42314188563b6e83c6b03df4478a2281ef0b5d750755")
COMPILER="d3e2c90173cf733e42b299d0c4274df4b593a12f"
B3="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
def inputs():
    binary_owners_successor.verify_recipe(HERE)
    manifest=decode((HERE/"SOURCE_MANIFEST.json").read_bytes())
    require(set(manifest["sources"])|{"SOURCE_MANIFEST.json"}=={p.relative_to(HERE).as_posix() for p in HERE.rglob("*") if p.is_file()},"complete recipe source")
    for name,expected in manifest["sources"].items():require(pin(HERE/name)==expected,"exact frozen recipe bytes")
    return decode((HERE/"SOURCE_ROWS.json").read_bytes()),decode((HERE/"PATCH.json").read_bytes())
def check_source(root):
    rows,proof=inputs()
    successor=binary_owners_successor.profile(root)
    require(len(rows)==536 and len({r["path"] for r in rows})==536,"exact536 source paths")
    for row in rows:
        name=Path(row["path"]);require(not name.is_absolute() and ".." not in name.parts,"source relative path")
        path=root/name
        require(not any(p.is_symlink() for p in (path,*path.parents)) and path.is_file(),"ordinary source")
        raw=successor["originals"].get(str(name),path.read_bytes())
        require(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==
            {k:row[k] for k in ("bytes","sha256")},"complete source bytes: "+str(name))
        require(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"exact Git source object")
    raw=successor["originals"].get("scripts/hia_native_runtime_mcp_build.py",
        (root/"scripts/hia_native_runtime_mcp_build.py").read_bytes()).decode()
    before=(HERE/"before-default-build.py.txt").read_text()
    restored=raw
    for old,new in reversed(proof["exact_replacements"]):
        require(restored.count(new)==1,"one exact default-entry inverse")
        restored=restored.replace(new,old,1)
    require(restored==before and dict(bytes=len(raw.encode()),sha256=hashlib.sha256(raw.encode()).hexdigest())=={k:proof["new"][k] for k in ("bytes","sha256")},
        "whole default-entry inverse and pin")
    baseline=(HERE/"before-source-binding.json.txt").read_text()
    old,new=proof["old"],proof["new"]
    a='"scripts/hia_native_runtime_mcp_build.py": {\n      "bytes": '+str(old["bytes"])+',\n      "sha256": "'+old["sha256"]+'"\n    }'
    b='"scripts/hia_native_runtime_mcp_build.py": {\n      "bytes": '+str(new["bytes"])+',\n      "sha256": "'+new["sha256"]+'"\n    }'
    binding=successor["originals"].get("native/runtime_mcp_sources.json",
        (root/"native/runtime_mcp_sources.json").read_bytes()).decode()
    require(baseline.count(a)==1 and baseline.replace(a,b,1)==binding,"raw source-binding exact inverse")
    model=decode(binding.encode())
    require(len(model["sources"])==535 and set(model["sources"])=={r["path"] for r in rows}-{"native/runtime_mcp_sources.json"},
        "all bound sources")
    for row in rows:
        if row["path"] in model["sources"]:
            require(model["sources"][row["path"]]=={k:row[k] for k in ("bytes","sha256")},"source closure")
    result=dict(source_files=536,source_binding=pin(root/"native/runtime_mcp_sources.json"),hia_sources_changed=0,
        runtime_boundary_changed=False,exact_inverse=True)
    if successor["active"]:
        result.update(source_files=537,hia_sources_changed=1,runtime_boundary_changed=True,
            binary_root_operation9=True,additional_sources=[binary_root_successor.COMPOSITION])
    if successor["owners_active"]:
        result.update(source_files=544,hia_sources_changed=3,binary_owners_integrated=True,
            public_binary_write_registered=False,additional_sources=[binary_root_successor.COMPOSITION,*successor["additional_sources"]])
    return result
def prepare(source,capture):
    require(not capture.exists(),"fresh default-entry output")
    checked=check_source(source);capture.mkdir(parents=True)
    target=capture/"source"
    for row in inputs()[0]:
        src=source/row["path"];dst=target/row["path"];dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
    for name in checked.get("additional_sources",[]):
        src=source/name;dst=target/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
    require(check_source(target)==checked,"complete copied source")
    for path in sorted(target.rglob("*.py")):compile(path.read_bytes(),str(path),"exec")
    (capture/"SOURCE.json").write_bytes(canonical(checked))
    return checked
def read(capture):
    source=capture/"source";out=capture/"default-build"
    checked=check_source(source)
    owners=checked.get("binary_owners_integrated",False)
    direct,physical,total,slots=(118,119,126,71) if owners else (116,117,124,69)
    expected_public=binary_owners_successor.PUBLIC if owners else binary_root_successor.PUBLIC if checked.get("binary_root_operation9") else PUBLIC
    require(decode((capture/"SOURCE.json").read_bytes())==checked,"recorded preparation")
    build=decode((out/"BUILD.json").read_bytes())
    require(build["status"]=="NATIVE_BUILD_PASS" and build["physical_images"]==physical and build["runtime_hia_images"]==total
        and build["direct_hia_members"]==direct and build["packed_hia_members"]==8 and build["fresh_member_compiles"]==direct
        and build["checked_reused_members"]==0 and build["fresh_packed_member_compiles"]==8
        and build["default_public_entrypoint"] is True and build["fresh_hia_link_and_pack"] is True,
        "actual default entry fresh124 receipt")
    require(build["source_binding_sha256"]==checked["source_binding"]["sha256"]
        and build["publication_slots"]==[64,65,66,67,68] and build["publication_scope_forget_slot"]==68
        and build["publication_callable_context"]=="descriptor67+8","default builder exact bindings")
    old=Path(build["manifest"]).parents[2]
    def move(raw):
        rel=Path(raw).relative_to(old)
        require(".." not in rel.parts,"build path")
        return out/rel
    manifest=move(build["manifest"])
    require(pin(manifest)["sha256"]==build["manifest_sha256"],"actual public manifest")
    model=decode(manifest.read_bytes())
    require(model["compiler_commit"]==COMPILER and model["compiler_image_sha256"]==B3
        and model["physical_images"]==physical and model["runtime_hia_images"]==total
        and len(model["members"])==direct and len({r["name"] for r in model["members"]})==direct,
        "complete fixed fresh graph")
    require(model["source_binding"]["manifest_sha256"]==checked["source_binding"]["sha256"],"manifest source identity")
    require(len(model["extra_table"])==slots and model["extra_table"][69:]==(["binary_write_params","binary_call_plan"] if owners else [])
        and model["extra_table"][59:69]==["extract_gateway","extract_params","extract_call","extract_adapter",None,
        "publisher_gateway","publisher_params","publisher_call",None,None]
        and model["private_descriptor_base"]==8192 and model["private_engine_bytes"]==16384,
        "exact69 slots and unchanged descriptor/engine placement")
    if owners:
        require(build["binary_write_params_slot"]==69 and build["binary_call_plan_slot"]==70
            and build["public_binary_write_registered"] is False
            and model["binary_write_params_slot"]==69 and model["binary_call_plan_slot"]==70
            and model["private_slots"]==71 and model["private_work_high"]==12736 and model["private_output_high"]==12744
            and model["public_binary_write_registered"] is False
            and model["binary_write_effects_qualified"] is False and model["binary_write_audit_qualified"] is False
            and model["binary_write_lifecycle_qualified"] is False,"new exact layout and unclosed effect scope")
    for member in model["members"]:
        require(member["fresh_compile"] is True,"no earlier compile reused")
        leaf=move(member["manifest"])
        require(pin(leaf)["sha256"]==member["manifest_sha256"],"full leaf manifest")
        data=decode(leaf.read_bytes())
        require(data["schema"]=="hepta.runtime.native-module.v1" and data["compiler_commit"]==COMPILER
            and data["compiler_sha256"]==B3 and data.get("standalone") is None
            and data.get("buffer_profile","standard")==member["buffer_profile"],"exact leaf compile provenance")
        require((leaf.parent/data["source"]).read_bytes()==(source/member["source"]).read_bytes()
            and pin(source/member["source"])["sha256"]==member["source_sha256"]==data["source_sha256"],"compiled actual owner")
        require(pin(leaf.parent/data["image"])==dict(bytes=member["image_bytes"],sha256=member["image_sha256"])
            and data["image_sha256"]==member["image_sha256"],"whole compiled image")
    binary=move(build["elf"])
    require(binary==manifest.parent/model["elf"] and pin(binary)==expected_public
        and model["elf_sha256"]==expected_public["sha256"] and model["elf_bytes"]==expected_public["bytes"]
        and build["elf_sha256"]==expected_public["sha256"] and build["elf_bytes"]==expected_public["bytes"],
        "actual default binary must equal the retained actual124 public ELF")
    component=decode((source/"native/bellman_port_component.json").read_bytes())
    port=model["packed_capabilities"]["57"]
    require(port["runtime_hia_images"]==8 and pin(move(port["build_root"])/"bellman-port-packed.elf")==component["executable"]
        and {k:port["elf_"+k] for k in ("bytes","sha256")}==component["executable"],"actual packed8 exact bytes")
    for label in ("worker","port"):
        process=decode((out/"processes"/(label+".json")).read_bytes())
        require(process==build["dependency_processes"][label] and process["returncode"]==0 and process["status"]=="PASS",
            "fresh owned dependency process")
    for process in model["boundary_processes"]:
        require(process["exit_code"]==0 and process["timed_out"] is False,"actual link/pack boundary process")
    require(build["full_async_runtime_qualified"] is False and build["full_sdk_qualified"] is False
        and build["production_activated"] is False,"scope flags")
    result=dict(status="ACTUAL_DEFAULT124_ENTRY_COMPLETE_READ_PASS",source=checked,public_binary=expected_public,
        direct_fresh=direct,packed_fresh=8,physical_images=physical,descriptors=slots,retained124_public_binary_identical=True,ordinary686_on124_pending=True,
        hia_executed=False,rust_executed=False,full_async=False,full_sdk=False,production_installed=False)
    if checked.get("binary_root_operation9"):
        result.update(retained124_public_binary_identical=False,binary_root_product_binary_identical=True)
    if owners:
        result.update(status="ACTUAL_DEFAULT126_ENTRY_COMPLETE_READ_PASS",binary_root_product_binary_identical=False,
            binary_owners_product_binary_identical=True,public_binary_write_registered=False)
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("prepare","read"))
    p.add_argument("--source",type=Path);p.add_argument("--capture",type=Path,required=True);p.add_argument("--output",type=Path)
    a=p.parse_args()
    if a.mode=="prepare":result=prepare(a.source.resolve(strict=True),a.capture.absolute())
    else:
        require(a.output is not None and not a.output.exists(),"fresh read proof path")
        started=time.monotonic()
        result=readonly.guarded(lambda:read(a.capture.resolve(strict=True)),roots=(HERE,a.capture))
        require(time.monotonic()-started<180,"retained pure-reader180-second limit")
        a.output.write_bytes(canonical(result))
    print(json.dumps(result if a.mode=="prepare" else result["evidence"],sort_keys=True))
if __name__=="__main__":main()
