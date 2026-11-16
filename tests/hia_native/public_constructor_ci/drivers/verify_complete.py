"""Read the complete fresh80/actual-constructor/public90 artifact; launch nothing."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, sys
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
BASE="0bbb39cbfd04cdb16539c64c7305c4e5d10e6e1594cfcf66acc7bad9f28668cc"
HEPTA="d3e2c90173cf733e42b299d0c4274df4b593a12f"
B3="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
LABELS=["fresh-retained-62","fresh-public-80","fresh-constructor-components",
        "native-constructor-65","fresh-original-constructor-65","actual-public-nine",
        "readonly-complete"]

def read(path):return json.loads(path.read_bytes())
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def baseline(root):
    built=read(root/"BUILD.json")
    assert built["status"]=="FRESH_RETAINED_62_PASS"
    assert built["fresh_members"]==62 and built["existing_binary_inputs"] is False
    assert built["rust_executed"] is False and built["fresh_cold_qualified"] is False
    assert built["input_manifest_sha256"]=="d234cd39fdf8d2e7f3a1fa394f57c69b0d851742c5321d9d6094021a4c748366"
    folder=root/"build/retained-eight"
    raw=(folder/"manifest.json").read_bytes()
    assert SHA(raw)==built["manifest_sha256"]
    manifest=json.loads(raw)
    assert manifest["status"]=="PASS" and manifest["physical_images"]==62
    assert manifest["compiler_commit"]==HEPTA and manifest["compiler_image_sha256"]==B3
    binary=(folder/manifest["elf"]).read_bytes()
    assert SHA(binary)==manifest["elf_sha256"]==built["elf_sha256"]==BASE
    assert len(binary)==manifest["elf_bytes"]
    assert len(manifest["members"])==62 and len({r["name"] for r in manifest["members"]})==62
    binding=(root/"source/native/runtime_mcp_sources.json").read_bytes()
    assert SHA(binding)==manifest["source_binding"]["manifest_sha256"]
    sources=json.loads(binding)["sources"]
    assert sources==manifest["source_binding"]["files"]
    for relative,pin in sources.items():
        path=Path(relative);assert not path.is_absolute() and ".." not in path.parts
        raw=(root/"source"/path).read_bytes()
        assert SHA(raw)==pin["sha256"] and len(raw)==pin["bytes"]
    for row in manifest["members"]:
        assert row["fresh_compile"] is True
        path=root/"build/modules"/Path(row["manifest"]).parent.name/"manifest.json"
        raw=path.read_bytes();assert SHA(raw)==row["manifest_sha256"]
        module=json.loads(raw)
        assert module["compiler_commit"]==HEPTA and module["compiler_sha256"]==B3
        for key in ("source","image"):
            raw=(path.parent/module[key]).read_bytes()
            assert SHA(raw)==row[key+"_sha256"]==module[key+"_sha256"]
        assert (path.parent/module["source"]).read_bytes()==(root/"source"/row["source"]).read_bytes()
    for name in ("B1","B2","B3"):
        assert SHA((root/"build/bootstrap"/(name+".image.bin")).read_bytes())==B3
    return dict(fresh_members=62,elf_sha256=BASE)

def verify(source,run,module_map=None,require_recipe_pass=False):
    source=source.resolve(strict=True);run=run.resolve(strict=True)
    sys.path.insert(0,str(source/"drivers"))
    from package_checks import verify_source
    package=verify_source(source)
    recipe=read(run/"RECIPE.json")
    assert recipe["source_manifest_sha256"]==SHA((source/"source-manifest.json").read_bytes())
    assert recipe["status"] in (("PASS",) if require_recipe_pass else ("RUNNING","PASS"))
    rows=recipe["processes"]
    wanted=LABELS if recipe["status"]=="PASS" else LABELS[:-1]
    assert [row["label"] for row in rows]==wanted
    for row in rows:
        assert row["exit_code"]==0 and row["outer_timeout_seconds"] is None
        for stream in ("stdout","stderr"):
            raw=(run/"processes"/(row["label"]+"."+stream)).read_bytes()
            assert row[stream]==dict(bytes=len(raw),sha256=SHA(raw))
    base=baseline(run/"retained-eight")
    core=load("_constructor_core_reader",source/"source/scripts/verify_constructor_native.py")
    native=core.verify(source/"source",run/"component",run/"component-native")
    assert native["status"]=="PASS" and native["profile"]=="wide" and native["cases"]==65
    actual=load("_constructor_actual_reader",source/"drivers/verify_constructor_reference.py")
    original=actual.verify(source,run/"original",run/"component-native")
    public_reader=load("_constructor_public_reader",source/"drivers/verify_native_constructor_public.py")
    public=public_reader.verify(source/"source",run/"public",run/"public-loop",module_map)
    assert public["status"]=="READONLY_NATIVE_PUBLIC_NINE_PASS"
    assert public["physical_images"]==public["fresh_member_compiles"]==80 and public["checked_reused_members"]==0
    manifest=read(run/"public/build/public-nine-constructor/manifest.json")
    constructor=next(r for r in manifest["members"] if r["name"]=="text_constructor")
    assert constructor["source_sha256"]==native["source_sha256"]
    assert constructor["image_sha256"]==native["image_sha256"]
    built=read(run/"public/BUILD.json")
    assert built["fresh_member_compiles"]==80 and built["checked_reused_members"]==0
    assert built["bootstrap_reused"] is True
    for flag in ("full_sdk_qualified","full_136_route_qualified","full_async_text_editor_qualified",
                 "scope_wide_qualified","cancellation_fence_timing_qualified","production_activated",
                 "old_path_removed","fresh_cold_qualified","target_original_public_handler_comparison",
                 "target_connection_identity_integrated","target_general_response_owner_integrated",
                 "target_async_transport_integrated"):
        assert recipe[flag] is False,flag
    result=dict(schema="hepta.runtime.public-constructor-complete-readonly.v1",
        status="READONLY_FRESH80_CONSTRUCTOR_PUBLIC90_PASS",
        source_manifest_sha256=SHA((source/"source-manifest.json").read_bytes()),
        source_files=len(package["files"]),fresh_retained_members=62,fresh_public_members=80,
        reused_public_members=0,constructor_cases=65,
        constructor_native_calls=native["native_calls"],retained_typed_comparisons=native["retained_typed_comparisons"],
        actual_target_rust_cases=original["cases"],actual_target_constructor_comparison=True,
        registry_archives_read=original["registry_archives_read"],
        registry_source_files_hashed=original["registry_source_files_hashed"],
        public_counts=public["counts"],candidate_elf_sha256=public["elf_sha256"],
        constructor_source_sha256=constructor["source_sha256"],constructor_image_sha256=constructor["image_sha256"],
        native_or_original_code_launched=False,full_sdk_qualified=False,full_136_route_qualified=False,
        target_original_public_handler_comparison=False,production_activated=False,old_path_removed=False)
    if recipe["status"]=="PASS":
        assert recipe["counts"]==result["public_counts"]
        assert recipe["candidate_elf_sha256"]==result["candidate_elf_sha256"]
        assert recipe["actual_target_constructor_comparison"] is True
        assert recipe["fresh_80_candidate"] is True and recipe["fresh_62_baseline"] is True
        assert recipe["fresh_exact_rust_built"] is True and recipe["rust_executed"] is True
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","run"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--module-map",type=Path)
    p.add_argument("--require-recipe-pass",action="store_true")
    a=p.parse_args()
    print(json.dumps(verify(a.source,a.run,a.module_map,a.require_recipe_pass),sort_keys=True))

if __name__=="__main__":main()

