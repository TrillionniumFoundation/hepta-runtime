#!/usr/bin/env python3
"""One copied-B3 HIA compile, zero formatter or original applications."""
from pathlib import Path
import argparse,ast,shutil,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,require,source_evidence,pin,B3,HEPTA
def source_check():
    identity=source_evidence(ROOT)
    for path in ROOT.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
    binding=decode((ROOT/"AUTHOR_BINDING.json").read_bytes())
    require(binding["author_commit"]=="a066161f112ad1178a04e14370ecd2892013745b"
        and binding["native_application_calls"]==binding["original_application_calls"]==0
        and binding["process"]["status"]=="PASS"and binding["process"]["returncode"]==0
        and binding["process"]["timeout"]is False
        and binding["process"]["source_manifest_sha256"]==binding["process"]["source_after_sha256"]
        ==binding["author_manifest_sha256"],"complete zero-application source author")
    for name,row in binding["complete"]["members"].items():
        path=ROOT/("native/"+name.split("/",1)[1]if name.startswith("generated/")else"author-evidence/"+name)
        require(pin(path)=={k:row[k]for k in("bytes","sha256")}and path.stat().st_mode&0o777==int(row["mode"],8),
            "all retained author output bytes and modes")
    composition=decode((ROOT/"native/complete_error_composition.json").read_bytes())
    require(composition["schema"]=="hepta.runtime.complete-error.author.v1"
        and composition["functions"]==35 and composition["instructions"]==5880 and composition["blocks"]==446
        and composition["source_sha256"]==pin(ROOT/"native/complete_error.hepta")["sha256"]
        and composition["retained_legacy"]["functions"]==34
        and composition["retained_legacy"]["entry_relocation"]=={"f0":"f34"}
        and composition["retained_legacy"]["inverse_relocation_exact_ir"] is True
        and composition["retained_legacy"]["other_function_names_unchanged"] is True
        and composition["retained_legacy"]["source_sha256"]==pin(ROOT/"baseline/path_error.hepta")["sha256"]
        and composition["retained_legacy"]["composition_sha256"]==pin(ROOT/"baseline/path_error_composition.json")["sha256"]
        and composition["complete_error"]==dict(full_prefixed_utf8=True,header_bytes=64,kind=3,
            magic="HCPER001",newline_added=False,reserved_words=[16,24,32,40,48],
            workspace_unchanged=True,zero_payload_rejected=True)
        and composition["platform_data_sha256"]==pin(ROOT/"native/platform_data.json")["sha256"],
        "exact generated source and retained baseline contract")
    return dict(status="COMPLETE_ERROR_SOURCE_PASS",source=identity,functions=35,instructions=5880,
        native_application_calls=0,original_application_calls=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["check","build"])
    p.add_argument("--hepta",type=Path);p.add_argument("--output",type=Path);a=p.parse_args();checked=source_check()
    if a.stage=="check":print(canonical(checked).decode(),end="");return
    from hia_native_build import NativeBuild
    import bootstrap_input
    require(a.hepta is not None and a.output is not None and not a.output.exists(),"fresh bounded native build")
    a.output.mkdir(parents=True);builder=NativeBuild(a.hepta,a.output/"build")
    copied=bootstrap_input.prepare(ROOT,a.output,builder.identity)
    require((a.output/"build/bootstrap/bootstrap.json").is_file(),"retained B3 installed before compile")
    manifest=builder.compile("complete-error",ROOT/"native/complete_error.hepta",standalone=None)
    require(builder.compiler_sha256==B3,"copied fixed-point compiler")
    metadata=decode(manifest.read_bytes());dep=a.output/"compiler-source";dep.mkdir()
    for name,digest in builder.identity["files"].items():
        target=dep/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(a.hepta/name,target);target.chmod((a.hepta/name).stat().st_mode&0o777)
        require(pin(target)["sha256"]==digest,"entire compiler source closure")
    result=dict(schema="hepta.runtime.complete-error.native-build.v1",compiler_commit=HEPTA,compiler_sha256=B3,
        member=dict(manifest=manifest.relative_to(a.output).as_posix(),manifest_sha256=pin(manifest)["sha256"],
            source_sha256=metadata["source_sha256"],image_sha256=metadata["image_sha256"]),
        image=pin(manifest.parent/metadata["image"]),application_calls=0,source=checked["source"],
        compiler_cold_gate_repeated=False,compiler_modes={name:(dep/name).stat().st_mode&0o777 for name in builder.identity["files"]},
        copied_bootstrap=copied,new_seed_executions=0,new_bootstrap_generations=0,hia_compiles=1)
    (a.output/"build/formatter.json").write_bytes(canonical(result))
    require(source_check()==checked,"source changed during native build")
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
