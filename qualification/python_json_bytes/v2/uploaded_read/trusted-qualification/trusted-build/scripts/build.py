#!/usr/bin/env python3
"""One copied-B3 HIA compile, zero JSON decoder or original applications."""
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
    require(binding["author_commit"]=="abc337d34992d1d399c926d97440764360a42ef5"
        and binding["native_application_calls"]==binding["original_application_calls"]==0
        and binding["process"]["status"]=="PASS"and binding["process"]["returncode"]==0
        and binding["process"]["timeout"]is False
        and binding["process"]["source_manifest_sha256"]==binding["process"]["source_after_sha256"]
        ==binding["author_manifest_sha256"],"complete zero-application source author")
    for name,row in binding["complete"]["members"].items():
        path=ROOT/("native/"+name.split("/",1)[1]if name.startswith("generated/")else"author-evidence/"+name)
        require(pin(path)=={k:row[k]for k in("bytes","sha256")}and path.stat().st_mode&0o777==int(row["mode"],8),
            "all retained author output bytes and modes")
    composition=decode((ROOT/"native/python_json_bytes_composition.json").read_bytes())
    require(composition["schema"]=="hepta.runtime.python-json-bytes.author.v1"
        and composition["functions"]==28 and composition["instructions"]==2008 and composition["blocks"]==178
        and composition["source_sha256"]==pin(ROOT/"native/python_json_bytes.hepta")["sha256"]
        and composition["input_limit"]==6291456 and composition["workspace_minimum"]==1024,
        "exact generated decoder contract")
    return dict(status="PYTHON_JSON_BYTES_SOURCE_PASS",source=identity,functions=28,instructions=2008,
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
    manifest=builder.compile("python-json-bytes",ROOT/"native/python_json_bytes.hepta",standalone=None,buffer_profile="serde-json.v1")
    require(builder.compiler_sha256==B3,"copied fixed-point compiler")
    metadata=decode(manifest.read_bytes());dep=a.output/"compiler-source";dep.mkdir()
    for name,digest in builder.identity["files"].items():
        target=dep/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(a.hepta/name,target);target.chmod((a.hepta/name).stat().st_mode&0o777)
        require(pin(target)["sha256"]==digest,"entire compiler source closure")
    result=dict(schema="hepta.runtime.python-json-bytes.native-build.v1",compiler_commit=HEPTA,compiler_sha256=B3,
        member=dict(manifest=manifest.relative_to(a.output).as_posix(),manifest_sha256=pin(manifest)["sha256"],
            source_sha256=metadata["source_sha256"],image_sha256=metadata["image_sha256"]),
        image=pin(manifest.parent/metadata["image"]),application_calls=0,source=checked["source"],
        compiler_cold_gate_repeated=False,compiler_modes={name:(dep/name).stat().st_mode&0o777 for name in builder.identity["files"]},
        copied_bootstrap=copied,new_seed_executions=0,new_bootstrap_generations=0,hia_compiles=1)
    (a.output/"build/module.json").write_bytes(canonical(result))
    require(source_check()==checked,"source changed during native build")
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
