"""Build the 80-image public9 + shared constructor graph, with exact optional reuse."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys
import time

sys.dont_write_bytecode=True
SHA=lambda data:hashlib.sha256(data).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("source","hepta","output"):
        p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--bootstrap",type=Path)
    p.add_argument("--reuse-public-manifest",type=Path)
    p.add_argument("--reuse-constructor-build",type=Path)
    a=p.parse_args()
    source,output=a.source.resolve(),a.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    build=output/"build"
    report=dict(schema="hepta.runtime.public-constructor-build.v1",status="RUNNING",
        source=str(source),rust_executed=False,independent_cold_qualified=False,
        ordinary_public_qualified=False,actual_target_rust_compared=False,full_sdk_qualified=False)
    def save():
        (output/"BUILD.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    save()
    began=time.monotonic()
    try:
        if a.bootstrap:
            shutil.copytree(a.bootstrap.resolve(),build/"bootstrap")
        sys.path.insert(0,str(source/"scripts"))
        from public_nine_build import MEMBERS,build_runtime_mcp
        assert len(MEMBERS)==80
        available={}
        if a.reuse_public_manifest:
            prior_path=a.reuse_public_manifest.resolve()
            raw=prior_path.read_bytes();prior=json.loads(raw)
            assert prior["status"]=="PASS" and prior["physical_images"]==79
            for row in prior["members"]:
                relocated=prior_path.parent.parent/"modules"/Path(row["manifest"]).parent.name/"manifest.json"
                assert SHA(relocated.read_bytes())==row["manifest_sha256"]
                available[(row["source_sha256"],row["buffer_profile"])]=relocated
            report["prior_public_manifest"]=dict(path=str(prior_path),sha256=SHA(raw))
        if a.reuse_constructor_build:
            core=a.reuse_constructor_build.resolve()
            built=json.loads((core/"BUILD.json").read_bytes())
            assert built["status"]=="HIA_COMPILE_PASS"
            row=built["modules"]["text-result-constructor"]
            path=core/row["manifest"]
            assert SHA(path.read_bytes())==row["manifest_sha256"]
            available[(row["source_sha256"],row["buffer_profile"])]=path
            report["prior_constructor_build"]=dict(path=str(core/"BUILD.json"),
                sha256=SHA((core/"BUILD.json").read_bytes()))
        reuse={}
        for name,owner,profile in MEMBERS:
            key=SHA((source/"native"/(owner+".hepta")).read_bytes()),profile
            if key in available:
                reuse[name]=str(available[key])
        (output/"reuse.json").write_text(json.dumps(reuse,sort_keys=True,indent=2)+"\n")
        manifest=build_runtime_mcp(a.hepta.resolve(),build,name="public-nine-constructor",
                                  source_root=source,manifests=reuse or None)
        raw=manifest.read_bytes();metadata=json.loads(raw)
        assert metadata["physical_images"]==80 and len(metadata["members"])==80
        fresh=sum(row["fresh_compile"] is True for row in metadata["members"])
        assert fresh==80-len(reuse)
        binary=manifest.parent/metadata["elf"]
        assert SHA(binary.read_bytes())==metadata["elf_sha256"]
        report.update(status="NATIVE_BUILD_PASS",manifest=str(manifest),manifest_sha256=SHA(raw),
            elf=str(binary),elf_sha256=metadata["elf_sha256"],elf_bytes=binary.stat().st_size,
            physical_images=80,fresh_member_compiles=fresh,checked_reused_members=len(reuse),
            fresh_hia_link_and_pack=True,bootstrap_reused=a.bootstrap is not None,
            target_text_constructor_integrated=True,target_general_response_owner_integrated=False)
    except BaseException as exc:
        report.update(status="FAIL",error=repr(exc))
        raise
    finally:
        report["elapsed_seconds"]=time.monotonic()-began
        save()
    print(json.dumps(report,sort_keys=True))


if __name__=="__main__":
    main()

