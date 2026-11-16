"""CI-only mechanical timing pack; all 111 HIA sources/images stay exact."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys

def pin(path):
    with path.open("rb") as f:sha=hashlib.file_digest(f,"sha256").hexdigest()
    return {"bytes":path.stat().st_size,"sha256":sha}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("source","package","build","failure","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);package=a.package.resolve(strict=True)
    build=a.build.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.resolve()
    assert os.environ.get("GITHUB_ACTIONS")=="true" and not out.exists()
    declared=json.loads((source/"SOURCE.json").read_bytes())
    actual={q.relative_to(source).as_posix():pin(q) for q in sorted(source.rglob("*")) if q.is_file() and q.name!="SOURCE.json"}
    assert actual==declared["files"]
    corpus=json.loads((source/"CORPUS.json").read_bytes());out.mkdir(parents=True)
    sys.path.insert(0,str(package/"ci"));from common import command,put
    py=[sys.executable,"-I","-S","-B"]
    command(out,"recover-exact-corpus",py+[str(source/"recover_corpus.py"),"--source",str(source),"--failure",str(a.failure.resolve(strict=True)),"--output",str(out/"inputs")])
    command(out,"read-original-complete-build",py+[str(package/"ci/read_build.py"),"--package",str(package),"--build",str(build),"--manifest-sha256",corpus["base_package_sha256"]])
    put(out/"ORIGIN.json",{"diagnostic_source":pin(source/"SOURCE.json"),"corpus":pin(source/"CORPUS.json"),
        "base_build_archive":corpus["build_artifact"],"head":os.environ["GITHUB_SHA"],"run_id":os.environ["GITHUB_RUN_ID"],
        "all_hia_and_packed_port_bytes_unchanged":True,"full_public_domain_qualified":False})
    generated=out/"profile-source"
    command(out,"author-fixed-observations",py+[str(source/"author_engine_profile.py"),"--source",str(package/"graph/source"),"--output",str(generated)])
    production=json.loads((build/"production/build/public-task-batch/manifest.json").read_bytes())
    members={r["name"]:str(build/"production/build/modules"/("public-task-batch-"+r["name"].replace("_","-"))/"manifest.json") for r in production["members"]}
    assert len(members)==103;put(out/"same-ci-members.json",members)
    target=out/"build";target.mkdir();shutil.copytree(build/"production/worker/build/bootstrap",target/"bootstrap")
    command(out,"pack-fixed-profile",py+[str(generated/"scripts/public_nine_build.py"),"--hepta",str(hepta),"--build",str(target),"--name","profile",
        "--bellman-port-build",str(build/"production/port/build-v3"),"--bellman-port-package",str(generated/"runtime_support/bellman_port"),
        "--bellman-worker-build",str(build/"production/worker"),"--member-manifests-json",str(out/"same-ci-members.json"),"--private-pump-fixture","--private-pump-trace"])
    manifest=target/"profile/manifest.json";m=json.loads(manifest.read_bytes())
    assert len(m["members"])==103 and all(r["fresh_compile"] is False for r in m["members"])
    fields=("name","source","source_sha256","manifest_sha256","image_sha256","image_bytes","buffer_profile")
    assert [{k:r[k] for k in fields} for r in production["members"]]==[{k:r[k] for k in fields} for r in m["members"]]
    assert m["packed_capabilities"]["57"]["elf_sha256"]==production["packed_capabilities"]["57"]["elf_sha256"]
    binary=target/"profile"/m["elf"];assert pin(binary)=={"bytes":m["elf_bytes"],"sha256":m["elf_sha256"]}
    reports=[]
    for row in corpus["rows"]:
        name=row["name"];capture=out/name
        command(out,"observe-"+name,py+[str(source/"observe.py"),"--binary",str(binary),"--elf-sha256",m["elf_sha256"],"--input",str(out/"inputs"/(name+".stdin")),"--output",str(capture),"--trace"])
        command(out,"read-"+name,py+[str(source/"read_profile.py"),"--source",str(source),"--inputs",str(out/"inputs"),"--capture",str(capture),"--manifest",str(manifest),"--name",name])
        reports.append(json.loads((out/"processes"/("read-"+name+".stdout")).read_bytes()))
    result={"status":"THREE_ENGINEERING_REQUESTS_PROFILED","cases":len(reports),"hia_images_changed":0,"direct_leaf_recompiles":0,
        "mechanical_profile_repacked":True,"all_three_complete_wire_preserved":True,"reports":reports,
        "whole_1394_or_async_qualified":False,"per_process_seconds":60,"original_1394_process_seconds":180}
    put(out/"PROFILE.json",result);print(json.dumps(result,sort_keys=True))

if __name__=="__main__":main()
