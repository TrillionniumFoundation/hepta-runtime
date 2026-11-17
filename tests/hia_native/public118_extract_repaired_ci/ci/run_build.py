"""Build the actual installed public118 default and three fixed observation entries."""
from pathlib import Path
import argparse,json,os,shutil,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import command,pin,put,require
from source_check import source,installed_source
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("package","installed-source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--manifest-sha256",required=True);a=p.parse_args()
    package=a.package.resolve(strict=True);graph=a.installed_source.resolve(strict=True)
    hepta=a.hepta.resolve(strict=True);out=a.output.resolve()
    require(os.environ.get("GITHUB_ACTIONS")=="true","fresh public118 composition is CI-only")
    require(not out.exists(),"fresh build output already exists")
    admitted=source(package,a.manifest_sha256,syntax=True);before=installed_source(package,graph)
    out.mkdir(parents=True)
    origin={"package":str(package),"installed_source":str(graph),"hepta":str(hepta),"output":str(out),
        "manifest_sha256":a.manifest_sha256,"source_admission":admitted,"pid":os.getpid(),
        "git_head":os.environ.get("GITHUB_SHA"),"run_id":os.environ.get("GITHUB_RUN_ID"),
        "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT"),"fresh_direct_members":110,"packed_hia_members":8,
        "same_ci_member_reuse_entries":["journal","trace","instances"],"actual_default_entry":True}
    put(out/"BUILD_ORIGIN.json",origin)
    py=[sys.executable,"-I","-S","-B"]
    command(out,"source-reproduction",py+[str(package/"ci/reproduce_source.py"),
        "--package",str(package),"--hepta",str(hepta),"--output",str(out/"source-reproduction")])
    command(out,"shape-source-proof",py+[str(package/"ci/author_shape_admission.py"),
        "--package",str(package),"--hepta",str(hepta)])
    command(out,"main-default-entry",py+[str(graph/"scripts/hia_native_runtime_mcp_build.py"),
        "--source",str(graph),"--hepta",str(hepta),"--output",str(out/"production")])
    result=json.loads((out/"production/BUILD.json").read_bytes())
    require(result["status"]=="NATIVE_BUILD_PASS" and result["fresh_member_compiles"]==110
        and result["checked_reused_members"]==0 and result["runtime_hia_images"]==118
        and result["fresh_packed_member_compiles"]==8 and result["bootstrap_reused"] is False
        and result["default_public_entrypoint"] is True,"actual default build did not complete freshly")
    production=out/"production/build/public-task-batch-extract/manifest.json"
    md=json.loads(production.read_bytes())
    require(Path(result["manifest"])==production and len(md["members"])==110
        and all(r["fresh_compile"] is True for r in md["members"]),"actual default direct member ownership")
    put(out/"same-ci-members.json",{r["name"]:r["manifest"] for r in md["members"]})
    for label in ("journal","trace","instances"):
        directory=out/label;directory.mkdir()
        shutil.copytree(out/"production/worker/build/bootstrap",directory/"bootstrap")
        argv=py+[str(graph/"scripts/public_nine_build.py"),"--hepta",str(hepta),
            "--build",str(directory),"--name","task-pump",
            "--bellman-port-build",str(out/"production/port/build-v3"),
            "--bellman-port-package",str(graph/"runtime_support/bellman_port"),
            "--bellman-worker-build",str(out/"production/worker"),
            "--member-manifests-json",str(out/"same-ci-members.json")]
        argv += ["--private-filesystem-fixture"] if label=="instances" else ["--private-pump-fixture"]
        if label=="trace":argv.append("--private-pump-trace")
        command(out,"build-"+label,argv)
        child=json.loads((directory/"task-pump/manifest.json").read_bytes())
        require(len(child["members"])==110 and all(r["fresh_compile"] is False for r in child["members"]),
                "only same-CI direct members may be reused")
    after=installed_source(package,graph);require(after==before,"actual installed source changed")
    put(out/"INSTALLED_SOURCE_UNCHANGED.json",{"root":str(graph),"before":before,"after":after,
        "default_entry":str(graph/"scripts/hia_native_runtime_mcp_build.py"),"source_mutated":False})
    command(out,"shape-admission-controls",py+[str(package/"ci/shape_admission_controls.py"),
        "--package",str(package),"--build",str(out)])
    command(out,"read-build",py+[str(package/"ci/read_build.py"),"--package",str(package),
        "--build",str(out),"--manifest-sha256",a.manifest_sha256])
    report=json.loads((out/"processes/read-build.stdout").read_bytes())
    require(report["status"]=="FRESH_PUMP_GRAPH_BUILD_READBACK_PASS","complete graph reader did not pass")
    put(out/"BUILD_PASS.json",{"status":"FRESH_PUMP_GRAPH_BUILD_READBACK_PASS",
        "reader_stdout":pin(out/"processes/read-build.stdout"),"source_manifest_sha256":a.manifest_sha256,
        "runtime_hia_images":118,"direct_fresh_members":110,"packed_hia_members":8,
        "actual_default_entry":True,"public_semantic_qualification":False,
        "async_qualification":False,"fresh_cold_qualified":False})
    command(out,"physical-controls",py+[str(package/"ci/build_controls.py"),
        "--package",str(package),"--build",str(out),"--manifest-sha256",a.manifest_sha256])
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
