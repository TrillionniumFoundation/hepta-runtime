"""CI-only single-owner compilation and two fresh links with the exact retained B3."""
from pathlib import Path
import argparse,json,os,shutil,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from read_primitives import *
import callable_common,read_graph,read_successor,patch_source,read_only_guard as guard,restore_graph,wait_native_fixture
def put(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser()
    for name in ("output","retained","hepta"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();require(os.environ.get("GITHUB_ACTIONS")=="true","compiler execution only in CI")
    require(not a.output.exists(),"fresh successor build");a.output.mkdir(parents=True);out=a.output.resolve()
    require(callable_common.syntax(HERE)["status"]=="SOURCE_ONLY_PASS","complete frozen source")
    target=restore_graph.restore(a.retained)
    put(out/"RETAINED_ARCHIVE.json",doc(a.retained/"RESTORE.json"))
    shutil.copyfile(a.retained/"FILES.json",out/"RETAINED_FILES.json")
    read_graph.prepare(target) # Resolve read-only dependencies before capability guards.
    before_read=guard.guarded(lambda:read_graph.verify(target),roots=[target,HERE],foreign_path=Path("/dev/null"))
    put(out/"BEFORE_READ.json",before_read)
    native=target/"capture/native-build";graph=out/"source"
    patch_source.apply(target,graph)
    proof=patch_source.prove(target,graph,a.hepta)
    put(out/"SOURCE_AST.json",proof);print(json.dumps(proof,sort_keys=True),flush=True)
    builder=read_graph.prepare(target)[0]
    before,adapted,fixture_proof=wait_native_fixture.source(graph,builder)
    (out/"before.S").write_bytes(before);(out/"fixture.S").write_bytes(adapted)
    put(out/"FIXTURE_SOURCE.json",fixture_proof)
    put(out/"ORIGIN.json",{"schema":"hepta.runtime.extract-local-policy-successor-build.v1","retained":str(target),"source":str(graph),"output":str(out),"source_commit":doc(HERE/"PRODUCTION_ROWS.json")["commit"],"source_binding":pin(graph/"native/runtime_mcp_sources.json"),"fresh_direct_compiles":1,"reverified_reused_direct":114,"application_semantics_executed":0})
    reuse={name:str(native/"build-public/modules"/("publication-public-"+name.replace("_","-"))/"manifest.json") for name,_,_ in builder.MEMBERS if name!="extract_gateway"}
    original=builder.adapter_source
    report={"status":"RUNNING","fresh_direct_hia_compiles":1,"verified_reused_direct_hia_members":114,"roles":{},"application_semantics_executed":0}
    put(out/"BUILD.json",report)
    start=time.monotonic()
    try:
        for role in ("public","fixture"):
            require(time.monotonic()-start<900,"unchanged graph900 second budget")
            build=out/("build-"+role)
            shutil.copytree(native/"worker/build/bootstrap",build/"bootstrap")
            require(files(build/"bootstrap")==files(native/"worker/build/bootstrap"),"copied and reverified actual B3 only")
            if role=="fixture":
                reuse["extract_gateway"]=str(out/"build-public/modules/policy-public-extract-gateway/manifest.json")
                def fixture_source(root,**flags):
                    require(Path(root).resolve()==graph and flags=={"private_fixture":False,"private_pump_fixture":True,"private_pump_trace":True},"fixed explicit fixture mode")
                    require(original(root,**flags).encode()==before,"same production prefix")
                    return adapted.decode()
                builder.adapter_source=fixture_source
            manifest=builder.build_runtime_mcp(a.hepta.resolve(strict=True),build,name="policy-"+role,source_root=graph,manifests=reuse,private_pump_fixture=role=="fixture",private_pump_trace=role=="fixture",bellman_port_build=native/"port/build-v3",bellman_port_package=graph/"runtime_support/bellman_port",bellman_worker_build=native/"worker")
            m=doc(manifest);binary=manifest.parent/m["elf"]
            report["roles"][role]={"manifest":pin(manifest),"manifest_path":str(manifest),"binary":str(binary),"elf":pin(binary)}
            put(out/"BUILD.json",report)
        report.update(status="ONE_OWNER_SUCCESSOR123_BUILD_PASS",source=builder.source_check(graph),runtime_hia_images=123,physical_images=116,descriptor_slots=69,elapsed_seconds=time.monotonic()-start)
    except BaseException as error:
        report.update(status="FAIL",error=repr(error),traceback=traceback.format_exc());raise
    finally:
        builder.adapter_source=original;put(out/"BUILD.json",report)
    checked=guard.guarded(lambda:read_successor.verify(target,out),roots=[target,out,HERE],foreign_path=Path("/dev/null"))
    put(out/"AFTER_READ.json",checked)
    print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
