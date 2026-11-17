"""CI-only fresh links with all115 exact retained HIA receipts and the copied actual B3."""
from pathlib import Path
import argparse,json,os,shutil,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from read_primitives import *
import callable_common,read_graph,read_successor,patch_source,read_only_guard as guard,wait_native_fixture
def put(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser()
    for name in ("output","inputs","hepta"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();require(os.environ.get("GITHUB_ACTIONS")=="true","HIA linker/packer execution only in CI")
    require(not a.output.exists(),"fresh successor build");a.output.mkdir(parents=True);out=a.output.resolve()
    require(callable_common.syntax(HERE)["status"]=="SOURCE_ONLY_PASS","complete frozen source")
    inputs=a.inputs.resolve(strict=True);target=inputs/"shared/retained";previous=inputs/"successor/capture"
    ready=doc(inputs/"NATIVE_READY.json");identity=doc(HERE/"INPUTS.json")["local_policy"]
    require(ready["status"]=="COMPLETE_UPLOADED_NATIVE_SUCCESSOR_READY" and ready["source_commit"]==identity["production_source"] and ready["build_source"]==identity["build_source"] and ready["build_artifact"]==identity["native_build"]["artifact"] and ready["original_executions"]==ready["native_executions"]==0,"separate complete guarded source/build admission")
    require({k:ready["native"][k] for k in ("bytes","sha256")}==identity["native_build"]["fixture"],"exact retained Local-repaired build")
    for name in ("NATIVE_READ_ONLY.json","BUILD_SOURCE.json","CAPTURE_SOURCE.json","BUILD_ARCHIVE_READ.json","NATIVE_READY.json"):
        shutil.copyfile(inputs/name,out/name)
    native=target/"capture/native-build";graph=out/"source"
    read_graph.prepare(target)
    patch_source.apply(previous,graph)
    proof=patch_source.prove(previous,graph);put(out/"SOURCE_PROOF.json",proof)
    builder=read_graph.prepare(target)[0]
    before,adapted,fixture_proof=wait_native_fixture.source(graph,builder)
    (out/"before.S").write_bytes(before);(out/"fixture.S").write_bytes(adapted)
    put(out/"FIXTURE_SOURCE.json",fixture_proof)
    put(out/"ORIGIN.json",{"schema":"hepta.runtime.extract-fence-successor-build.v1","retained":str(target),"input_successor":str(previous),"source":str(graph),"output":str(out),"source_commit":doc(HERE/"PRODUCTION_ROWS.json")["commit"],"source_binding":pin(graph/"native/runtime_mcp_sources.json"),"fresh_direct_compiles":0,"reverified_reused_direct":115,"application_semantics_executed":0})
    reuse={name:str(native/"build-public/modules"/("publication-public-"+name.replace("_","-"))/"manifest.json") for name,_,_ in builder.MEMBERS}
    reuse["extract_gateway"]=str(previous/"build-public/modules/policy-public-extract-gateway/manifest.json")
    original=builder.adapter_source
    report={"status":"RUNNING","fresh_direct_hia_compiles":0,"verified_reused_direct_hia_members":115,"roles":{},"application_semantics_executed":0}
    put(out/"BUILD.json",report);start=time.monotonic()
    try:
        for role in ("public","fixture"):
            require(time.monotonic()-start<900,"unchanged graph900 second budget")
            build=out/("build-"+role)
            shutil.copytree(native/"worker/build/bootstrap",build/"bootstrap")
            require(files(build/"bootstrap")==files(native/"worker/build/bootstrap"),"copied and reverified actual B3 only")
            if role=="fixture":
                def fixture_source(root,**flags):
                    require(Path(root).resolve()==graph and flags=={"private_fixture":False,"private_pump_fixture":True,"private_pump_trace":True},"fixed explicit fixture mode")
                    require(original(root,**flags).encode()==before,"same production prefix")
                    return adapted.decode()
                builder.adapter_source=fixture_source
            manifest=builder.build_runtime_mcp(a.hepta.resolve(strict=True),build,name="fence-"+role,source_root=graph,manifests=reuse,private_pump_fixture=role=="fixture",private_pump_trace=role=="fixture",bellman_port_build=native/"port/build-v3",bellman_port_package=graph/"runtime_support/bellman_port",bellman_worker_build=native/"worker")
            m=doc(manifest);binary=manifest.parent/m["elf"]
            report["roles"][role]={"manifest":pin(manifest),"manifest_path":str(manifest),"binary":str(binary),"elf":pin(binary)}
            put(out/"BUILD.json",report)
        report.update(status="RETAINED115_FENCE_SUCCESSOR123_BUILD_PASS",source=builder.source_check(graph),runtime_hia_images=123,physical_images=116,descriptor_slots=69,elapsed_seconds=time.monotonic()-start)
    except BaseException as error:
        report.update(status="FAIL",error=repr(error),traceback=traceback.format_exc());raise
    finally:
        builder.adapter_source=original;put(out/"BUILD.json",report)
    checked=guard.guarded(lambda:read_successor.verify(target,previous,out),roots=[target,previous,out,HERE],foreign_path=Path("/dev/null"))
    put(out/"AFTER_READ.json",checked);print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
