"""CI-only new fixed test entry; every inherited HIA body is reverified then reused."""
from pathlib import Path
import argparse,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from read_primitives import *
import callable_common,read_graph,read_only_guard as guard,restore_graph,wait_native_fixture
HERE=Path(__file__).resolve().parent
def put(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser()
    for name in ("output","retained","hepta"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();require(os.environ.get("GITHUB_ACTIONS")=="true","compiler execution only in CI")
    require(not a.output.exists(),"fresh fixed fixture build");a.output.mkdir(parents=True);out=a.output.resolve()
    require(callable_common.syntax(HERE)["status"]=="SOURCE_ONLY_PASS","complete frozen author source")
    target=restore_graph.restore(a.retained)
    put(out/"RETAINED_ARCHIVE.json",doc(a.retained/"RESTORE.json"))
    shutil.copyfile(a.retained/"FILES.json",out/"RETAINED_FILES.json")
    graph=target/"capture/composition/source";native=target/"capture/native-build"
    modules=read_graph.prepare(target);builder=modules[0]
    before_read=guard.guarded(lambda:read_graph.verify(target),roots=[target,HERE],foreign_path=Path("/dev/null"))
    put(out/"BEFORE_READ.json",before_read)
    before,adapted,proof=wait_native_fixture.source(graph,builder)
    (out/"before.S").write_bytes(before);(out/"fixture.S").write_bytes(adapted);put(out/"FIXTURE_SOURCE.json",proof)
    put(out/"ORIGIN.json",{"schema":"hepta.runtime.shared123.actual-wait-fixture-origin.v1","retained":str(target),"source":str(graph),"build":str(out/"build"),"fixture_package":str(HERE),"hepta":str(a.hepta.resolve(strict=True)),"source_commit":"e5d701339c16c4b1bd1801252d2357721452687c","source_binding":doc(HERE/"SOURCE_INDEX.json")["binding"],"fresh_link_and_pack_only":True,"application_semantics_executed":0})
    shutil.copytree(native/"worker/build/bootstrap",out/"build/bootstrap")
    require(files(out/"build/bootstrap")==files(native/"worker/build/bootstrap"),"complete copied actual B3")
    reuse={name:str(native/"build-public/modules"/("publication-public-"+name.replace("_","-"))/"manifest.json") for name,_,_ in builder.MEMBERS}
    original=builder.adapter_source
    def fixture_source(root,**flags):
        require(Path(root).resolve()==graph and flags=={"private_fixture":False,"private_pump_fixture":True,"private_pump_trace":True},"fixed explicit fixture mode")
        require(original(root,**flags).encode()==before,"production prefix unchanged")
        return adapted.decode()
    builder.adapter_source=fixture_source
    report={"status":"RUNNING","production_source_changed":False,"fresh_direct_hia_compiles":0,"verified_reused_direct_hia_members":115,"fresh_link_and_pack":True,"application_semantics_executed":0}
    put(out/"BUILD.json",report)
    try:
        manifest=builder.build_runtime_mcp(a.hepta.resolve(strict=True),out/"build",name="wait-control",source_root=graph,manifests=reuse,private_pump_fixture=True,private_pump_trace=True,bellman_port_build=native/"port/build-v3",bellman_port_package=graph/"runtime_support/bellman_port",bellman_worker_build=native/"worker")
        m=doc(manifest);report.update(status="SHARED123_TEST_WAIT_FIXTURE_BUILD_PASS",manifest=pin(manifest),elf=pin(manifest.parent/m["elf"]),runtime_hia_images=123,physical_images=116,descriptor_slots=69)
    except BaseException as error:
        report.update(status="FAIL",error=repr(error),traceback=traceback.format_exc());raise
    finally:
        builder.adapter_source=original;put(out/"BUILD.json",report)
    checked=guard.guarded(lambda:read_graph.verify(target,out),roots=[target,out,HERE],foreign_path=Path("/dev/null"))
    put(out/"AFTER_READ.json",checked)
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
