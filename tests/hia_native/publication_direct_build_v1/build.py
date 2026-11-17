#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""One new private fixture, 116 exact unchanged direct images, fresh GAS/HIA pack."""
from pathlib import Path
import argparse,json,os,shutil,sys,time,traceback
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import direct_common as c
def main():
    p=argparse.ArgumentParser()
    for n in ("recipe","previous","output","hepta"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();c.require(os.environ.get("GITHUB_ACTIONS")=="true","native build only in CI")
    modules,prepared=c.prepare(a.previous,a.recipe)
    identity,ac,restore,old,dynamic,guard,reader=modules
    import direct_compose
    c.require(not a.output.exists(),"fresh private direct build output");a.output.mkdir(parents=True)
    out=a.output.resolve();previous=a.previous.resolve()
    _,original,retained=prepared[0];native=retained/"capture/native-build";worker=native/"worker"
    shutil.copytree(previous/"source",out/"source")
    shutil.copytree(previous/"source-repair",out/"source-repair")
    shutil.copyfile(previous/"SOURCE_REPAIR_READ.json",out/"SOURCE_REPAIR_READ.json")
    graph=out/"source";ac.source_files(graph);builder,_,_=dynamic.load(graph)
    reuse={}
    for name,source,profile in builder.MEMBERS:
        module=("async-public-" if name in ac.FRESH else "publication-public-")+name.replace("_","-")
        folder=(original/"build-public/modules" if name in ac.FRESH else native/"build-public/modules")/module
        c.require(ac.raw(folder/(module+".hepta"))==ac.raw(graph/"native"/(source+".hepta")),"exact retained HIA image source")
        reuse[name]=str(folder/"manifest.json")
    c.require(len(reuse)==116,"116 unchanged HIA owners")
    c.put(out/"ORIGIN.json",dict(schema="hepta.runtime.publication-direct.build.v1",
        retained=str(retained),previous=str(original),predecessor=str(previous),source=str(graph),output=str(out),
        source_commit=ac.PRODUCTION,source_binding=ac.pin(graph/"native/runtime_mcp_sources.json"),
        recipe=identity,prior_archive=json.loads((HERE/"BUILD_INPUT.json").read_bytes()),
        fresh_direct=[],retained_direct=sorted(reuse),application_executions=0))
    c.put(out/"DIRECT.json",direct_compose.evidence())
    report=dict(status="RUNNING",fresh_direct_hia_compiles=0,verified_reused_direct_hia_members=116,
        application_semantics_executed=0,roles={});c.put(out/"BUILD.json",report);start=time.monotonic()
    build=out/"build-direct";shutil.copytree(worker/"build/bootstrap",build/"bootstrap")
    c.require(ac.files(build/"bootstrap")==ac.files(worker/"build/bootstrap"),"exact prior actual bootstrap")
    original_adapter=direct_compose.install(builder)
    try:
        manifest=builder.build_runtime_mcp(a.hepta.resolve(strict=True),build,name="async-direct",source_root=graph,
            manifests=reuse,private_fixture=False,private_pump_fixture=True,private_pump_trace=True,
            private_publication_trace=True,bellman_port_build=native/"port/build-v3",
            bellman_port_package=graph/"runtime_support/bellman_port",bellman_worker_build=worker)
        m=ac.doc(manifest);binary=manifest.parent/m["elf"]
        c.require(not any(r["fresh_compile"] for r in m["members"]),"all retained images classified exactly")
        report["roles"]["direct"]=dict(manifest=ac.pin(manifest),manifest_path=str(manifest),binary=str(binary),elf=ac.pin(binary))
        report.update(status="ACTUAL_PUBLICATION124_DIRECT_BUILD_PASS",source=builder.source_check(graph),
            runtime_hia_images=124,physical_images=117,descriptor_slots=69,elapsed_seconds=time.monotonic()-start)
    except BaseException as error:
        report.update(status="FAIL",error=repr(error),traceback=traceback.format_exc());raise
    finally:
        builder.adapter_source=original_adapter;c.put(out/"BUILD.json",report)
    print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
