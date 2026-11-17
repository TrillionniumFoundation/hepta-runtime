#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""CI-only real new HIA compiles and exact retained member graph assembly."""
from pathlib import Path
import argparse,os,shutil,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from async_build_common import *
import read_graph,read_only_guard as guard,restore_graph,dynamic_builder,read_build
def main():
    p=argparse.ArgumentParser()
    for name in ("source","output","downloads","hepta"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();require(os.environ.get("GITHUB_ACTIONS")=="true","actual HIA build is CI-only")
    package_identity=package();source_files(a.source,complete=False)
    require(not a.output.exists(),"fresh complete build result");a.output.mkdir(parents=True);out=a.output.resolve()
    graph=out/"source";graph.mkdir()
    for r in doc(HERE/"PRODUCTION_ROWS.json")["rows"]:
        q=graph/r["path"];q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(a.source/r["path"],q);q.chmod(0o644)
    source_files(graph)
    retained=restore_graph.restore(a.downloads)
    retained.rename(out/"retained");retained=out/"retained"
    for name in ("RESTORE.json","ARCHIVE.json","FILES.json"):shutil.copyfile(a.downloads/name,out/("RETAINED_"+name))
    read_graph.prepare(retained)
    before=guard.guarded(lambda:read_graph.verify(retained),roots=[retained,HERE],foreign_path=Path("/dev/null"))
    put(out/"RETAINED_READ.json",before)
    native=retained/"capture/native-build";worker=native/"worker"
    builder,_,_=dynamic_builder.load(graph)
    require(len(builder.MEMBERS)==116 and set(FRESH)<={x[0] for x in builder.MEMBERS},"exact actual direct source list")
    reuse={}
    for name,source,profile in builder.MEMBERS:
        if name in FRESH:continue
        module="publication-public-"+name.replace("_","-")
        folder=native/"build-public/modules"/module
        require(raw(folder/(module+".hepta"))==raw(graph/"native"/(source+".hepta")),"unchanged retained owner input")
        reuse[name]=str(folder/"manifest.json")
    require(len(reuse)==112,"exact retained direct count")
    origin=dict(schema="hepta.runtime.publication-worker.public-build.v1",retained=str(retained),source=str(graph),output=str(out),
        source_commit=PRODUCTION,source_binding=pin(graph/"native/runtime_mcp_sources.json"),recipe=package_identity,
        fresh_direct=sorted(FRESH),retained_direct=sorted(reuse),application_executions=0)
    put(out/"ORIGIN.json",origin)
    report=dict(status="RUNNING",fresh_direct_hia_compiles=4,verified_reused_direct_hia_members=112,
        application_semantics_executed=0,roles={})
    put(out/"BUILD.json",report);start=time.monotonic()
    try:
        for role in ("public","publisher","filesystem"):
            require(time.monotonic()-start<900,"existing graph900 second limit")
            build=out/("build-"+role);shutil.copytree(worker/"build/bootstrap",build/"bootstrap")
            require(files(build/"bootstrap")==files(worker/"build/bootstrap"),"copied exact actual B3")
            observed=role=="publisher";instance=role=="filesystem"
            manifest=builder.build_runtime_mcp(a.hepta.resolve(strict=True),build,name="async-"+role,source_root=graph,
                manifests=reuse,private_fixture=instance,private_pump_fixture=observed,private_pump_trace=observed,
                private_publication_trace=observed,bellman_port_build=native/"port/build-v3",
                bellman_port_package=graph/"runtime_support/bellman_port",bellman_worker_build=worker)
            m=doc(manifest);binary=manifest.parent/m["elf"]
            report["roles"][role]=dict(manifest=pin(manifest),manifest_path=str(manifest),binary=str(binary),elf=pin(binary))
            if role=="public":
                require({r["name"] for r in m["members"] if r["fresh_compile"]}==FRESH,"actual new compile classification")
                reuse={r["name"]:r["manifest"] for r in m["members"]}
            else:require(not any(r["fresh_compile"] for r in m["members"]),"same-CI role members")
            put(out/"BUILD.json",report)
        report.update(status="ACTUAL_PUBLICATION_WORKER124_BUILD_PASS",source=builder.source_check(graph),
            runtime_hia_images=124,physical_images=117,descriptor_slots=69,elapsed_seconds=time.monotonic()-start)
    except BaseException as error:
        report.update(status="FAIL",error=repr(error),traceback=traceback.format_exc());raise
    finally:put(out/"BUILD.json",report)
    checked=guard.guarded(lambda:read_build.verify(retained,out),roots=[out,HERE],foreign_path=Path("/dev/null"))
    put(out/"AFTER_READ.json",checked)
    print(__import__("json").dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
