#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual four-entry linker/packer, all116 unchanged HIA receipts verified."""
from pathlib import Path
import argparse,os,shutil,sys,time,traceback
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from async_build_common import *
import restore_full,read_graph,previous_reader,dynamic_builder,read_all,duplex_boundary,read_only_guard as guard
def main():
    p=argparse.ArgumentParser()
    for name in ("source","output","downloads","hepta"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();require(os.environ.get("GITHUB_ACTIONS")=="true","actual build only in CI")
    identity=package();source_files(a.source,complete=False)
    require(not a.output.exists(),"fresh build");a.output.mkdir(parents=True);out=a.output.resolve()
    restored,archive=restore_full.restore(a.downloads,doc(HERE/"PREVIOUS_INPUT.json"))
    restored.rename(out/"prior");predecessor=out/"prior/capture"
    (out/"prior-read").mkdir()
    for name in ("READ.json","ARCHIVE.json","FILES.json"):shutil.copyfile(a.downloads/name,out/"prior-read"/name)
    old=previous_reader.prepare(predecessor);_,original,retained=old
    before=guard.guarded(lambda:previous_reader.verify(predecessor,old),roots=[out,HERE.parent],foreign_path=Path("/dev/null"))
    put(out/"PREVIOUS_READ.json",before)
    graph=out/"source";graph.mkdir()
    for r in doc(HERE/"PRODUCTION_ROWS.json")["rows"]:
        q=graph/r["path"];q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(a.source/r["path"],q);q.chmod(0o644)
    source_files(graph)
    for path,expected in doc(predecessor/"source/native/runtime_mcp_sources.json")["sources"].items():
        if path in {"scripts/runtime_mcp_task_storage.S","scripts/runtime_mcp_task_teardown.S"}:continue
        require(pin(graph/path)==expected,"every other original production byte unchanged: "+path)
    native=retained/"capture/native-build";worker=native/"worker"
    builder,_,_=dynamic_builder.load(graph);require(len(builder.MEMBERS)==116,"actual graph")
    reuse={}
    for name,source,profile in builder.MEMBERS:
        module=("async-public-" if name in FRESH else "publication-public-")+name.replace("_","-")
        folder=(original/"build-public/modules" if name in FRESH else native/"build-public/modules")/module
        require(raw(folder/(module+".hepta"))==raw(graph/"native"/(source+".hepta")),"all actual HIA unchanged")
        reuse[name]=str(folder/"manifest.json")
    require(len(reuse)==116,"all direct receipts")
    put(out/"ORIGIN.json",dict(schema="hepta.runtime.publication-duplex.build.v1",
        retained=str(retained),previous=str(original),predecessor=str(predecessor),
        source=str(graph),output=str(out),source_commit=PRODUCTION,
        source_binding=pin(graph/"native/runtime_mcp_sources.json"),recipe=identity,prior_archive=archive,
        fresh_direct=[],retained_direct=sorted(reuse),application_executions=0))
    put(out/"DUPLEX.json",duplex_boundary.evidence())
    report=dict(status="RUNNING",fresh_direct_hia_compiles=0,verified_reused_direct_hia_members=116,
        application_semantics_executed=0,roles={});put(out/"BUILD.json",report);start=time.monotonic()
    original_adapter=builder.adapter_source
    try:
        for role in ("public","publisher","filesystem","duplex"):
            require(time.monotonic()-start<900,"original build900s")
            build=out/("build-"+role);shutil.copytree(worker/"build/bootstrap",build/"bootstrap")
            require(files(build/"bootstrap")==files(worker/"build/bootstrap"),"exact actual B3")
            observed=role in ("publisher","duplex");instance=role=="filesystem"
            if role=="duplex":duplex_boundary.install(builder)
            try:
                manifest=builder.build_runtime_mcp(a.hepta.resolve(strict=True),build,
                    name="async-"+role,source_root=graph,manifests=reuse,private_fixture=instance,
                    private_pump_fixture=observed,private_pump_trace=observed,private_publication_trace=observed,
                    bellman_port_build=native/"port/build-v3",bellman_port_package=graph/"runtime_support/bellman_port",
                    bellman_worker_build=worker)
            finally:builder.adapter_source=original_adapter
            m=doc(manifest);binary=manifest.parent/m["elf"]
            require(not any(r["fresh_compile"] for r in m["members"]),"no reclassified fresh images")
            report["roles"][role]=dict(manifest=pin(manifest),manifest_path=str(manifest),binary=str(binary),elf=pin(binary))
            put(out/"BUILD.json",report)
        report.update(status="ACTUAL_PUBLICATION124_TWO_SESSION_BUILD_PASS",source=builder.source_check(graph),
            runtime_hia_images=124,physical_images=117,descriptor_slots=69,elapsed_seconds=time.monotonic()-start)
    except BaseException as error:
        report.update(status="FAIL",error=repr(error),traceback=traceback.format_exc());raise
    finally:put(out/"BUILD.json",report)
    result=read_all.checked(out);put(out/"AFTER_READ.json",result)
    print(__import__("json").dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
