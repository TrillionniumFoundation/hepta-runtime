"""Guarded read of one unchanged completed application artifact using a separately frozen reader."""
import argparse,gzip,json,os,sys,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,loads,read,encoded,pin,require,files
from read_actual import verify
from read_only_guard import guarded
from export import directories
def read_all(workspace):
    identity=source();row=loads(read(ROOT/"RECOVERY_DEPENDENCY.json"));old=workspace/"retained"
    manifest=loads(read(workspace/"prior/artifact-manifest.json"))
    require(files(old)=={k:{x:v[x]for x in("bytes","sha256","mode")}for k,v in manifest["files"].items()},
        "unchanged completed archive whole files")
    ds=directories(old);ds.pop(".");require(ds==manifest["directories"],"unchanged completed archive whole directories and modes")
    original=loads(read(old/"source/SOURCE_MANIFEST.json"))
    changed={"read_trace.py","read_buffers.py","read_group.py","read_actual.py"}
    for entry in original["files"]:
        if entry["path"]not in changed:require(read(ROOT/entry["path"])==read(old/"source"/entry["path"]),"every unchanged original production, fixture and source reader byte")
    result=verify(old,row["group"],row)
    require(source()==identity and source(old/"source")==row["source_manifest_sha256"],"both full source identities remain unchanged")
    return dict(result,recovery_source_manifest_sha256=identity,original_archive=row["artifact"],
        old_failure_preserved=True,completed_application_replays=0)
def run(workspace):
    started=time.monotonic();result=guarded(lambda:read_all(workspace),roots=[workspace],
        foreign_path="/tmp/namespace-versions-recovery-forbidden/CAPTURE.json")
    require(time.monotonic()-started<=180,"complete guarded actual recovery deadline")
    (workspace/"run/RECOVERED-GUARDED.json").write_bytes(encoded(result));e=result["evidence"]
    summary=dict(schema="hepta.namespace-versions.actual-recovered-gate.v1",status="NAMESPACE_VERSIONS_ACTUAL_RECOVERED_GROUP_PASS",
        group=e["group"],source_manifest_sha256=e["recovery_source_manifest_sha256"],actual_source_manifest_sha256=e["source_manifest_sha256"],
        source_operations=e["source_operations"],parallel_calls=e["parallel_calls"],old_original_processes=e["original_processes"],
        old_native_processes=e["native_processes"],original_binary=e["original_binary"],native_image=e["native_image"],
        kernel_comparison=e["kernel_comparison"],complete_native_records=sum(x["records"]for x in e["native"]),
        complete_native_logical_bytes=sum(x["logical_bytes"]for x in e["native"]),
        complete_native_object_bytes=sum(x["complete_object_bytes"]for x in e["native"]),
        native_entry_calls=sum(len(x["entries"])for x in e["native"]),actual_atomic_attempts=sum(len(x["actual_cas"])for x in e["native"]),
        actual_child_lifecycle_records=sum(len(x["child_lifecycle"])for x in e["native"]),
        actual_native_read_joins=sum(len(x["native_read_joins"])for x in e["traces"]),
        complete_kernel_physical_checks=sum(len(x["kernel_physical"])for x in e["native"]),
        whole_kernel_payload_bytes=sum(x["whole_kernel_payload_bytes"]for x in e["traces"]),
        guard_probes=len(result["probes"]),whole_filesystem_entries=len(result["before"]),elapsed_seconds=time.monotonic()-started,
        application_replays=0,new_native_executions=0,new_original_executions=0,old_failure_preserved=True,
        namespace_version_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    (workspace/"run/GATE.json").write_bytes(encoded(summary))
    print("NAMESPACE_ACTUAL_RECOVERY_BEGIN");print(encoded(summary).decode(),end="");print("NAMESPACE_ACTUAL_RECOVERY_END")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);a=p.parse_args();run(a.workspace.resolve(strict=True))
