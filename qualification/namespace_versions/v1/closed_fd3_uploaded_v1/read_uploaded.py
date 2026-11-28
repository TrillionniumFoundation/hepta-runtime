"""Read all uploaded original/native source, memory, syscall and lifecycle bytes under twelve strict guards."""
import argparse,gzip,json,os,sys,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,loads,read,encoded,pin,require,files
from read_completed import verify
from read_only_guard import guarded
from export import directories
def read_all(workspace,group):
    identity=source();row=loads(read(ROOT/"UPLOAD_DEPENDENCIES.json"))["groups"][group];old=workspace/"retained"
    manifest=loads(read(workspace/"prior/artifact-manifest.json"))
    require(files(old)=={k:{x:v[x]for x in("bytes","sha256","mode")}for k,v in manifest["files"].items()},
        "every uploaded actual file remains byte and mode identical")
    ds=directories(old);ds.pop(".");require(ds==manifest["directories"],"all actual directory identities and modes are retained")
    original=loads(read(old/"source/SOURCE_MANIFEST.json"))
    for entry in original["files"]:
        require(read(ROOT/entry["path"])==read(old/"source"/entry["path"]),
            "every original production, fixture, domain and original reader byte remains exactly frozen")
    result=verify(old,group,row)
    require(source()==identity and source(old/"source")==row["source_manifest_sha256"],"both complete source freezes remain exact")
    return dict(result,uploaded_reader_source_manifest_sha256=identity,original_archive=row["artifact"],
        whole_uploaded_source_files_directories_modes_reread=True,files_deleted=0)
def run(workspace,group):
    started=time.monotonic();result=guarded(lambda:read_all(workspace,group),roots=[workspace],
        foreign_path="/tmp/namespace-uploaded-reader-forbidden/CAPTURE.json")
    require(time.monotonic()-started<=180,"complete uploaded reader deadline")
    (workspace/"run/UPLOADED-GUARDED.json").write_bytes(encoded(result));e=result["evidence"]
    summary=dict(schema="hepta.namespace-versions.uploaded-group-gate.v1",status="NAMESPACE_VERSIONS_UPLOADED_GROUP_PASS",
        group=e["group"],source_manifest_sha256=e["uploaded_reader_source_manifest_sha256"],actual_source_manifest_sha256=e["source_manifest_sha256"],
        source_operations=e["source_operations"],parallel_calls=e["parallel_calls"],old_original_processes=e["original_processes"],
        old_native_processes=e["native_processes"],original_binary=e["original_binary"],native_image=e["native_image"],
        kernel_comparison=e["kernel_comparison"],complete_native_records=sum(x["records"]for x in e["native"]),
        complete_native_logical_bytes=sum(x["logical_bytes"]for x in e["native"]),
        complete_native_object_bytes=sum(x["complete_object_bytes"]for x in e["native"]),
        native_entry_calls=sum(len(x["entries"])for x in e["native"]),actual_atomic_attempts=sum(len(x["actual_cas"])for x in e["native"]),
        actual_child_lifecycle_records=sum(len(x["child_lifecycle"])for x in e["native"]),
        actual_native_read_joins=sum(len(x["native_read_joins"])for x in e["traces"]),
        closed_standard_descriptor_lifetimes=sum(len(x.get("fd_floor_results",[]))for x in e["native"]),
        direct_watcher_entry_calls=sum(sum(v["entries"]for v in x.get("fd_floor_results",[]))for x in e["native"]),
        complete_kernel_physical_checks=sum(len(x["kernel_physical"])for x in e["native"]),
        whole_kernel_payload_bytes=sum(x["whole_kernel_payload_bytes"]for x in e["traces"]),
        guard_probes=len(result["probes"]),whole_filesystem_entries=len(result["before"]),elapsed_seconds=time.monotonic()-started,
        application_replays=0,new_native_executions=0,new_original_executions=0,
        namespace_version_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    (workspace/"run/GATE.json").write_bytes(encoded(summary))
    print("NAMESPACE_UPLOADED_GATE_BEGIN");print(encoded(summary).decode(),end="");print("NAMESPACE_UPLOADED_GATE_END")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);p.add_argument("--group",required=True)
    a=p.parse_args();run(a.workspace.resolve(strict=True),a.group)
