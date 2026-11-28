"""Complete guarded actual-group reader; no native mapping, application, replay or mutation."""
import argparse,gzip,json,os,sys,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,loads,read,encoded,require,pin
from source_check import verify as check_source
from read_group import verify as group_read
from read_only_guard import guarded
def verify(workspace,group,prior_failure=None):
    checked=check_source();identity=source(workspace/"source");run=workspace/"run";retained=workspace/"retained"
    if prior_failure is None:require(identity==checked["source_manifest_sha256"],"same frozen live reader source")
    else:require(identity==prior_failure["source_manifest_sha256"]and group==prior_failure["group"],"exact unchanged prior application source")
    admission=loads(read(retained/"ADMISSION.json"));meta=loads(read(run/"RUN.json"));processes=loads(read(run/"processes/processes.json"))
    require(admission["status"]=="PASS"and admission["source_manifest_sha256"]==identity
        and admission["native_application_calls"]==admission["original_application_calls"]==0,"whole pre-application independent build admission")
    require(meta["schema"]=="hepta.namespace-versions.actual-run.v1"and meta["status"]in(("RUNNING","PASS")if prior_failure is None else("FAIL",))and meta["group"]==group
        and meta["source_manifest_sha256"]==identity and meta["application_replays"]==0,"exact source-bound actual run before final reader")
    names=["source","restore","read-native","read-original","strace-version","application"]
    if meta["status"]in("PASS","FAIL"):names.append("read")
    require([p["name"]for p in processes]==names,"complete actual original/native build readers and one source group")
    for p in processes:
        require(p["completed"]and not p["timed_out"]and p["exit_code"]==(1 if prior_failure is not None and p["name"]=="read"else 0)and p["pid"]==p["pgid"]
            and p["parent_pid"]==meta["pid"]and p["elapsed_seconds"]<=p["timeout_seconds"]and p["stdin"]is None,
            "every actual prior process completed once within owned deadline")
        require(p["timeout_seconds"]==(60 if p["name"]in("source","strace-version","application")else 180),"source-frozen execution deadline")
        for name in("stdout","stderr"):require(p[name]==dict(file=p["name"]+"."+name,**pin(read(run/"processes"/p[name]["file"]))),
            "all actual prior process bytes")
    if prior_failure is not None:
        require(meta["exception"]=="RuntimeError('recorded command failed: read')"and
            b"ValueError: every actual kernel read byte retained" in read(run/"processes/read.stderr"),
            "the exact old failed pure reader remains unchanged")
    expected=meta["commands"]
    require(len(expected)==7 and all(all(p[k]==expected[i][k]for k in("name","argv","cwd","timeout_seconds"))for i,p in enumerate(processes)),
        "all frozen commands join actual process custody")
    result=group_read(run/"group",group,identity)
    require(result["original_processes"]==1 and result["native_processes"]==2,"exact new application counts")
    return dict(result,source_check=checked,build_admission=pin(read(retained/"ADMISSION.json")),processes=processes)
def run(workspace,group,output):
    started=time.monotonic();result=guarded(lambda:verify(workspace,group),roots=[workspace],
        foreign_path="/tmp/namespace-versions-actual-forbidden/CAPTURE.json")
    require(time.monotonic()-started<=180,"complete independent group read deadline")
    output.write_bytes(encoded(result));e=result["evidence"]
    summary=dict(status=e["status"],group=group,source_manifest_sha256=e["source_manifest_sha256"],
        source_operations=e["source_operations"],parallel_calls=e["parallel_calls"],original_processes=e["original_processes"],
        native_processes=e["native_processes"],original_binary=e["original_binary"],native_image=e["native_image"],
        kernel_comparison=e["kernel_comparison"],complete_native_records=sum(x["records"]for x in e["native"]),
        complete_native_logical_bytes=sum(x["logical_bytes"]for x in e["native"]),
        complete_native_object_bytes=sum(x["complete_object_bytes"]for x in e["native"]),
        native_entry_calls=sum(len(x["entries"])for x in e["native"]),actual_atomic_attempts=sum(len(x["actual_cas"])for x in e["native"]),
        actual_child_lifecycle_records=sum(len(x["child_lifecycle"])for x in e["native"]),
        actual_native_read_joins=sum(len(x["native_read_joins"])for x in e["traces"]),
        whole_kernel_payload_bytes=sum(x["whole_kernel_payload_bytes"]for x in e["traces"]),
        guard_probes=len(result["probes"]),whole_filesystem_entries=len(result["before"]),elapsed_seconds=time.monotonic()-started,
        application_replays=0,reader_native_executions=0,reader_original_executions=0,
        namespace_version_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    print(encoded(summary).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args();run(a.workspace.resolve(strict=True),a.group,a.output.absolute())
