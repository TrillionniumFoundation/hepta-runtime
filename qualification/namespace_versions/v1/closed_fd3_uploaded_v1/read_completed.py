"""Independent complete reader of a previously successful application artifact; no native execution."""
from pathlib import Path
from common import source,loads,read,require,pin
from source_check import verify as check_source
from read_group import verify as group_read
def verify(workspace,group,capture):
    checked=check_source();identity=source(workspace/"source");run=workspace/"run";retained=workspace/"retained"
    require(identity==capture["source_manifest_sha256"]and group==capture["group"],"exact already completed source and group")
    admission=loads(read(retained/"ADMISSION.json"));meta=loads(read(run/"RUN.json"));processes=loads(read(run/"processes/processes.json"))
    require(admission["status"]=="PASS"and admission["source_manifest_sha256"]==identity
        and admission["native_application_calls"]==admission["original_application_calls"]==0,"whole original pre-application admission")
    require(meta["schema"]=="hepta.namespace-versions.actual-run.v1"and meta["status"]=="PASS"and meta["group"]==group
        and meta["source_manifest_sha256"]==identity and meta["application_replays"]==0,"exact completed actual group")
    names=["source","restore","read-native","read-original","strace-version","application","read"]
    require([p["name"]for p in processes]==names and processes==meta["processes"],"all actual completed custody and first pure reader")
    expected=meta["commands"];require(len(expected)==7,"exact seven prior commands")
    for i,p in enumerate(processes):
        require(p["completed"]and not p["timed_out"]and p["exit_code"]==0 and p["pid"]==p["pgid"]
            and p["parent_pid"]==meta["pid"]and p["elapsed_seconds"]<=p["timeout_seconds"]and p["stdin"]is None,
            "every prior real process completed once within unchanged deadline")
        require(p["timeout_seconds"]==(60 if p["name"]in("source","strace-version","application")else 180)
            and all(p[k]==expected[i][k]for k in("name","argv","cwd","timeout_seconds")),"every complete source-frozen command and budget")
        for name in("stdout","stderr"):
            require(p[name]==dict(file=p["name"]+"."+name,**pin(read(run/"processes"/p[name]["file"]))),
                "every complete captured process stream")
    gate=loads(read(run/"GATE.json"))
    require(gate==capture["gate"]and gate["status"]=="NAMESPACE_VERSIONS_ACTUAL_GROUP_PASS"
        and gate["source_manifest_sha256"]==identity and gate["processes"]==processes and gate["application_replays"]==0,
        "complete immutable original actual gate")
    result=group_read(run/"group",group,identity)
    require(result["original_processes"]==1 and result["native_processes"]==2,"exact already completed application counts")
    return dict(result,source_check=checked,build_admission=pin(read(retained/"ADMISSION.json")),processes=processes,
        new_original_applications=0,new_native_applications=0,completed_application_replays=0)
