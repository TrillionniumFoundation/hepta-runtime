"""Reuse complete actual original capture; resume only the interrupted native lane."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE/"build_reader")]
import callable_common,read_capture,read_only_guard as guard,wait_domain,wait_observations as obs
from restore_graph import download
from restore_inputs import flat_archive
from capture_common import file_pin
from run import invoke
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def need(value,message):
    if not value:raise ValueError(message)
def original_summary(folder,identity):
    values=read_capture.read(folder,"original",identity["original_binary"])
    return {"status":"COMPLETE_RETAINED_ORIGINAL_FOUR_CASES_READ_PASS","application_executions":0,"cases":[{"name":x["name"],"stdout":read_capture.pin(x["stdout"]),"stderr":read_capture.pin(x["stderr"]),"exit_code":x["exit_code"],"milestones":x["milestones"],"final":x["trace"]["final"]} for x in values]}
def prepare(out):
    need(not out.exists(),"fresh recovery capture");out.mkdir(parents=True)
    put(out/"SOURCE.json",callable_common.syntax(HERE))
    identity=json.loads((HERE/"RETAINED_FIRST.json").read_bytes())
    archive=out/"retained-first.zip";download(archive,identity["artifact"])
    restored=out/"retained-first"
    put(out/"RETAINED_ARCHIVE_READ.json",flat_archive(archive,identity,restored))
    source=restored/"recipe-source";capture=restored/"capture"
    manifest=(source/"SOURCE_MANIFEST.json").read_bytes()
    need(hashlib.sha256(manifest).hexdigest()==identity["source_manifest_sha256"],"entire old source manifest")
    oldrows=json.loads(manifest)["files"];changed=[]
    for row in oldrows:
        a=(source/row["path"]).read_bytes();b=(HERE/row["path"]).read_bytes()
        need(read_capture.pin(a)=={k:row[k] for k in ("bytes","sha256")} and callable_common.blob(a)==row["git_blob"],"complete retained old source")
        if row["path"]=="wait_observations.py":
            adapter=identity["byte_adapter"]
            need(hashlib.sha256(a).hexdigest()==adapter["before_sha256"] and hashlib.sha256(b).hexdigest()==adapter["after_sha256"],"exact single observer adapter pins")
            old,new=adapter["before"].encode(),adapter["after"].encode()
            need(a.count(old)==1 and a.replace(old,new)==b,"one byte adapter only")
            changed.append(row["path"])
        else:need(a==b,"no other old driver/reader/domain source changed")
    need(changed==["wait_observations.py"],"only native mapping representation changed")
    put(out/"SOURCE_TRANSFORM.json",{"old_source":identity["source"],"old_files_fully_read":len(oldrows),"changed":changed,"exact_single_replacement":identity["byte_adapter"],"production_or_hia_changes":0})
    checked=guard.guarded(lambda:original_summary(capture/"original",identity),roots=[restored,HERE],foreign_path=Path("/dev/null"))
    put(out/"ORIGINAL_READ_ONLY.json",checked)
    print(json.dumps({"original_status":checked["evidence"]["status"],"cases":len(checked["evidence"]["cases"]),"application_executions":0}),flush=True)
    partial=capture/"native/000/process/controls"
    record=json.loads((partial/"0001.json").read_bytes())
    need(record["complete"] is False and record["failure"]["type"]=="AttributeError" and record["failure"]["message"]=="'memoryview' object has no attribute 'decode'","preserved exact first observer failure")
    def decode_prefix():
        raw=read_capture.raw_stream(partial,record["output"])
        need(len(raw)==record["actual_response_extent"],"complete physically retained native reply")
        value=obs.frame(raw,"native")
        need((value["sequence"],value["operation"],value["slot"],value["phase"])==(1,4,0,0),"same real first cache seed reply")
        return {"status":"COMPLETE_RETAINED_NATIVE_REPLY_DECODE_PASS","actual_reply":read_capture.pin(raw),"decoded":value,"old_failure_preserved":True,"application_executions":0}
    decoded=guard.guarded(decode_prefix,roots=[restored,HERE],foreign_path=Path("/dev/null"))
    put(out/"NATIVE_PREFIX_READ_ONLY.json",decoded)
    print(json.dumps({"retained_native_prefix_status":decoded["evidence"]["status"],"actual_complete_mappings":len(decoded["evidence"]["decoded"]["full_native_mappings"]),"application_executions":0}),flush=True)
    shutil.copytree(capture/"original",out/"original",copy_function=shutil.copy2)
    copied=0
    for path in sorted((capture/"original").rglob("*")):
        if path.is_file():
            other=out/"original"/path.relative_to(capture/"original")
            need(path.read_bytes()==other.read_bytes() and path.stat().st_mode&0o777==other.stat().st_mode&0o777,"all retained original copy bytes/modes")
            copied+=1
    domain=json.loads((capture/"FROZEN_DOMAIN.json").read_bytes())
    expected=wait_domain.domain("ordinary-a-legacy",Path("/tmp/hia-extract-contention-ordinary-a-legacy/work"))
    need(domain==expected,"same frozen actual input domain")
    put(out/"FROZEN_DOMAIN.json",domain)
    put(out/"REUSED_ORIGINAL.json",{"source_artifact":identity["artifact"],"source_run":identity["run"],"whole_copied_files":copied,"complete_bytes_and_modes_compared":True,"source_reader":identity["independent_original_reader"],"executions_in_this_successor":0})
    put(out/"RUN.json",{"status":"RETAINED_ORIGINAL_AND_PREFIX_PREPARED","domain":"ordinary-a-legacy","original_replayed":False,"new_original_executions":0,"new_native_cases":4,"production_installed":False,"full_runtime":False,"full_sdk":False})
def execute(out,inputs):
    need(json.loads((out/"RUN.json").read_bytes())["status"]=="RETAINED_ORIGINAL_AND_PREFIX_PREPARED","exact complete recovery admission")
    binaries=json.loads((inputs/"BINARIES.json").read_bytes());need(binaries["status"]=="EXACT_ALREADY_BUILT_INPUTS_READY","full actual build custody")
    identity=json.loads((HERE/"RETAINED_FIRST.json").read_bytes())
    need({k:binaries["original"][k] for k in ("bytes","sha256")}==identity["original_binary"],"same exact already captured original")
    put(out/"INPUTS_READY.json",binaries)
    for name in ("NATIVE_DEPENDENCY_READONLY.json","FIXTURE_ARCHIVE_READ.json","ORIGINAL_ARCHIVE_READ.json","ORIGINAL_READER_PROCESS.json","original-reader.stdout","original-reader.stderr"):
        (out/name).write_bytes((inputs/name).read_bytes())
    status={"status":"RUNNING","domain":"ordinary-a-legacy","original_replayed":False,"new_original_executions":0,"new_native_cases":4,"production_installed":False,"full_runtime":False,"full_sdk":False}
    put(out/"RUN.json",status)
    try:
        invoke(out,"native",[sys.executable,"-I","-S","-B",str(HERE/"capture.py"),"--binary",binaries["native"]["path"],"--output",str(out/"native"),"--work","/tmp/hia-extract-contention-ordinary-a-legacy/work","--domain","ordinary-a-legacy","--side","native"],limit=180)
        def read():
            pair=[read_capture.read(out/side,side,{k:binaries[side][k] for k in ("bytes","sha256")}) for side in ("original","native")]
            return read_capture.compare(*pair)
        checked=guard.guarded(read,roots=[out,HERE],foreign_path=Path("/dev/null"))
        put(out/"READ_ONLY.json",checked);put(out/"QUALIFICATION.json",checked["evidence"])
        status.update(status="NEW_ACTUAL_NATIVE_RETAINED_ORIGINAL_PAIR_PASS",cases=4,independent_full_archive_read_required=True)
    except BaseException as error:
        status.update(status="FAIL",error=repr(error),traceback=traceback.format_exc())
        path=out/"native.stderr"
        if path.is_file():sys.stderr.buffer.write(path.read_bytes());sys.stderr.buffer.flush()
        raise
    finally:put(out/"RUN.json",status)
    print(json.dumps(status,sort_keys=True),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("prepare","execute"));p.add_argument("--output",type=Path,required=True);p.add_argument("--inputs",type=Path);a=p.parse_args()
    need(os.environ.get("GITHUB_ACTIONS")=="true","actual application CI only")
    if a.mode=="prepare":prepare(a.output.absolute())
    else:execute(a.output.absolute(),a.inputs.resolve(strict=True))
if __name__=="__main__":main()
