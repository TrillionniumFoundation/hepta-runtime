"""Exact main99 original source, archive and sealed-subset admission for pure readers."""
from __future__ import annotations
import gzip,hashlib,json,stat
from pathlib import Path
REPORT={"bytes":94615186,"sha256":"83437daf7232222bf19025a2c4b395ec4da70179984f2a52763abb452fd98078"}
ORIGINAL_ZIP={"bytes":4393597000,"sha256":"7e7401e56dce43db85a904b1e4196922960f2fecc1ba3375b14b52a4b969f379"}
ORIGINAL_TAR={"bytes":27711549440,"sha256":"21ef4d99bc8ba887e6bb358a612c9cb7e9ded04c6a22eba6989d656042358ba8"}
INDEX={"bytes":13973301,"sha256":"db1f950694c06617428b9aead92b99f8646b32e918ebb442cdb8ec021c571c6e"}
INDEX_ZIP={"bytes":97817288,"sha256":"aa8d7e9daae8fa84365d88512780a9c6a45dd4a121fc8124693294da9626a908"}
INSPECT_ZIP={"bytes":14695399,"sha256":"17fdf989d82838c70a5bdb08a336b236d1a92ebd7891466395fba59ec7a7ebdd"}
INPUTS={"bytes":2591326,"sha256":"88764bad160c07f3d28a7325a6004e86bd1f9d014ab7c963fe6105e8a0a10569"}
HEAD="99d107c062a6eb3f226dd82b05283aeecbd3c495"
def need(v,s):
    if not v:raise ValueError(s)
def read(p):return json.loads(p.read_bytes())
def pin(p):
    before=p.lstat();need(stat.S_ISREG(before.st_mode) and p.resolve()==p.absolute(),"complete ordinary retained input")
    with p.open("rb") as f:h=hashlib.file_digest(f,"sha256").hexdigest()
    after=p.lstat();need(all(getattr(before,k)==getattr(after,k) for k in
      ("st_dev","st_ino","st_mode","st_size","st_mtime_ns","st_ctime_ns")),"stable complete original input")
    return {"bytes":before.st_size,"sha256":h}
def artifact_expectations(kind):
    value=read(Path(__file__).with_name("EXPECTED.json"))
    need(value["original_head"]==HEAD and value["continuation_source"]=="fb97ee216f09b423b3ba17d72528f70d45ceb4d4"
         and value["original_failure_reclassified_as_pass"] is False,"fixed main99 independent reader plan")
    return value["artifacts"][kind]
def verify_origin(proof,hs,cap,prep,kind):
    need(kind in ("filesystem","regex") and prep["kind"]==kind,"exact original pending domain")
    need(prep["original_zip"]==ORIGINAL_ZIP and prep["original_tar"]==ORIGINAL_TAR
         and prep["original_files"]==153488 and prep["original_directories"]==26800
         and prep["original_logical_bytes"]==27390413778 and prep["index_zip"]==INDEX_ZIP and prep["index"]==INDEX
         and prep["inspection_zip"]==INSPECT_ZIP and prep["input_inspection"]==INPUTS
         and prep["original_report"]==REPORT and prep["original_workflow_status"]=="FAILURE"
         and prep["completed_aggregate_status"]=="PASS" and prep["source_pins_rebound"] is False
         and prep["original_failure_reclassified_as_pass"] is False and prep["native_or_rust_executions"]==0,
         "complete exact original failure/input restoration scope")
    api=read(proof/"ORIGINAL_API.json")
    need(api==prep["original_api"] and api["id"]==14308317195 and api["workflow_run"]["id"]==44023379853
         and api["workflow_run"]["head_sha"]==HEAD and api["expired"] is False
         and api["size_in_bytes"]==ORIGINAL_ZIP["bytes"] and api["digest"]=="sha256:"+ORIGINAL_ZIP["sha256"],
         "exact immutable original API custody")
    for name,identity,run,head,expected in (
        ("INDEX_API.json",14309198930,44040902201,"7b188b7ef52fa1f9ba4e67892fe5f3beecb4167d",INDEX_ZIP),
        ("INSPECTION_API.json",14309294507,44042371247,"884d2aa3dadc88055b9b06bee680197adab0db2d",INSPECT_ZIP)):
        row=read(proof/name)
        need(row["id"]==identity and row["workflow_run"]["id"]==run and row["workflow_run"]["head_sha"]==head
             and row["size_in_bytes"]==expected["bytes"] and row["digest"]=="sha256:"+expected["sha256"]
             and row["expired"] is False,"exact complete derivation artifact API")
    home=proof/"preparation";need(pin(home/"CONTROL_INPUTS.json")==INPUTS,"unchanged original input inspection bytes")
    inputs=read(home/"CONTROL_INPUTS.json")
    need(inputs["status"]=="EXACT_RETAINED_CONTROL_INPUTS_PASS" and inputs["head"]==HEAD
         and inputs["original_report"]==REPORT and inputs["report_status"]=="PASS"
         and inputs["report_phase"]=="complete" and inputs["actual_checks"]==405
         and inputs["actual_original_recipes"]==81 and inputs["materialized_source_files"]==prep["source_files"],
         "all source identities join independent complete inspection")
    expected_subset={name:{k:row[k] for k in ("bytes","sha256","mode")}
                     for name,row in inputs["output_files"][kind].items()}
    need(prep["output_files"]==expected_subset,"all restored inputs join separate immutable subset inspection")
    for name,row in prep["source_files"].items():
        need(pin(hs/name)=={k:row[k] for k in ("bytes","sha256")}
             and stat.S_IMODE((hs/name).lstat().st_mode)==row["mode"],"all physical original source bytes")
    need(len(prep["source_files"])==2879 and len(inputs["original_source_sha256"])==2113,"complete source domain")
    need(pin(cap/"result.json")==REPORT,"exact all original aggregate report bytes")
    original=read(cap/"result.json")
    need(original["status"]=="PASS" and original["phase"]=="complete" and len(original["checks"])==405
         and len(original["original_rust_comparisons"])==81 and original["source_sha256"]==inputs["original_source_sha256"],
         "completed original aggregate and exact source seal")
    for name,digest in original["source_sha256"].items():
        need(prep["source_files"][name]["sha256"]==digest,"all unchanged original source pins")
    need(pin(home/"tar-index.jsonl.gz")==INDEX,"complete original file/header index")
    index_proof=read(home/"INDEX_PROOF.json")
    need(index_proof["status"]=="COMPLETE_BYTE_READBACK_PASS" and index_proof["original_artifact"]==14308317195
         and index_proof["original_run"]==44023379853 and index_proof["original_head"]==HEAD
         and index_proof["zip"]==ORIGINAL_ZIP and index_proof["tar"]==ORIGINAL_TAR
         and index_proof["semantic_executions"]==0 and index_proof["original_failure_reclassified_as_pass"] is False,
         "original full archive read custody")
    count=files=dirs=logical=0;matched=set();seen=set()
    with gzip.open(home/"tar-index.jsonl.gz","rb") as stream:
        for line in stream:
            row=json.loads(line);count+=1;name=row["path"]
            need(name not in seen,"unique complete original indexed member");seen.add(name)
            if row["type"]=="0":
                files+=1;logical+=row["data"]["bytes"]
                need(row["size"]==row["data"]["bytes"],"complete indexed member extent")
            else:need(row["type"]=="5","ordinary original member");dirs+=1
            if name in prep["output_files"]:
                need(row["type"]=="0" and prep["output_files"][name]=={**row["data"],"mode":row["mode"]}
                     and inputs["original_tar_records"][name]==row,"all exact original retained file header/data identities")
                matched.add(name)
    need(count==180288 and files==153488 and dirs==26800 and logical==27390413778
         and matched==set(prep["output_files"]),"whole original index and every actual sealed input")
    need(len(matched)==(902 if kind=="filesystem" else 626),"full pending-control input domain")
    outer=read(home/"ORIGINAL_ARCHIVE_MANIFEST.json")
    need(outer["status"]=="COMPLETE" and outer["diagnostics_complete"] is True
         and outer["archive"]["complete"] is True and outer["archive"]["exit_code"]==0
         and outer["archive"]["timed_out"] is False and outer["original_failure_reclassified_as_pass"] is False
         and {k:outer["archive"]["archive"][k] for k in ("bytes","sha256")}==ORIGINAL_TAR,"unchanged complete original failure archive")
    return count,logical
