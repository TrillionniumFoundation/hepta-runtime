"""Read the complete uploaded failure and exact completed case, never rerun applications."""
from pathlib import Path
import argparse,hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
for k in ("source","native-source","output"):p.add_argument("--"+k,type=Path,required=True)
args=p.parse_args();source=args.source.resolve(strict=True);native_source=args.native_source.resolve(strict=True);out=args.output.absolute()
assert not out.exists();out.mkdir(parents=True)
sys.path[:0]=[str(source),str(source/"build_reader"),str(native_source)]
import callable_common,read_capture,read_only_guard as guard,failure_read
from read_capture import *
from restore_inputs import flat_archive
from restore_graph import download
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
identity=json.loads((HERE/"IDENTITY.json").read_bytes())
assert callable_common.pin(source/"SOURCE_MANIFEST.json")==identity["helper_manifest"]
assert callable_common.pin(native_source/"SOURCE_MANIFEST.json")==identity["native_driver_manifest"]
put(out/"SOURCE.json",callable_common.syntax(source));put(out/"NATIVE_SOURCE.json",callable_common.syntax(native_source))
archive=out/"producer.zip";download(archive,identity["artifact"])
put(out/"ARCHIVE_READ.json",flat_archive(archive,identity,out/"retained"))
for root,actual in ((out/"retained/recipe-source",source),(out/"retained/capture/recipe-extension",native_source)):
    assert (root/"SOURCE_MANIFEST.json").read_bytes()==(actual/"SOURCE_MANIFEST.json").read_bytes()
    for row in json.loads((root/"SOURCE_MANIFEST.json").read_bytes())["files"]:
        assert (root/row["path"]).read_bytes()==(actual/row["path"]).read_bytes()
original=(source/"read_capture.py").read_text()
body=original[original.index("def read(folder,side,binary):"):original.index("\ndef compare(")]
for previous,current in identity["prefix_edits"]:
    assert body.count(previous)==1
    body=body.replace(previous,current)
own=Path(__file__).read_text()
at=own.index("\ndef read_completed_prefix(")+1
end=own.index("\ndef inspect_complete()",at)
assert own[at:end]==body
def read_completed_prefix(folder,side,binary):
    folder=Path(folder);report=doc(folder/"CAPTURE.json")
    need(report["status"]=="FAIL" and report["side"]==side and report["lane_seconds"]==180 and report["per_exchange_seconds"]==60 and 0<=report["elapsed_seconds"]<180 and report["original_old_domains_replayed"] is False,"complete actual lane")
    plan=wait_domain.domain(report["domain"],Path(report["fixture"]));need(doc(folder/"DOMAIN.json")==plan,"exact whole frozen input domain")
    selected=report["binary"];need({k:selected[k] for k in ("bytes","sha256")}==binary and pin((folder/selected["captured_file"]).read_bytes())==binary,"entire actual runtime binary")
    need(side=="native" and len(report["cases"])==1 and len(plan["cases"])==4 and plan["cases"][0]["name"]=="read-before-lock-target-after-lock","exact one complete case in actual failed four-case lane")
    result=[]
    for i,item in enumerate(plan["cases"][:1]):
        case=folder/("%03d"%i);row=doc(case/"CASE.json")
        need(report["cases"][i]=={"index":i,"name":item["name"],"case":pin((case/"CASE.json").read_bytes())} and row["input"]==item and row["name"]==item["name"] and row["index"]==i and row["status"]=="ACTUAL_PROCESS_EOF_AND_RUNTIME_DROP_CAPTURED","complete case identity")
        used=set();snapshots=[row["initial"]]+[s["snapshot"] for s in row["steps"] if "snapshot" in s]+[row["final"]]
        views=[read_snapshot(case,s,Path(report["fixture"]),used) for s in snapshots]
        expected_files={x["path"].encode().hex():x for x in item["files"]}
        need({r["path_hex"] for r in views[0]["nodes"]}==set(expected_files),"exact frozen initial filesystem inventory")
        for initial in views[0]["nodes"]:
            original=expected_files[initial["path_hex"]]
            need(initial["kind"]=="file" and initial["mode"]==original["mode"] and (case/"blobs"/initial["content"]["path"]).read_bytes()==bytes.fromhex(original["bytes_hex"]),"exact frozen initial file bytes/mode")
        expected_setup=[]
        for initial in item["files"]:
            path=(Path(report["fixture"])/initial["path"]).as_posix().encode().hex()
            expected_setup.extend([{"kind":"write","path_hex":path,"data_hex":initial["bytes_hex"]},{"kind":"chmod","path_hex":path,"mode":initial["mode"]}])
        need([x["action"] for x in row["setup"]]==expected_setup and all(x["status"]=="EXECUTED" for x in row["setup"]),"complete actual frozen fixture setup")
        need(used=={p.name for p in (case/"blobs").iterdir()},"all complete filesystem blobs accounted")
        p=process(case/"process",row,item,side,binary,Path(report["fixture"]))
        p.update(name=item["name"],files=views,metadata=structural_snapshots([s["complete_metadata"] for s in snapshots]))
        result.append(p)
    return result
def inspect_complete():
    capture=out/"retained/capture"
    original=read_capture.read(capture/"original","original",identity["original_binary"])
    native=read_completed_prefix(capture/"native","native",identity["native_binary"])
    pair=read_capture.compare(original[:1],native)
    failure=failure_read.inspect(capture)
    assert len(failure["cases"])==2 and failure["cases"][0]["status"]=="ACTUAL_PROCESS_EOF_AND_RUNTIME_DROP_CAPTURED" and failure["cases"][1]["status"]=="FAIL"
    assert failure["cases"][1]["process"]=={"exit_code":111,"kill_requested":False,"timed_out":False,"cleanup_error":None}
    return {"status":"COMPLETE_FIRST_NATIVE_WAIT_PAIR_AND_NEXT_FAILURE_READ","completed_pair":pair,"next_failure":failure["cases"][1],"archive":identity,"original_replayed":False,"native_replayed":False,"whole_lane_pass":False}
proof=guard.guarded(inspect_complete,roots=[out/"retained",source,native_source,HERE],foreign_path=Path("/dev/null"))
put(out/"READ_ONLY.json",proof)
x=proof["evidence"]
print(json.dumps({"status":x["status"],"completed_pair":x["completed_pair"],"next_failure":{"case":x["next_failure"]["case"],"name":x["next_failure"]["name"],"exit":x["next_failure"]["process"]["exit_code"],"trace_counts":x["next_failure"]["trace"]["counts"]},"full_files":identity["files"],"guards":len(proof["probes"]),"application_executions":0,"whole_lane_pass":False},sort_keys=True))
