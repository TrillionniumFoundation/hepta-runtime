"""Complete retained failure archive and independent original-only actual capture read."""
from pathlib import Path
import argparse,hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
for name in ("source","output"):p.add_argument("--"+name,type=Path,required=True)
a=p.parse_args();source=a.source.resolve(strict=True);output=a.output.absolute();assert not output.exists();output.mkdir(parents=True)
sys.path[:0]=[str(source),str(source/"build_reader")]
import restore_inputs,read_capture,read_only_guard as guard
from restore_graph import download
from read_primitives import pin
identity=json.loads((HERE/"IDENTITY.json").read_bytes())
archive=output/"producer.zip";download(archive,identity["artifact"])
proof=restore_inputs.flat_archive(archive,identity,output/"restored")
(output/"ARCHIVE_READ.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
capture=output/"restored/capture";old=output/"restored/recipe-source"
assert (old/"SOURCE_MANIFEST.json").read_bytes()==(source/"SOURCE_MANIFEST.json").read_bytes()
for row in json.loads((source/"SOURCE_MANIFEST.json").read_bytes())["files"]:
    assert (old/row["path"]).read_bytes()==(source/row["path"]).read_bytes()
def original():
    values=read_capture.read(capture/"original","original",identity["original_binary"])
    return {"status":"COMPLETE_NEW_ORIGINAL_FOUR_CASES_READ_PASS","cases":[{"name":x["name"],"stdout":{"bytes":len(x["stdout"]),"sha256":hashlib.sha256(x["stdout"]).hexdigest()},"stderr":{"bytes":len(x["stderr"]),"sha256":hashlib.sha256(x["stderr"]).hexdigest()},"exit_code":x["exit_code"],"milestones":x["milestones"],"final":x["trace"]["final"]} for x in values],"application_executions":0}
try:
    checked=guard.guarded(original,roots=[output/"restored",source],foreign_path=Path("/dev/null"))
    (output/"ORIGINAL_READ.json").write_text(json.dumps(checked,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"original_status":checked["evidence"]["status"],"cases":len(checked["evidence"]["cases"])}))
except BaseException as error:
    import traceback
    (output/"ORIGINAL_READ_FAILURE.json").write_text(json.dumps({"error":repr(error),"traceback":traceback.format_exc()},sort_keys=True,indent=2)+"\n")
    print("ORIGINAL_READER_FAILURE",repr(error))
for name in ("native.stderr","native/CAPTURE.json","native/000/CASE.json","native/000/process/process.json"):
    path=capture/name
    if not path.is_file():continue
    if name.endswith(".stderr"):
        print("NATIVE_ACTUAL_STDERR",path.read_text())
    else:
        row=json.loads(path.read_bytes())
        fields={k:row[k] for k in ("status","failure","finalization_failure","exit_code","timed_out","kill_requested","cleanup_error") if k in row}
        if "steps" in row:fields["completed_steps"]=[{"kind":x["kind"],"label":x["label"]} for x in row["steps"]]
        print(name,json.dumps(fields,sort_keys=True))
print(json.dumps({"archive":proof,"application_executions":0},sort_keys=True))
