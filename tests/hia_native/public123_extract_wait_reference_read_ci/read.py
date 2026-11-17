"""All24 captured original cases, full archives and unchanged original reader; no execution."""
from pathlib import Path
import argparse,hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
source=a.source.resolve(strict=True);out=a.output.absolute();assert not out.exists();out.mkdir(parents=True)
sys.path[:0]=[str(source),str(source/"build_reader")]
import callable_common,read_capture,read_only_guard as guard
from restore_inputs import flat_archive
from restore_graph import download
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
identity=json.loads((HERE/"INPUTS.json").read_bytes())
assert hashlib.sha256((source/"SOURCE_MANIFEST.json").read_bytes()).hexdigest()==identity["reader_manifest"]
put(out/"SOURCE.json",callable_common.syntax(source))
results=[]
for item in identity["artifacts"]:
    here=out/item["domain"];here.mkdir()
    archive=here/"producer.zip";download(archive,item["artifact"])
    put(here/"ARCHIVE_READ.json",flat_archive(archive,item,here/"retained"))
    old=here/"retained/recipe-source";manifest=(old/"SOURCE_MANIFEST.json").read_bytes()
    assert hashlib.sha256(manifest).hexdigest()==item["source_manifest_sha256"]
    for row in json.loads(manifest)["files"]:
        before=(old/row["path"]).read_bytes();current=(source/row["path"]).read_bytes()
        assert read_capture.pin(before)=={k:row[k] for k in ("bytes","sha256")} and callable_common.blob(before)==row["git_blob"]
        if item["domain"]=="ordinary-a-legacy" and row["path"]=="wait_observations.py":
            adapter=identity["first_byte_adapter"]
            assert hashlib.sha256(before).hexdigest()==adapter["before_sha256"] and hashlib.sha256(current).hexdigest()==adapter["after_sha256"]
            assert before.count(adapter["before"].encode())==1 and before.replace(adapter["before"].encode(),adapter["after"].encode())==current
        else:assert before==current
    capture=here/"retained/capture/original"
    def read():
        values=read_capture.read(capture,"original",item["original_binary"])
        assert len(values)==4
        return {"status":"COMPLETE_ACTUAL_ORIGINAL_REFERENCE_READ","application_executions":0,"cases":[{"name":v["name"],"stdout":read_capture.pin(v["stdout"]),"stderr":read_capture.pin(v["stderr"]),"exit_code":v["exit_code"],"tail":v["tail"],"file_snapshots":len(v["files"]),"state_milestones":v["milestones"],"final_runtime_and_fixture_drop":v["trace"]["final"]} for v in values]}
    proof=guard.guarded(read,roots=[here/"retained",source],foreign_path=Path("/dev/null"))
    put(here/"READ_ONLY.json",proof)
    results.append({"domain":item["domain"],"artifact":item["artifact"],"files":item["files"],"logical_bytes":item["logical_bytes"],"case_count":len(proof["evidence"]["cases"]),"guard_probes":len(proof["probes"]),"status":proof["evidence"]["status"]})
result={"status":"ALL24_ACTUAL_ORIGINAL_WAIT_REFERENCES_INDEPENDENT_COMPLETE_READ_PASS","cases":sum(x["case_count"] for x in results),"artifacts":results,"application_executions":0,"public_native_qualified":False}
assert result["cases"]==identity["actual_cases"]==24
put(out/"ALL24_READ.json",result);print(json.dumps(result,sort_keys=True))
