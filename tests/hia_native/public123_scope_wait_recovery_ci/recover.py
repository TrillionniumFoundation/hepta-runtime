"""Complete uploaded capture recovery, never application execution."""
from pathlib import Path
import argparse,hashlib,json,os,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
for k in ("capture-source","native-source","output"):p.add_argument("--"+k,type=Path,required=True)
p.add_argument("--domain",required=True)
a=p.parse_args();source=a.capture_source.resolve(strict=True);native=a.native_source.resolve(strict=True);out=a.output.absolute()
assert not out.exists();out.mkdir(parents=True)
sys.path[:0]=[str(HERE),str(native),str(source),str(source/"build_reader")]
import callable_common,read_only_guard as guard,read_lifetime as reader
from restore_inputs import flat_archive
from restore_graph import download
from capture_common import file_pin
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
identity=next(x for x in json.loads((HERE/"INPUTS.json").read_bytes())["artifacts"] if x["domain"]==a.domain)
assert file_pin(source/"SOURCE_MANIFEST.json")==identity["capture_source_manifest"]
assert file_pin(native/"SOURCE_MANIFEST.json")==identity["native_source_manifest"]
for root,label in ((HERE,"recipe"),(source,"capture"),(native,"native")):put(out/(label+"-SOURCE.json"),callable_common.syntax(root))
archive=out/"producer.zip";download(archive,identity["artifact"])
put(out/"ARCHIVE_READ.json",flat_archive(archive,identity,out/"retained"))
actual=out/"retained/capture"
for captured,frozen in ((out/"retained/recipe-source",source),(actual/"recipe-extension",native)):
    assert (captured/"SOURCE_MANIFEST.json").read_bytes()==(frozen/"SOURCE_MANIFEST.json").read_bytes()
    for row in json.loads((frozen/"SOURCE_MANIFEST.json").read_bytes())["files"]:
        assert (captured/row["path"]).read_bytes()==(frozen/row["path"]).read_bytes()
assert (HERE/"read_capture_fixed.py").read_bytes()==(native/"read_capture_fixed.py").read_bytes()
inputs=json.loads((actual/"INPUTS_READY.json").read_bytes())
assert {k:inputs["native"][k] for k in ("bytes","sha256")}==reader.source_contract()["native_fixture"]
def read():
    pair=[reader.read(actual/side,side,{k:inputs[side][k] for k in ("bytes","sha256")}) for side in ("original","native")]
    return reader.compare(*pair)
proof=guard.guarded(read,roots=[out,source,native,HERE],foreign_path=Path("/dev/null"))
put(out/"READ_ONLY.json",proof);put(out/"QUALIFICATION.json",proof["evidence"])
old=json.loads((actual/"RUN.json").read_bytes())
result={"status":"COMPLETE_RETAINED_SCOPE_WAIT_PAIR_PASS","domain":a.domain,"source":"320862f03902153b5c804d1b68142126a9c7a606",
    "original_cases":4,"native_cases":4,"new_original_executions":0,"new_native_executions":0,"guard_probes":len(proof["probes"]),
    "producer_status_preserved":old["status"],"inode_reallocation_proofs":len(proof["evidence"]["inode_reallocation_proofs"]),
    "complete_files":identity["files"],"complete_logical_bytes":identity["logical_bytes"],"artifact":identity["artifact"],
    "production_installed":False,"full_runtime":False,"full_sdk":False}
put(out/"RESULT.json",result)
print(json.dumps(result,sort_keys=True),flush=True)
