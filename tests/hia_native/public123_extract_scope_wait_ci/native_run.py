"""Execute only native against retained original cases; no original replay."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
for k in ("capture-source","inputs","output"):p.add_argument("--"+k,type=Path,required=True)
p.add_argument("--domain",required=True)
a=p.parse_args();source=a.capture_source.resolve(strict=True);inputs=a.inputs.resolve(strict=True);out=a.output.absolute()
assert os.environ.get("GITHUB_ACTIONS")=="true" and not out.exists();out.mkdir(parents=True)
sys.path[:0]=[str(source),str(source/"build_reader"),str(HERE)]
import callable_common,read_only_guard as guard,wait_domain,failure_read
import read_capture_fixed as read_capture
from restore_inputs import flat_archive
from restore_graph import download
from run import invoke
from capture_common import file_pin
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
identity=json.loads((HERE/"IDENTITY.json").read_bytes())
stage=identity["reader_stage_patch"]
original_reader=(source/"read_capture.py").read_text()
assert original_reader.count(stage["before"])==1
reader=original_reader.replace(stage["before"],stage["after"])
fence_reader=identity["reader_fence_patch"]
assert reader.count(fence_reader["before"])==1
reader=reader.replace(fence_reader["before"],fence_reader["after"])
for patch in identity["reader_scope_patches"]:
    assert reader.count(patch["before"])==1
    reader=reader.replace(patch["before"],patch["after"])
assert reader==(HERE/"read_capture_fixed.py").read_text()
assert file_pin(source/"SOURCE_MANIFEST.json")==identity["capture_source_manifest"]
put(out/"SOURCE.json",callable_common.syntax(source));shutil.copytree(HERE,out/"recipe-extension")
matches=[x for x in identity["original"]["artifacts"] if x["domain"]==a.domain]
assert len(matches)==1
original=matches[0];archive=out/"retained-original.zip";download(archive,original["artifact"])
put(out/"ORIGINAL_ARCHIVE_READ.json",flat_archive(archive,original,out/"retained-original"))
old=out/"retained-original/recipe-source";manifest=(old/"SOURCE_MANIFEST.json").read_bytes()
assert hashlib.sha256(manifest).hexdigest()==original["source_manifest_sha256"]
for row in json.loads(manifest)["files"]:
    previous=(old/row["path"]).read_bytes();current=(source/row["path"]).read_bytes()
    assert read_capture.pin(previous)=={k:row[k] for k in ("bytes","sha256")} and callable_common.blob(previous)==row["git_blob"]
    if a.domain=="ordinary-a-legacy" and row["path"]=="wait_observations.py":
        adapter=identity["original"]["first_byte_adapter"]
        assert hashlib.sha256(previous).hexdigest()==adapter["before_sha256"] and hashlib.sha256(current).hexdigest()==adapter["after_sha256"]
        assert previous.count(adapter["before"].encode())==1 and previous.replace(adapter["before"].encode(),adapter["after"].encode())==current
    else:assert previous==current
retained=out/"retained-original/capture/original"
def read_original():
    values=read_capture.read(retained,"original",original["original_binary"])
    assert len(values)==4
    return {"status":"EXACT_RETAINED_ORIGINAL_FOUR_READ","case_names":[x["name"] for x in values],"application_executions":0}
put(out/"ORIGINAL_READ_ONLY.json",guard.guarded(read_original,roots=[out,source,HERE],foreign_path=Path("/dev/null")))
shutil.copytree(retained,out/"original",copy_function=shutil.copy2)
count=0
for path in retained.rglob("*"):
    if path.is_file():
        copied=out/"original"/path.relative_to(retained)
        assert path.read_bytes()==copied.read_bytes() and path.stat().st_mode&0o777==copied.stat().st_mode&0o777
        count+=1
put(out/"REUSED_ORIGINAL.json",{"artifact":original["artifact"],"source":original["source"],"independent_read_commit":"7c3df2056b2a30b523fedda493fbf17f67bac444","independent_read_run":44059308537,"all_bytes_and_modes_exact":True,"copied_files":count,"new_original_executions":0})
ready=json.loads((inputs/"NATIVE_READY.json").read_bytes());assert ready["status"]=="COMPLETE_UPLOADED_SCOPE_SUCCESSOR_READY"
assert file_pin(ready["native"]["path"])==identity["native_build"]["fixture"]=={k:ready["native"][k] for k in ("bytes","sha256")}
put(out/"INPUTS_READY.json",{"status":"EXACT_NATIVE_AND_RETAINED_ORIGINAL_READY","native":ready["native"],"original":original["original_binary"],"original_replayed":False})
for name in ("NATIVE_READ_ONLY.json","BUILD_ARCHIVE_READ.json","NATIVE_READY.json","BUILD_SOURCE.json","CAPTURE_SOURCE.json"):(out/name).write_bytes((inputs/name).read_bytes())
work=Path("/tmp")/("hia-extract-contention-"+a.domain)/"work"
frozen=wait_domain.domain(a.domain,work)
assert json.loads((out/"retained-original/capture/FROZEN_DOMAIN.json").read_bytes())==frozen
put(out/"FROZEN_DOMAIN.json",frozen)
status={"status":"RUNNING","domain":a.domain,"new_original_executions":0,"new_native_cases":4,"exchange_seconds":60,"lane_seconds":180,"production_installed":False,"full_runtime":False,"full_sdk":False}
put(out/"RUN.json",status)
try:
    invoke(out,"native",[sys.executable,"-I","-S","-B",str(source/"capture.py"),"--binary",ready["native"]["path"],"--output",str(out/"native"),"--work",str(work),"--domain",a.domain,"--side","native"],limit=180)
    def read():
        pair=[read_capture.read(out/side,side,original["original_binary"] if side=="original" else identity["native_build"]["fixture"]) for side in ("original","native")]
        return read_capture.compare(*pair)
    checked=guard.guarded(read,roots=[out,source,HERE],foreign_path=Path("/dev/null"))
    put(out/"READ_ONLY.json",checked);put(out/"QUALIFICATION.json",checked["evidence"])
    status.update(status="ACTUAL_NATIVE_RETAINED_ORIGINAL_WAIT_PAIR_PASS",independent_full_archive_read_required=True)
except BaseException as error:
    status.update(status="FAIL",error=repr(error),traceback=traceback.format_exc())
    if (out/"native.stderr").is_file():sys.stderr.buffer.write((out/"native.stderr").read_bytes());sys.stderr.buffer.flush()
    proof=guard.guarded(lambda:failure_read.inspect(out),roots=[out,source,HERE],foreign_path=Path("/dev/null"))
    put(out/"FAILURE_READ_ONLY.json",proof)
    failure_read.show(proof)
    raise
finally:put(out/"RUN.json",status)
print(json.dumps(status,sort_keys=True))
