"""Read the complete uploaded Scope graph and all retained HIA receipts without execution."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
for k in ("build-source","capture-source","retained-inputs","output"):p.add_argument("--"+k,type=Path,required=True)
a=p.parse_args();build=a.build_source.resolve(strict=True);capture=a.capture_source.resolve(strict=True);inputs=a.retained_inputs.resolve(strict=True);out=a.output.absolute()
assert not out.exists();out.mkdir(parents=True)
sys.path[:0]=[str(build),str(capture),str(capture/"build_reader"),str(HERE)]
import callable_common,read_graph,read_successor,restore_graph,read_only_guard as guard
from restore_inputs import flat_archive
from read_primitives import pin,doc
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
identity=doc(HERE/"IDENTITY.json")
assert pin(build/"SOURCE_MANIFEST.json")==identity["build_source_manifest"]
assert pin(capture/"SOURCE_MANIFEST.json")==identity["capture_source_manifest"]
put(out/"BUILD_SOURCE.json",callable_common.syntax(build))
put(out/"CAPTURE_SOURCE.json",callable_common.syntax(capture))
retained=inputs/"shared/retained";previous=inputs/"successor/capture"
old=doc(inputs/"NATIVE_READY.json");base=identity["previous_native_build"]
assert old["status"]=="COMPLETE_UPLOADED_NATIVE_SUCCESSOR_READY" and old["source_commit"]==base["production_source"] and old["build_source"]==base["build_source"] and old["build_artifact"]==base["native_build"]["artifact"] and old["original_executions"]==old["native_executions"]==0
assert {k:old["native"][k] for k in ("bytes","sha256")}==base["native_build"]["fixture"]
put(out/"PREVIOUS_READ_ONLY.json",doc(inputs/"NATIVE_READ_ONLY.json"))
archive=out/"producer.zip";restore_graph.download(archive,identity["native_build"]["artifact"])
put(out/"BUILD_ARCHIVE_READ.json",flat_archive(archive,identity["native_build"],out/"successor"))
old_source=out/"successor/recipe-source"
assert (old_source/"SOURCE_MANIFEST.json").read_bytes()==(build/"SOURCE_MANIFEST.json").read_bytes()
for row in doc(build/"SOURCE_MANIFEST.json")["files"]:
    assert (old_source/row["path"]).read_bytes()==(build/row["path"]).read_bytes()
read_graph.prepare(retained)
proof=guard.guarded(lambda:read_successor.verify(retained,previous,out/"successor/capture"),roots=[retained,previous,out/"successor",build,capture],foreign_path=Path("/dev/null"))
put(out/"NATIVE_READ_ONLY.json",proof)
binary=out/"successor/capture/build-fixture/scope-fixture/task-pump-fixture.elf"
assert pin(binary)==identity["native_build"]["fixture"]
result={"status":"COMPLETE_UPLOADED_SCOPE_SUCCESSOR_READY","native":{"path":str(binary),**pin(binary)},"original_executions":0,"native_executions":0,"source_commit":identity["production_source"],"build_source":identity["native_build"]["source"],"build_artifact":identity["native_build"]["artifact"],"all_direct_members_reverified":115}
put(out/"NATIVE_READY.json",result);print(json.dumps(result,sort_keys=True))
