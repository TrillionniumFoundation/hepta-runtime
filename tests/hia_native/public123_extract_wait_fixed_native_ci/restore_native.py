"""Complete uploaded build and inherited graph reads; no application is executed."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
for k in ("build-source","capture-source","output"):p.add_argument("--"+k,type=Path,required=True)
a=p.parse_args();build=a.build_source.resolve(strict=True);capture=a.capture_source.resolve(strict=True);out=a.output.absolute()
assert not out.exists();out.mkdir(parents=True)
sys.path[:0]=[str(build),str(capture),str(capture/"build_reader")]
import callable_common,read_graph,read_successor,restore_graph,read_only_guard as guard
from restore_inputs import flat_archive
from read_primitives import pin,doc
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
identity=doc(HERE/"IDENTITY.json")
assert pin(build/"SOURCE_MANIFEST.json")==identity["build_source_manifest"]
assert pin(capture/"SOURCE_MANIFEST.json")==identity["capture_source_manifest"]
put(out/"BUILD_SOURCE.json",callable_common.syntax(build))
put(out/"CAPTURE_SOURCE.json",callable_common.syntax(capture))
retained=restore_graph.restore(out/"shared")
archive=out/"producer.zip";restore_graph.download(archive,identity["native_build"]["artifact"])
put(out/"BUILD_ARCHIVE_READ.json",flat_archive(archive,identity["native_build"],out/"successor"))
old=out/"successor/recipe-source"
assert (old/"SOURCE_MANIFEST.json").read_bytes()==(build/"SOURCE_MANIFEST.json").read_bytes()
for row in doc(build/"SOURCE_MANIFEST.json")["files"]:
    assert (old/row["path"]).read_bytes()==(build/row["path"]).read_bytes()
read_graph.prepare(retained)
proof=guard.guarded(lambda:{"retained":read_graph.verify(retained),"successor":read_successor.verify(retained,out/"successor/capture")},roots=[retained,out/"successor",build,capture],foreign_path=Path("/dev/null"))
put(out/"NATIVE_READ_ONLY.json",proof)
binary=out/"successor/capture/build-fixture/policy-fixture/task-pump-fixture.elf"
assert pin(binary)==identity["native_build"]["fixture"]
result={"status":"COMPLETE_UPLOADED_NATIVE_SUCCESSOR_READY","native":{"path":str(binary),**pin(binary)},"original_executions":0,"native_executions":0,"source_commit":identity["production_source"],"build_source":identity["native_build"]["source"],"build_artifact":identity["native_build"]["artifact"]}
put(out/"NATIVE_READY.json",result);print(json.dumps(result,sort_keys=True))
