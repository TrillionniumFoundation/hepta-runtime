"""Read the retained successful compilation after a pure-reader failure; zero applications."""
import argparse,os,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,require,pin
from process import Recorder
def run(workspace):
    identity=source();output=workspace/"run";output.mkdir()
    python=Path(sys.executable).resolve(strict=True);recorder=Recorder(ROOT,output/"processes",dict(os.environ))
    metadata=dict(schema="hepta.namespace-versions.original-recovery.v1",status="RUNNING",source_manifest_sha256=identity,
        original_compile_replays=0,original_application_calls=0,native_application_calls=0,reader_native_executions=0,reader_rust_executions=0)
    (output/"RECOVERY.json").write_bytes(encoded(metadata))
    try:
        recorder.run("restore",[python,"-I","-B",ROOT/"restore.py","--workspace",workspace],timeout=180)
        raw,_=recorder.run("read",[python,"-I","-B",ROOT/"read_build.py","--original",workspace/"original","--output",output/"GUARDED.json"],timeout=180)
        checked=loads(raw);require(checked["status"]=="COMPLETE_ORIGINAL_NAMESPACE_RECOVERED_READ_PASS","precise recovered original build")
        require(source()==identity,"complete frozen recovery source unchanged")
        metadata.update(status="NAMESPACE_VERSIONS_ORIGINAL_RECOVERED_BUILD_PASS",evidence=checked,processes=recorder.records,
            restore=loads(read(output/"RESTORE.json")),retained_original_failure=loads(read(workspace/"original/run/BUILD.json")),
            namespace_version_qualified=False,public_handler_qualified=False)
        (output/"GATE.json").write_bytes(encoded(metadata));(output/"RECOVERY.json").write_bytes(encoded(metadata))
        print("NAMESPACE_ORIGINAL_RECOVERY_BEGIN");print(encoded(metadata).decode(),end="");print("NAMESPACE_ORIGINAL_RECOVERY_END")
    except BaseException as error:
        metadata.update(status="FAIL",exception=repr(error),processes=recorder.records)
        (output/"RECOVERY.json").write_bytes(encoded(metadata));raise
    finally:
        for row in recorder.records:
            path=output/"processes"/row["stderr"]["file"]
            if path.exists()and path.stat().st_size:sys.stderr.buffer.write(read(path))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);a=p.parse_args();run(a.workspace.resolve(strict=True))
