"""Bounded CI-only driver; preserves complete failed or successful stages."""
from pathlib import Path
import argparse,json,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from common import source,read,pin,put
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();identity=source(a.source_manifest_sha256)
    assert not a.output.exists();a.output.mkdir(parents=True);out=a.output.resolve()
    rec=Recorder(ROOT,out/"processes");started=time.monotonic();status="FAIL";failure=None;stage="build"
    try:
        raw,row=rec.run("build",[sys.executable,"-I","-B",ROOT/"build_native.py","--hepta",a.hepta,
            "--output",out/"build","--source-manifest-sha256",identity],timeout=900)
        print(raw.decode(),end="",flush=True);stage="native"
        raw,row=rec.run("native",[sys.executable,"-I","-B",ROOT/"native_runner.py","--build",out/"build",
            "--output",out/"native","--source-manifest-sha256",identity],timeout=60)
        print(raw.decode(),end="",flush=True);stage="read-only-admission"
        raw,row=rec.run("read-only-admission",[sys.executable,"-I","-B",ROOT/"verify_readonly.py","--build",out/"build",
            "--native",out/"native","--proof",out/"admission.json","--source-manifest-sha256",identity],timeout=180)
        print(raw.decode(),end="",flush=True);stage="physical-controls"
        raw,row=rec.run("physical-controls",[sys.executable,"-I","-B",ROOT/"controls.py","--build",out/"build",
            "--native",out/"native","--output",out/"controls","--source-manifest-sha256",identity],timeout=180)
        print(raw.decode(),end="",flush=True);assert source()==identity;status="PASS";stage="complete"
    except BaseException as error:
        failure=dict(error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
        raise
    finally:
        report=dict(schema="hepta.runtime.engine-layout.gate.v1",status=status,stage=stage,failure=failure,
            source_manifest_sha256=identity,elapsed_seconds=time.monotonic()-started,processes=rec.records,
            private_storage_only=True,public_tools=False,whole_runtime_replaced=False)
        put(out/"GATE.json",report)
if __name__=="__main__":main()
