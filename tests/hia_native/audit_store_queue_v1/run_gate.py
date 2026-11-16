"""Fresh fixed-source audit queue gate, preserving every child and failure."""
from pathlib import Path
import argparse,json,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from build import verify_source
from process import Recorder,put
def run(hepta,rust_bin,output):
    source=verify_source();started=time.monotonic()
    output.mkdir(parents=True,exist_ok=False)
    report=dict(schema="hepta.runtime.audit-store-queue.gate.v2",status="RUNNING",
        source_manifest_sha256=source,execution_source_root=str(ROOT),execution_output_root=str(output),
        hepta_root=str(hepta),rust_bin=str(rust_bin),whole_runtime_replaced=False)
    put(output/"GATE.json",report);rec=Recorder(ROOT,output/"processes")
    try:
        commands=[
          ("native-build",[sys.executable,"-I","-B",ROOT/"build.py","--hepta",hepta,"--output",output/"build"],180),
          ("native-domain",[sys.executable,"-I","-B",ROOT/"run_native.py","--build",output/"build","--output",output/"native"],180),
          ("original",[sys.executable,"-I","-B",ROOT/"original.py","--rust-bin",rust_bin,"--output",output/"original"],900)]
        for name,argv,budget in commands:
            rec.run(name,argv,timeout=budget)
        report["status"]="CAPTURED";put(output/"GATE.json",report)
        reader=[sys.executable,"-I","-B",ROOT/"verify_readonly.py","--output",output,
                "--source-manifest-sha256",source]
        rec.run("readonly-baseline",reader,timeout=180)
        rec.run("reader-controls",[sys.executable,"-I","-B",ROOT/"reader_controls.py",
            "--capture",output,"--output",output/"reader-controls"],timeout=180)
        raw,_=rec.run("readonly-complete",reader+["--require-controls"],timeout=180)
        proof=json.loads(raw)
        report.update(status=proof["evidence"]["status"],evidence=proof["evidence"],
            readonly_guard_refusals=len(proof["probes"]),source_unchanged=verify_source()==source)
    except BaseException as exc:
        report.update(status="FAILED",error=dict(type=type(exc).__name__,message=str(exc)))
        raise
    finally:
        report["elapsed_seconds"]=time.monotonic()-started
        report["source_unchanged"]=verify_source()==source
        put(output/"GATE.json",report)
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--hepta",type=Path,required=True)
    p.add_argument("--rust-bin",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.rust_bin.resolve(strict=True),a.output.absolute())
