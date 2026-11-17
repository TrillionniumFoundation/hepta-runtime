#!/usr/bin/env python3
"""Run each frozen real process once, retaining every byte even on failure."""
from pathlib import Path
import argparse,sys,time,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder,environment
def capture(source,build,runtime,output,role):
    identity=source_evidence(source);domain=decode((source/"DOMAIN.json").read_bytes())
    require(not output.exists(),"fresh actual role capture");output.mkdir(parents=True)
    env,environment_binding=environment(__import__("os").environ)
    recorder=Recorder(source,output/"processes",env);completed=[];began=time.monotonic()
    base=dict(schema="hepta.runtime.binary-entropy.actual-role.v1",role=role,source=identity,
        source_origin=str(source),build_origin=str(build),runtime_origin=str(runtime),output_origin=str(output),
        python_executable=sys.executable,environment=environment_binding,application_deadline_seconds=60)
    try:
        for case in domain["cases"]:
            require(time.monotonic()-began<100,"controller has no full remaining 60-second application window")
            folder=output/case["name"];folder.mkdir()
            name=role+"-"+case["name"]
            raw,process=recorder.run(name,[sys.executable,"-I","-S","-B",source/"scripts/worker.py",
                "--source",source,"--build",build,"--runtime",runtime,"--output",folder,
                "--role",role,"--case",case["name"]],timeout=60)
            require(raw==b""and process["stderr"]["bytes"]==0,"no hidden actual process diagnostic")
            files={p.name:dict(**pin(p),mode=p.stat().st_mode&0o777)for p in folder.iterdir()}
            require(set(files)=={"events.bin","results.jsonl","foreign-file"},"complete fixed actual files")
            completed.append(dict(case=case["name"],process=process,files=files))
            (output/"CAPTURE.json").write_bytes(encoded(dict(**base,status="RUNNING",completed=completed,
                processes=recorder.records)))
        result=dict(**base,status="PASS",completed=completed,processes=recorder.records,
            application_calls=sum(len(q["modes"])for q in domain["cases"]))
        (output/"CAPTURE.json").write_bytes(encoded(result))
        require(source_evidence(source)==identity,"source changed during actual capture")
        return result
    except BaseException as exc:
        (output/"CAPTURE.json").write_bytes(encoded(dict(**base,status="FAIL",completed=completed,
            processes=recorder.records,error_type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc(),
            remaining_inputs_not_executed=True,unknown_inputs_never_replayed=True)))
        raise
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in("source","build","runtime","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--role",choices=["original","native"],required=True);a=p.parse_args()
    result=capture(a.source.resolve(strict=True),a.build.resolve(strict=True),a.runtime.resolve(strict=True),
        a.output.absolute(),a.role)
    print(encoded(dict(status=result["status"],role=a.role,processes=len(result["processes"]),
        application_calls=result["application_calls"])).decode(),end="")
