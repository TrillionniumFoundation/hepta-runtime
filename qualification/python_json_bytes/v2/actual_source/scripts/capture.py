"""One bounded actual worker per frozen group; completed or unknown calls never replay."""
from pathlib import Path
import sys,time,traceback
sys.dont_write_bytecode=True
from common import canonical,decode,pin,require,source_evidence
from process import Recorder
import cases
def run(source,runtime,original_runtime,output,shard):
    source,runtime,original_runtime=map(lambda p:Path(p).resolve(strict=True),(source,runtime,original_runtime))
    output=Path(output).absolute();require(not output.exists(),"fresh JSON byte application capture");output.mkdir()
    identity=source_evidence(source);domain=cases.shard_domain(shard);plan=cases.plan(shard)
    origin=dict(source=str(source),capture=str(output),runtime=str(runtime),original_runtime=str(original_runtime),python=sys.executable)
    (output/"ORIGIN.json").write_bytes(canonical(origin))
    recorder=Recorder(source,output/"processes");done=[];current=None;began=time.monotonic()
    def save(status,error=None):
        value=dict(status=status,source=identity,domain=domain,completed=done,processes=recorder.records,
            current=current,error=error,planned_groups=len(plan),application_replays=0,
            completed_or_unknown_never_replayed=True)
        (output/"CAPTURE.json").write_bytes(canonical(value));return value
    save("PENDING")
    try:
        for role,group in plan:
            require(time.monotonic()-began<450,"stop before new applications to retain export budget")
            current=dict(role=role,group=group);save("RUNNING")
            command=[sys.executable,"-I","-S","-B",source/"scripts"/(role+"_capture.py"),
                "--group",group,"--output",output/role/group]
            command+=["--capture",runtime]if role=="native"else["--runtime",original_runtime]
            raw,record=recorder.run(role+"-"+group,command,timeout=60);value=decode(raw)
            count=30 if group=="controls"else next(r["cases"]for r in domain["groups"]if r["id"]==int(group))
            require(value["status"]=="PASS"and value["cases"]==count and value["group"]==group,"complete frozen actual group")
            done.append(dict(role=role,group=group,cases=count,process=record["name"],capture=pin(output/role/group/"CAPTURE.json")))
            current=None;save("RUNNING")
        result=save("PASS");result.update(new_original_calls=domain["semantic_cases"],
            native_semantic_calls=domain["semantic_cases"],private_native_calls=domain["private_native_calls"])
        (output/"CAPTURE.json").write_bytes(canonical(result))
        require(source_evidence(source)==identity,"actual workers changed frozen source");return result
    except BaseException as error:
        unknown=bool(recorder.records and recorder.records[-1]["timed_out"])
        save("UNKNOWN"if unknown else"FAIL",dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),
            unknown_group=current if unknown else None));raise
