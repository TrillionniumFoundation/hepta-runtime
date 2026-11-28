"""One bounded worker per frozen group; complete groups are never replayed."""
from pathlib import Path
import sys,time,traceback
sys.dont_write_bytecode=True
from common import canonical,decode,pin,require,source_evidence
from process import Recorder
import cases
def run(source,runtime,output):
    source=Path(source).resolve(strict=True);runtime=Path(runtime).resolve(strict=True);output=Path(output).absolute()
    require(not output.exists(),"fresh actual literal capture")
    output.mkdir();identity=source_evidence(source);domain=cases.validate()
    origin=dict(source=str(source),capture=str(output),runtime=str(runtime),python=sys.executable)
    (output/"ORIGIN.json").write_bytes(canonical(origin))
    recorder=Recorder(source,output/"processes");done=[];current=None;began=time.monotonic()
    plan=[("original",g["name"])for g in cases.domain()["new_groups"]]
    plan+=[("native",g["name"])for g in cases.groups()]+[("native","controls")]
    def save(status,error=None):
        value=dict(status=status,source=identity,domain=domain,completed=done,processes=recorder.records,
            current=current,error=error,planned_groups=len(plan),application_replays=0,
            completed_or_unknown_never_replayed=True,legacy_original_applications=0)
        (output/"CAPTURE.json").write_bytes(canonical(value))
        return value
    save("PENDING")
    try:
        for role,group in plan:
            require(time.monotonic()-began<540,"stop before another group to retain workflow export budget")
            current=dict(role=role,group=group);save("RUNNING")
            command=[sys.executable,"-I","-S","-B",source/"scripts"/(role+"_capture.py"),
                "--group",group,"--output",output/role/group]
            if role=="native":command+=["--capture",runtime]
            raw,record=recorder.run(role+"-"+group,command,timeout=60)
            value=decode(raw)
            count=len(cases.controls())if group=="controls"else len(list(cases.cases(group)))
            require(value["status"]=="PASS"and value["cases"]==count and value["group"]==group,
                "actual worker completed its entire frozen group")
            done.append(dict(role=role,group=group,cases=count,process=record["name"],
                capture=pin(output/role/group/"CAPTURE.json")))
            current=None;save("RUNNING")
        totals=dict(new_original_calls=sum(r["cases"]for r in done if r["role"]=="original"),
            native_semantic_calls=sum(r["cases"]for r in done if r["role"]=="native"and r["group"]!="controls"),
            private_native_calls=sum(r["cases"]for r in done if r["group"]=="controls"))
        require(totals==dict(new_original_calls=435,native_semantic_calls=22336,private_native_calls=1255),
            "complete declared actual application counts")
        result=save("PASS");result.update(totals);(output/"CAPTURE.json").write_bytes(canonical(result))
        require(source_evidence(source)==identity,"actual workers changed source")
        return result
    except BaseException as error:
        unknown=bool(recorder.records and recorder.records[-1]["timed_out"])
        save("UNKNOWN"if unknown else"FAIL",dict(type=type(error).__name__,message=str(error),
            traceback=traceback.format_exc(),unknown_group=current if unknown else None))
        raise
