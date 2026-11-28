"""Run only the previously skipped pure readers/physical evidence controls."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import recovery_common as rc
def run(prior,output,phase):
    identity=rc.source();original=prior/"source";capture=prior/"run/semantic"
    sys.path.insert(0,str(original))
    import common
    rc.check(common.source()=="925dede1dfdd747371c7101ad3cb7a2075e59c57d6326312737c71098ff9ecbf","frozen original source before importing recorder")
    from process import Recorder,environment
    output.mkdir(parents=True,exist_ok=True)
    env,_=environment(os.environ)
    rec=Recorder(ROOT,output/"processes"/phase,env)
    receipt=output/(phase+".json")
    command=[sys.executable,"-I","-B",ROOT/"reader.py","--phase",phase,"--original-source",original,"--capture",capture,"--receipt",receipt]
    if phase in ("controls","final"):command+=["--controls",output/"controls"]
    try:
        raw,row=rec.run("pure-"+phase,command,timeout=180)
        print(raw.decode(),end="")
        rc.check(rc.source()==identity,"unchanged recovery source after actual bounded reader")
        if phase=="final":
            proof=rc.loads(rc.read(receipt));value=proof["evidence"]["complete_evidence"]
            rc.check(value["status"]=="PASS" and proof["before"]==proof["after"] and len(proof["probes"])==12,"full final guarded result")
            process_rows={}
            for stage in ("semantic","controls","final"):
                records=rc.loads(rc.read(output/"processes"/stage/"processes.json"))
                rc.check(len(records)==1,"one bounded reader per fixed phase")
                item=records[0]
                argv=[sys.executable,"-I","-B",str(ROOT/"reader.py"),"--phase",stage,"--original-source",str(original),"--capture",str(capture),"--receipt",str(output/(stage+".json"))]
                if stage in ("controls","final"):argv+=["--controls",str(output/"controls")]
                rc.check(item["name"]=="pure-"+stage and item["argv"]==argv and item["cwd"]==str(ROOT) and item["timeout_seconds"]==180 and type(item["timeout_seconds"]) is int
                    and item["exit_code"]==0 and type(item["exit_code"]) is int and item["completed"] is True and item["timed_out"] is False and item["stdin"] is None
                    and type(item["elapsed_seconds"]) in (int,float) and 0<item["elapsed_seconds"]<=180
                    and all(type(item[k]) is int and item[k]>1 for k in ("pid","parent_pid","pgid")) and item["pgid"]==item["pid"]!=item["parent_pid"],"all actual retained bounded pure reader process custody")
                actual=rc.loads(rc.read(output/(stage+".json")))
                expected_stdout=actual if stage=="controls" else {k:v for k,v in actual.items() if k not in ("before","after")}
                for stream in ("stdout","stderr"):
                    filename="pure-"+stage+"."+stream;body=rc.read(output/"processes"/stage/filename)
                    rc.check(item[stream]==dict(file=filename,**rc.pin(body)) and body==(rc.enc(expected_stdout) if stream=="stdout" else b""),"complete actual pure reader streams")
                process_rows[stage]=dict(process=rc.pin(rc.read(output/"processes"/stage/"processes.json")),receipt=rc.pin(rc.read(output/(stage+".json"))))
            gate=dict(schema="hepta.audit-pinned-anchor.reader-recovery.v1",status="PASS",processes=process_rows,
                prior_status="FAIL",prior_head="a30d3e93185e84ee2a0e8c4abbdcc0d23177676a",
                source_sha256=identity,original_source_sha256=value["source_manifest_sha256"],
                cases=value["observed"]["cases"],operations=value["observed"]["operations"],
                observed=value["observed"],observer_off=value["observer_off"],original=value["original"],
                transport_controls=value["transport_controls"],owner_controls=value["owner_controls"],reader_controls=value["controls"],
                final_receipt=rc.pin(rc.read(receipt)),native_executions=0,rust_executions=0,
                archive_store_qualified=False,hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False)
            (output/"GATE.json").write_bytes(rc.enc(gate))
    finally:
        error=rec.directory/("pure-"+phase+".stderr")
        if error.is_file():sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--prior",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--phase",choices=("semantic","controls","final"),required=True);a=p.parse_args()
    run(a.prior.resolve(strict=True),a.output.absolute(),a.phase)
