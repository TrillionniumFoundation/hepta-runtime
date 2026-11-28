"""Each actual strict reader/control phase retains its original 180-second budget."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,read,pin,require,source
from process import Recorder,environment
def run(phase,output):
    identity=source();env,_=environment(os.environ);recorder=Recorder(ROOT,output/"reader-processes"/phase,env)
    report=output/(phase+"-read.json")
    if phase=="controls":command=[sys.executable,"-I","-B",ROOT/"run_reader_controls.py","--capture",output/"semantic","--output",output/"controls"]
    else:
        command=[sys.executable,"-I","-B",ROOT/"reader_cli.py","--capture",output/"semantic","--receipt",report]
        if phase=="final":command+=["--controls",output/"controls"]
    try:
        raw,record=recorder.run("readonly-"+phase,command,timeout=180)
        print(raw.decode(),end="")
        if phase=="final":
            proof=loads(read(report));evidence=proof["evidence"]
            require(proof["before"]==proof["after"] and evidence["status"]=="PASS" and source()==identity,"same frozen source full final evidence")
            gate=dict(schema="hepta.audit-pinned-anchor.gate.v1",status="PASS",source_manifest_sha256=identity,cases=evidence["observed"]["cases"],
                operations=evidence["observed"]["operations"],observer_off_cases=evidence["observer_off"]["cases"],observer_off_operations=evidence["observer_off"]["operations"],
                transport_controls=evidence["transport_controls"],owner_controls=evidence["owner_controls"],reader_controls=evidence["controls"],
                final_read=pin(read(report)),final_process=pin(read(output/"reader-processes/final/processes.json")),
                fresh_original_comparison=True,native_or_rust_executions_in_reader=0,
                archive_store_qualified=False,hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
            (output/"GATE.json").write_bytes(encoded(gate))
    finally:
        error=recorder.directory/("readonly-"+phase+".stderr")
        if error.is_file():sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--phase",choices=("semantic","controls","final"),required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.phase,a.output.resolve(strict=True))
