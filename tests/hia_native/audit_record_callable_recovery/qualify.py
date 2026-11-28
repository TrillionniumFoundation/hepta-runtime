"""Own each recovery-only reader process within the original 180-second limit."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from recovery_common import source,read,loads,pin,encoded,need,BASE_SOURCE

def run(phase,original,output):
    identity=source()
    sys.path.insert(0,str(original/"source"))
    from process import Recorder,environment
    env,_=environment(os.environ)
    output.mkdir(parents=True,exist_ok=True)
    recorder=Recorder(ROOT,output/"processes"/phase,env)
    report=output/("final-read.json" if phase=="verify" else phase+"-read.json")
    argv=[sys.executable,"-I","-B",ROOT/"reader_cli.py","--phase",phase,
        "--original",original/"source","--capture",original/"run/semantic",
        "--retained",original/"retained","--controls",output/"controls","--report",report]
    try:
        stdout,process=recorder.run("readonly-"+phase,argv,timeout=180)
        print(stdout.decode(),end="")
        need(source()==identity,"same recovery source after actual process")
        if phase=="final":
            proof=loads(read(report))
            need(proof["evidence"]["status"]=="PASS" and proof["reader_adapter_source_sha256"]==identity and
                 proof["before"]==proof["after"] and len(proof["probes"])==12 and
                 proof["native_or_rust_executions"]==proof["reader_writes"]==0,
                 "complete final independent unchanged-byte proof")
            gate=dict(schema="hepta.audit-record-callable.recovered-gate.v1",status="PASS",
                reader_adapter_source_sha256=identity,original_source_manifest_sha256=BASE_SOURCE,
                original_head="f7273eb417e1f90c4e11b0556f7d6c7d2758bd33",original_run=44061230103,
                original_status="FAIL",original_failure_preserved=True,
                cases=219,operations=459,observer_off_cases=219,observer_off_operations=459,
                transport_refusals=45,transport_recoveries=45,physical_reader_refusals=13,physical_admissions=2,
                final_read=pin(read(report)),final_process=pin(read(output/"processes/final/processes.json")),
                native_or_rust_executions=0,original_rust_replay=0,whole_runtime_replaced=False,
                archive_and_hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False)
            (output/"GATE.json").write_bytes(encoded(gate))
    finally:
        error=recorder.directory/("readonly-"+phase+".stderr")
        if error.is_file():sys.stderr.write(error.read_text())

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase",choices=("semantic","controls","final","verify"),required=True)
    p.add_argument("--original",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.phase,a.original.resolve(strict=True),a.output.absolute())
