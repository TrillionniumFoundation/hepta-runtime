"""Run one independently owned pure reader within the original 180 seconds."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from independent_support import source,read,loads,encoded,pin,need

def run(capture,output):
    identity=source();output.mkdir(parents=True,exist_ok=True)
    sys.path.insert(0,str(capture/"original/source"))
    from process import Recorder,environment
    import os
    env,_=environment(os.environ)
    recorder=Recorder(ROOT,output/"processes",env)
    try:
        stdout,row=recorder.run("independent-read",
            [sys.executable,"-I","-B",ROOT/"reader.py","--capture",capture,
             "--report",output/"FULL_GUARD.json"],timeout=180)
        value=loads(stdout)
        need(value["status"]=="PASS" and value["native_or_rust_executions"]==value["reader_writes"]==0 and
             value["guard_probes"]==12 and value["independent_source_sha256"]==identity and
             value["all_entry_bytes_and_metadata_unchanged"] is True and
             value["complete_guard"]==pin(read(output/"FULL_GUARD.json")) and source()==identity,
             "entire actual independent pure process")
        result=dict(value,process=row,original_status="FAIL")
        (output/"RESULT.json").write_bytes(encoded(result))
        print(encoded(result).decode(),end="")
    finally:
        error=recorder.directory/"independent-read.stderr"
        if error.is_file():sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--capture",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.capture.resolve(strict=True),a.output.absolute())
