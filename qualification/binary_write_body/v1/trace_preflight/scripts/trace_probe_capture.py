#!/usr/bin/env python3
"""Capture one frozen observer probe; semantic decisions belong to the separate reader."""
from pathlib import Path
import argparse,os,sys,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,pin,require,source_evidence
from buffer_store import Writer
from carrier import Carrier
from protocol import U,proc_fds
class Hooks:
    def __init__(self,pid,store):self.pid=pid;self.store=store;self.rows=[]
    def consume(self,raw):
        require(raw==b"HBWTEOF1"+bytes(56),"fixed observer probe EOF witness")
        self.rows.append(dict(raw=self.store.put(raw),ack=self.store.put(bytes(8)),fds=proc_fds(self.pid)))
        return bytes(8)
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--case",type=int,required=True);a=p.parse_args();source=a.source.resolve(strict=True)
    identity=source_evidence(source);case=decode((source/"PROBE_DOMAIN.json").read_bytes())["cases"][a.case]
    require(case["id"]==a.case,"frozen observer probe case")
    out=a.output.absolute();out.mkdir(parents=True,exist_ok=False);store=Writer(out/"buffers")
    executable=Path(sys.executable).resolve(strict=True)
    carrier=Carrier(executable,out,store,argv=[executable,"-I","-S","-B",source/"scripts/trace_probe_worker.py"])
    hooks=Hooks(carrier.pid,store);carrier.hooks=hooks
    try:
        moved=None
        if case["kind"]=="fd-zero":
            raw,moved=carrier.exchange(17,0);require(U(raw,8)==0,"actual probe FD-zero control move")
        concrete=dict(case,path=str(out/"probe.file"))
        raw,number=carrier.exchange(1,0,encoded(concrete),application=True)
        require(U(raw,8)==0 and U(raw,24)==2,"actual complete probe response")
        result=decode(raw[64:]);before_eof=proc_fds(carrier.pid);receipt=carrier.finish()
        record=dict(status="CAPTURED",case=case,concrete=concrete,result=result,exchange=number,
            control_move=moved,receipt=receipt,eof=hooks.rows,fds_before_eof=before_eof,source=identity,
            file=pin(out/"probe.file"),file_hex=(out/"probe.file").read_bytes().hex(),
            buffers=dict(images=store.images,logical_bytes=store.logical_bytes,blocks=len(store.known)),
            target_hia_application_calls=0,original_write_application_calls=0,observer_probe_calls=1)
        (out/"CAPTURE.json").write_bytes(encoded(record));require(source_evidence(source)==identity,"observer source changed")
        print(encoded(dict(status="CAPTURED",case=case["kind"],observer_probe_calls=1,target_hia_application_calls=0,
            original_write_application_calls=0)).decode(),end="")
    except BaseException as e:
        carrier.cleanup();(out/"FAILURE.json").write_bytes(encoded(dict(status="FAIL",case=case,source=identity,
            error_type=type(e).__name__,error=str(e),traceback=traceback.format_exc(),
            actual_probe_status="UNKNOWN_UNLESS_COMPLETE_CAPTURE_PRESENT",target_hia_application_calls=0,
            original_write_application_calls=0)));raise
if __name__=="__main__":main()
