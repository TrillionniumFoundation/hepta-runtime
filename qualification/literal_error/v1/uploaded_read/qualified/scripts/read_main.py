#!/usr/bin/env python3
"""One complete nonexecuting read, including every retained message and arena tail."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,owned,require
from readonly import guarded
import read_capture
def roots(source,application,runtime,legacy,admission):
    return [source,application,runtime,admission.parent,legacy/"original",legacy/"processes"]
def main():
    p=argparse.ArgumentParser()
    for name in("source","application","runtime","legacy","admission"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--expected-error");a=p.parse_args()
    source,application,runtime,legacy,admission=[getattr(a,k).resolve(strict=True)
        for k in("source","application","runtime","legacy","admission")]
    def operation():
        saved=decode(admission.read_bytes())
        require(saved["status"]=="FULL_ARCHIVE_ADMISSION_PASS","frozen admitted upstream archives")
        try:
            result=read_capture.verify(source,application,runtime,legacy,saved["legacy_identity"],saved["runtime"])
        except ValueError as error:
            require(a.expected_error is not None and str(error)==a.expected_error,
                "physical refusal differs from frozen target: "+str(error))
            return dict(status="EXPECTED_PHYSICAL_REFUSAL",reason=str(error),new_application_calls=0)
        require(a.expected_error is None,"physically corrupted complete evidence was accepted")
        return result
    value=guarded(operation,roots=roots(source,application,runtime,legacy,admission))
    print(canonical(value).decode(),end="")
if __name__=="__main__":main()
