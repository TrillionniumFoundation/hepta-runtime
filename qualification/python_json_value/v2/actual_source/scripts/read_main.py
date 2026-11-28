#!/usr/bin/env python3
"""Guard complete retained decoder comparison; never load native code."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,require
import read_capture,cases
from readonly import guarded
def main():
    p=argparse.ArgumentParser()
    for k in("source","application","runtime","original-runtime","admission"):p.add_argument("--"+k,type=Path,required=True)
    p.add_argument("--expected-error");a=p.parse_args()
    source,application,runtime,original_runtime,admission=map(lambda p:p.resolve(strict=True),
        (a.source,a.application,a.runtime,a.original_runtime,a.admission))
    cases.domain()
    def operation():
        try:value=read_capture.verify(source,application,runtime,original_runtime,admission)
        except ValueError as error:
            require(a.expected_error is not None and str(error)==a.expected_error,"unexpected evidence refusal: "+str(error))
            return dict(status="EXPECTED_PHYSICAL_REFUSAL",reason=a.expected_error,new_application_calls=0)
        require(a.expected_error is None,"expected physical refusal was accepted");return value
    value=guarded(operation,roots=[source,application,runtime,original_runtime,admission.parent])
    print(canonical(value).decode(),end="")
if __name__=="__main__":main()
