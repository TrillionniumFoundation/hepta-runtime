#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent uploaded capture qualification; never execute original applications."""
from pathlib import Path
import argparse,sys,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,need,unpack,pin
from common import source_evidence
import read_capture
from inspect_probes import failure
def main():
    p=argparse.ArgumentParser()
    for n in("source","native","original","stage","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();sys.addaudithook(read_capture.deny_application)
    need(not a.stage.exists()and not a.output.exists(),"fresh pure uploaded reading outputs");a.stage.mkdir();a.output.mkdir()
    binding=source_evidence(a.source);inputs=decode((a.source/"UPLOADED.json").read_bytes());roots={}
    for side,path in(("native",a.native),("original",a.original)):roots[side]=unpack(path,a.stage/side,inputs[side])
    (a.output/"UPLOADED_INPUTS.json").write_bytes(canonical(inputs))
    sys.argv=[str(Path(read_capture.__file__)),"--source",str(a.source),"--native",str(roots["native"]),"--original",str(roots["original"]),
        "--stage",str(a.stage/"compiled"),"--output",str(a.output/"comparison")]
    try:read_capture.main()
    except Exception as error:
        detail,summary=failure(error);(a.output/"FAILED_CHECK.json").write_bytes(canonical(detail))
        print("RETAINED_PURE_CHECK_FAILURE "+canonical(dict(error=detail["error"],**summary)).decode(),end="");raise
    need(source_evidence(a.source)==binding,"frozen pure reading source changed")
    result=dict(status="UPLOADED_SSH_NINE_LIFECYCLE_CASES_PASS",comparison=pin(a.output/"comparison/EVIDENCE.json"),
        uploaded_inputs=inputs,source=binding,new_applications=0,application_replays=0,old_pure_failures_preserved=True,
        public_ssh=False,first_four_independently_complete=True,remaining_domain_cases=[])
    (a.output/"RESULT.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
