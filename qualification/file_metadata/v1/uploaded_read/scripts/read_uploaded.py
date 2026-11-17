#!/usr/bin/env python3
"""Read all uploaded application evidence and its qualified upstream build; no replay."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,source_evidence,require
from readonly import guarded
import restore_semantic
sys.path.insert(0,str(ROOT/"trusted-qualification/scripts"))
import read_evidence,read_capture,build_reuse,read_build_evidence
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    work=a.work.resolve(strict=True);before=source_evidence(ROOT);bound=restore_semantic.selection(ROOT,a.group)
    source=work/"semantic/original/restored/source";capture=work/"semantic/original/restored/run"
    build_reuse.prepare_imports(work/"upstream")
    def full():
        archive=restore_semantic.verify(ROOT,work/"semantic",bound)
        qualification=read_evidence.verify(source,capture,a.group,work/"upstream")
        return dict(status="COMPLETE_INDEPENDENT_UPLOADED_METADATA_PASS",archive=archive,qualification=qualification,application_executions=0)
    result=guarded(full,roots=[ROOT,work/"semantic",work/"upstream"])
    require(source_evidence(ROOT)==before,"independent reader source changed")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
