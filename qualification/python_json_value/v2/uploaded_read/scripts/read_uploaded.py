#!/usr/bin/env python3
"""Independently read original uploaded decoder archives with no application replay."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import encoded,source_evidence,require
from readonly import guarded
import restore_uploaded
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    work=a.work.resolve(strict=True);before=source_evidence(ROOT);bound=restore_uploaded.selection(ROOT,a.group)
    trusted=ROOT/"trusted-qualification";source_evidence(trusted)
    # Admit every archived source byte before preparing only the frozen pure readers.
    admitted=restore_uploaded.verify(ROOT,work/"semantic",bound)
    sys.path.insert(0,str(trusted/"scripts"))
    import read_evidence
    source=work/"semantic/original/restored/source";capture=work/"semantic/original/restored/run"
    module=read_evidence.prepare(trusted,capture)
    def full():
        archive=restore_uploaded.verify(ROOT,work/"semantic",bound)
        require(archive==admitted,"whole uploaded archive stable before independent read")
        qualification=read_evidence.verify(source,capture,module)
        require(qualification["status"]=="COMPLETE_UPLOADED_PYTHON_JSON_VALUE_EVIDENCE_PASS","all complete original guarded records")
        return dict(status="COMPLETE_INDEPENDENT_UPLOADED_JSON_VALUE_PASS",group=a.group,
            archive=archive,qualification=qualification,new_application_calls=0,new_physical_controls=0)
    result=guarded(full,roots=[ROOT,work/"semantic"])
    require(source_evidence(ROOT)==before,"independent reader source unchanged")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
