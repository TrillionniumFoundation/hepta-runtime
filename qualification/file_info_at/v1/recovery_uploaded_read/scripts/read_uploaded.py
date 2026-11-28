#!/usr/bin/env python3
"""Independent entire uploaded recovery admission, including every original captured byte."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,source_evidence,require
from readonly import guarded
import restore_recovery
sys.path.append(str(ROOT/"trusted-recovery/scripts"))
import read_recovery_evidence,read_retained,build_reuse
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    work=a.work.resolve(strict=True);before=source_evidence(ROOT);bound=restore_recovery.selection(ROOT,a.group)
    source=work/"recovery/original/restored/source";capture=work/"recovery/original/restored/run"
    build_reuse.prepare_imports(work/"upstream")
    def full():
        archive=restore_recovery.verify(ROOT,work/"recovery",bound)
        qualified=read_recovery_evidence.verify(source,capture,a.group,work/"upstream")
        return dict(status="COMPLETE_INDEPENDENT_UPLOADED_INFO_RECOVERY_PASS",archive=archive,qualification=qualified,applications_replayed=0)
    value=guarded(full,roots=[ROOT,work/"recovery",work/"upstream"])
    require(source_evidence(ROOT)==before,"independent source changed")
    print(encoded(value).decode(),end="")
if __name__=="__main__":main()
