#!/usr/bin/env python3
"""Read every uploaded byte, original strict readers, all full buffers and saved controls."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,source_evidence,require
from readonly import guarded
import restore_uploaded
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    work=a.work.resolve(strict=True);before=source_evidence(ROOT);bound=restore_uploaded.selection(ROOT,a.group)
    require(bound["profile"]=="actual","fixed retained source profile")
    # These imports are the complete frozen Git readers, not code selected by archive content.
    trusted=ROOT/"trusted-qualification"/bound["profile"]
    source_evidence(trusted)
    sys.path.insert(0,str(trusted/"scripts"))
    import read_all,reader_controls
    sys.path.insert(0,str(ROOT/"scripts"))
    import read_failed_evidence
    source=work/"semantic/original/restored/source";capture=work/"semantic/original/restored/run"
    read_all.prepare(capture/"capture")
    def full():
        archive=restore_uploaded.verify(ROOT,work/"semantic",bound)
        qualification=read_failed_evidence.verify(source,capture,a.group)
        require(qualification["status"]=="COMPLETE_ORIGINAL_STDIO_READ67_CAPTURE_RECOVERY_PASS","all original guarded qualification records")
        return dict(status="COMPLETE_INDEPENDENT_UPLOADED_STDIO_READ67_PASS",group=a.group,profile=bound["profile"],
            archive=archive,qualification=qualification,new_application_calls=0,new_physical_controls=0)
    result=guarded(full,roots=[ROOT,work/"semantic"])
    require(source_evidence(ROOT)==before,"independent source unchanged")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
