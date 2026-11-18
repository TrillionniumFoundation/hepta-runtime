#!/usr/bin/env python3
"""Recover complete frozen original profiles; never run their JSON operations."""
import argparse,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,owned,pin,require,source_evidence
from reuse import same
import archive_restore,legacy_cases,legacy_verify,profile_read_archives
from readonly import guarded
def binding(source,group):
    return decode(owned(source,"PROFILE_INPUTS.json").read_bytes())["groups"][group]
def prepare(source,work,group):
    bound=binding(source,group);trusted=source/"trusted-profiles"/bound["family"]
    same(trusted,work/"original/restored/source")
    legacy_cases.set_source(trusted)
    "".encode("utf-32-le","surrogatepass")
    return trusted,bound
def verify(source,work,group):
    trusted,bound=prepare(source,work,group)
    require(pin(trusted/"SOURCE_MANIFEST.json")["sha256"]==bound["manifest_sha256"],"complete frozen original profile source")
    archive=profile_read_archives.verify(source,work,group)
    result=legacy_verify.verify(trusted,work/"original/restored/run",bound["profile_group"])
    require(result["profile"]["actual_calls"]==bound["original_cases"],"all original operations retained and read")
    return dict(status="COMPLETE_ORIGINAL_BOUNDARY_PROFILE_PASS",group=group,archive=archive,profile=result,new_original_calls=0,new_native_calls=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","unpack","read"])
    p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);work=a.work.resolve(strict=True);before=source_evidence(source)
    bound=binding(source,a.group)
    if a.stage in("fetch","unpack"):
        result=(archive_restore.fetch if a.stage=="fetch"else archive_restore.unpack)(work,bound)
    else:
        prepare(source,work,a.group)
        result=guarded(lambda:verify(source,work,a.group),roots=[source,work])
    require(source_evidence(source)==before,"frozen original profile admission unchanged")
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
