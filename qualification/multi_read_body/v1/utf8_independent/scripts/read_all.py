#!/usr/bin/env python3
"""Independently read all three uploaded archives and the completed recovery proof."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,owned,pin,require,source_evidence
sys.path.insert(0,str(ROOT/"trusted-reader/scripts"))
import build_reuse,read_recovery
from read_build_evidence import tree
from readonly import guarded
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    a=p.parse_args();work=a.work.resolve(strict=True);recovery=work/"recovery";semantic=work/"semantic";reuse=work/"build"
    recovered=recovery/"original/restored";reader=recovered/"source";capture=recovered/"run"
    build_reuse.prepare_imports(reuse)
    def operation():
        identity=source_evidence(ROOT)
        require(source_evidence(reader)==source_evidence(ROOT/"trusted-reader")
            and tree(reader)[1]==tree(ROOT/"trusted-reader")[1],"complete uploaded and frozen recovery reader bytes differ")
        bound=decode(owned(ROOT,"UPLOAD_BINDING.json").read_bytes())["groups"][a.group]
        archive=decode(owned(recovery/"original","ARTIFACT_MANIFEST.json").read_bytes())
        require(archive["git_head"]==bound["commit"] and archive["schema"]==bound["archive_schema"]
            and archive["gate_status"]=="PASS","exact uploaded recovery admission")
        value=read_recovery.completed(reader,semantic,reuse,capture,a.group)
        actual=value["evidence"]["actual"];summary=bound["actual"]
        require(actual["original_decodes"]==summary["original_decodes"]
            and actual["actual_native_calls"]==summary["native_calls"]
            and actual["private_controls"]==summary["private_controls"],"retained actual counts")
        require(value["evidence"]["physical_refusals"]==8 and value["evidence"]["full_relocations"]==2
            and value["new_original_or_native_applications"]==0,"all physical controls and zero replay")
        return dict(status="INDEPENDENT_COMPLETE_UPLOADED_UTF8_PASS",group=a.group,source=identity,
            complete_recovery=value,uploaded_recovery_binding=bound,original_failure_preserved=True,
            new_original_or_native_applications=0,body_or_public_qualified=False)
    roots=[ROOT]
    for part in(recovery,semantic,reuse):roots.extend([part/"original",part/"download"])
    result=guarded(operation,roots=roots)
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
