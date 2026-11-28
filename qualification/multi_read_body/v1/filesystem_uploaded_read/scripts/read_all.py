#!/usr/bin/env python3
"""Independently read every uploaded file, original capture and retained physical proof."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,owned,pin,require,source_evidence
sys.path.insert(0,str(ROOT/"trusted-reader/scripts"))
import build_reuse,read_recovery,read_qualification
from read_build_evidence import tree
from readonly import guarded
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    a=p.parse_args();work=a.work.resolve(strict=True);semantic=work/"semantic";reuse=work/"build"
    bound=decode(owned(ROOT,"UPLOAD_BINDING.json").read_bytes())["groups"][a.group]
    is_recovery=bound["kind"]=="recovered"
    require(is_recovery or bound["kind"]=="original","exact qualification profile")
    recovery=work/"recovery"
    build_reuse.prepare_imports(reuse)
    def operation():
        identity=source_evidence(ROOT);base=semantic/"original/restored";source=base/"source"
        require((source/"SOURCE_MANIFEST.json").read_bytes()==
            (ROOT/"trusted-reader/ORIGINAL_SOURCE_MANIFEST.json").read_bytes(),"all 139 original source rows")
        source_evidence(source)
        if is_recovery:
            recovered=recovery/"original/restored";reader=recovered/"source";capture=recovered/"run"
            require(source_evidence(reader)==source_evidence(ROOT/"trusted-reader")
                and tree(reader)[1]==tree(ROOT/"trusted-reader")[1],"complete recovered and frozen reader bytes")
            archive=decode(owned(recovery/"original","ARTIFACT_MANIFEST.json").read_bytes())
            require(archive["git_head"]==bound["commit"] and archive["schema"]==bound["archive_schema"]
                and archive["gate_status"]=="PASS","exact uploaded recovery admission")
            value=read_recovery.completed(reader,semantic,reuse,capture,a.group)
            actual=value["evidence"]["actual"]
            require(value["evidence"]["physical_refusals"]==8 and value["evidence"]["full_relocations"]==2
                and value["new_original_or_native_applications"]==0,"all recovery controls and zero replay")
        else:
            require((source/"scripts/read_qualification.py").read_bytes()==
                (ROOT/"scripts/read_qualification.py").read_bytes(),"exact complete original successful proof reader")
            archive=decode(owned(semantic/"original","ARTIFACT_MANIFEST.json").read_bytes())
            require(archive["git_head"]==bound["commit"] and archive["schema"]==bound["archive_schema"]
                and archive["gate_status"]=="PASS","exact original successful upload")
            value=read_qualification.verify(source,base/"run",a.group,reuse);actual=value["actual"]
            require(value["physical_refusals"]==8 and value["complete_relocations"]==2
                and value["new_application_executions"]==0,"all retained original controls and zero replay")
        summary=bound["actual"]
        require(actual["group"]==a.group and actual["cases"]==summary["cases"]
            and actual["original"]["entry_invocations"]==summary["original_invocations"]
            and actual["native"]["entry_invocations"]==summary["native_invocations"]
            and actual["native"]==summary["native"],"all retained actual invocation and complete-buffer counts")
        return dict(status="INDEPENDENT_COMPLETE_UPLOADED_MULTI_FILESYSTEM_PASS",group=a.group,source=identity,
            complete_profile=bound["kind"],complete=value,actual=actual,uploaded_binding=bound,
            first_failure_preserved=is_recovery,new_original_or_native_applications=0,
            new_physical_control_executions=0,public_routes_qualified=False,whole_runtime_replaced=False)
    roots=[ROOT]
    for part in ([recovery] if is_recovery else [])+[semantic,reuse]:
        roots.extend([part/"original",part/"download"])
    result=guarded(operation,roots=roots)
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
