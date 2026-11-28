#!/usr/bin/env python3
"""Recover complete captured items without changing the retained failed producer."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,source_evidence,require,owned,pin
from readonly import guarded
from guard_refs import tree,saved_guard
import restore_uploaded,read_recovered_evidence,controls
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["read","controls","verify"])
    p.add_argument("--work",type=Path,required=True);a=p.parse_args();work=a.work.resolve(strict=True)
    identity=source_evidence(ROOT);bound=restore_uploaded.selection(ROOT,"0")
    source=work/"semantic/original/restored/source";capture=work/"semantic/original/restored/run";proof=work/"proof"
    admission=restore_uploaded.verify(ROOT,work/"semantic",bound)
    module=read_recovered_evidence.prepare(source,capture)
    def captured():
        archive=restore_uploaded.verify(ROOT,work/"semantic",bound)
        require(archive==admission,"complete retained archive unchanged")
        recovered=read_recovered_evidence.verify(source,capture,module)
        return dict(status="COMPLETE_INDEPENDENT_RECOVERED_JSON_ITEMS_PASS",group="0",
            archive=archive,qualification=recovered,new_application_calls=0,new_physical_controls=0)
    if a.stage=="read":
        result=guarded(captured,roots=[ROOT,work/"semantic"])
    else:
        prior=decode(owned(proof,"READONLY.json").read_bytes());baseline=prior["evidence"]["qualification"]["actual"]
        args=(source,capture/"application",capture/"runtime",capture/"original-runtime",
            capture/"admission/ADMISSION.json",proof/"controls",baseline)
        if a.stage=="controls":
            require(not(proof/"controls").exists(),"physical controls have never been executed")
            result=controls.create(*args)
        else:
            def full():
                current=captured();require(current==prior["evidence"],"complete retained recovery unchanged")
                references=saved_guard(prior,{str(ROOT):tree(ROOT),str(work/"semantic"):tree(work/"semantic")})
                physical=controls.verify(*args)
                require(physical["refusals"]==8 and physical["relocations"]==2,"all first physical controls")
                return dict(status="COMPLETE_RECOVERED_JSON_ITEMS_AND_PHYSICAL_PASS",recovered=current,
                    physical=physical,saved_recovery_guard_file_references=references,
                    new_application_calls=0,physical_controls_reexecuted=False)
            result=guarded(full,roots=[ROOT,work/"semantic",proof/"controls"])
    require(source_evidence(ROOT)==identity,"source bytes unchanged during pure recovery")
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
