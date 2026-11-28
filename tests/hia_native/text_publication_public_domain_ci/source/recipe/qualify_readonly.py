#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete read-only comparison, optional physical controls and two relocations."""
from pathlib import Path
import argparse,json,os,shutil,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"));sys.path.insert(0,str(ROOT))
from common import canonical,decode,require,source_evidence
import dependencies,read_public,public_reader_controls,readonly
from helper_source import prepare
def prepared():
    source=source_evidence(ROOT)
    prepare(ROOT/"retained/text75_qualify.py")
    read_public.old.retained_filesystem()
    return source
def run(capture,physical):
    capture=Path(capture).resolve(strict=True);prepared()
    first=readonly.guarded(lambda:read_public.read(capture),roots=(ROOT,capture))
    (capture.parent/(capture.name+"-readonly.json")).write_bytes(canonical(first))
    result=dict(comparison=first["evidence"],guard_probes=len(first["probes"]),reader_entries=first["entries"],
        native_executed=False,rust_executed=False)
    if physical:
        require(first["evidence"]["mode"]=="carrier" and first["evidence"]["profile"]=="configured"
            and first["evidence"]["era"]=="legacy","physical controls bind one complete configured lane")
        controls=capture.parent/(capture.name+"-reader-controls")
        public_reader_controls.create(capture,controls)
        relocations=[]
        for name in ("relocation-one","relocation-two"):
            moved=controls/name/"capture"
            shutil.copytree(capture,moved,copy_function=os.link)
            proof=readonly.guarded(lambda:read_public.read(moved),roots=(ROOT,moved))
            require(proof["evidence"]==first["evidence"],"complete relocation changed comparison")
            (controls/name/"READONLY.json").write_bytes(canonical(proof))
            relocations.append(dict(name=name,evidence=proof["evidence"],guard_probes=len(proof["probes"])))
        def operation():
            original=read_public.read(capture)
            checked=public_reader_controls.verify(capture,controls)
            again=[]
            for row in relocations:
                name=row["name"]
                found=read_public.read(controls/name/"capture")
                retained=decode((controls/name/"READONLY.json").read_bytes())
                require(found==row["evidence"]==retained["evidence"]==original,"retained complete relocation")
                again.append(row)
            return dict(comparison=original,physical=checked,relocations=again)
        proof=readonly.guarded(operation,roots=(ROOT,capture,controls))
        (controls/"FINAL_READONLY.json").write_bytes(canonical(proof))
        result.update(physical_controls=len(proof["evidence"]["physical"]["controls"]),
            relocations=len(proof["evidence"]["relocations"]),final_guard_probes=len(proof["probes"]),
            final_reader_entries=proof["entries"])
    (capture.parent/(capture.name+"-result.json")).write_bytes(canonical(result))
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--capture",required=True,type=Path)
    p.add_argument("--physical-controls",action="store_true");a=p.parse_args();run(a.capture,a.physical_controls)
