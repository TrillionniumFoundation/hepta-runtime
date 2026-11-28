#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind actual partial second relocation and all source against complete archive index."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,sys,zipfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,pin,raw_pin,need,stable
from common import source_evidence
PREFIX="filesystem-public/original-controls/"
def all_zip(path,want):
    before=stable(path);need(pin(path)==want,"complete immutable uploaded ZIP")
    rows={}
    with zipfile.ZipFile(path)as z:
        for m in z.infolist():
            p=PurePosixPath(m.filename)
            need(not p.is_absolute()and".."not in p.parts and p.as_posix()==m.filename.rstrip("/"),"ordinary complete ZIP path")
            need(m.filename not in rows,"unique archive member")
            if m.is_dir():rows[m.filename]=None;continue
            b=z.read(m);need(len(b)==m.file_size,"full ZIP member extent");rows[m.filename]=b
    need(stable(path)==before,"immutable ZIP byte reading excludes atime");return rows
def main():
    p=argparse.ArgumentParser()
    for n in("source","diagnostic","partial","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();need(not a.output.exists(),"fresh pure metadata binding");a.output.mkdir()
    binding=source_evidence(a.source);inputs=decode((a.source/"INSTALLED_INPUTS.json").read_bytes());known=decode((a.source/"KNOWN_SOURCES.json").read_bytes())
    diag=all_zip(a.diagnostic,inputs["diagnostic"]["zip"]);parts=all_zip(a.partial,inputs["partial"]["zip"])
    members=[v for k,v in diag.items()if k.endswith("MEMBERS.json")];need(len(members)==1 and raw_pin(members[0])==inputs["member_index"],"previous whole TAR member-byte index")
    index=decode(members[0]);rows={r["path"]:r for r in index["tar"]};need(len(rows)==110036,"complete immutable original member count")
    proofdir=a.output/"retained-controls";proofdir.mkdir()
    partial={}
    for name,b in parts.items():
        if b is None:continue
        p=raw_pin(b);partial.setdefault((p["bytes"],p["sha256"]),[]).append((name,b))
    source_proofs=[]
    for r in known:
        m=rows[r["path"]];need(m["size"]==r["bytes"]and m["sha256"]==r["sha256"]and m["type"]=="0","actual source bound to whole failed TAR")
        options=partial[(r["bytes"],r["sha256"])];need(options,"actual partial source bytes")
        source_proofs.append(dict(path=r["path"],git_blob=r["git_blob"],uploaded_files=[x[0]for x in options],bytes=r["bytes"],sha256=r["sha256"]))
    selected={}
    tails=("SOURCE.json","BASELINE.json","NATIVE-BASELINE.json","REFUSALS.json","remote-process.json",
        "relocation-1/PROCESS.json","relocation-1/EVIDENCE.json","relocation-1/NATIVE-EVIDENCE.json",
        "relocation-2/PROCESS.json","relocation-2/EVIDENCE.json","relocation-2/NATIVE-EVIDENCE.json")
    for tail in tails:
        name=PREFIX+tail
        if name not in rows:continue
        r=rows[name];need(r["type"]=="0","ordinary completed/partial receipt")
        choices=partial.get((r["size"],r["sha256"]),[])
        if not choices:
            keys=[k for k in diag if k.endswith("SELECTED.json")];need(len(keys)==1,"complete prior selected index")
            lookup=decode(diag[keys[0]])["TAR/"+name];b=diag[lookup["file"]]
        else:b=choices[0][1]
        need(raw_pin(b)==dict(bytes=r["size"],sha256=r["sha256"]),"whole actual control receipt")
        dest=proofdir/tail;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b);selected[tail]=decode(b)
    need(len(selected["REFUSALS.json"]["controls"])==42,"42 completed refusals remain immutable")
    first=selected["relocation-1/PROCESS.json"];need(first["exit_code"]==0 and first["timed_out"]is False,"completed first relocation remains complete")
    need(selected["relocation-1/EVIDENCE.json"]==selected["BASELINE.json"]and selected["relocation-1/NATIVE-EVIDENCE.json"]==selected["NATIVE-BASELINE.json"],"entire first relocation objects already equal")
    prior_native="relocation-2/NATIVE-EVIDENCE.json"in selected;prior_full="relocation-2/EVIDENCE.json"in selected
    if prior_native:need(selected["relocation-2/NATIVE-EVIDENCE.json"]==selected["NATIVE-BASELINE.json"],"entire completed partial second-native object")
    if prior_full:need(selected["relocation-2/EVIDENCE.json"]==selected["BASELINE.json"],"entire second comparison already captured")
    bundle=[r for r in rows.values()if r["path"].startswith(PREFIX+"relocated-two/")]
    other=[r["path"]for r in rows.values()if r["path"].startswith(PREFIX+"relocated-one/")];need(not other,"exact original second root present")
    result=dict(status="ACTUAL_SECOND_RELOCATION_SOURCE_AND_PARTIAL_PHASE_BOUND",source=binding,files=source_proofs,
        controls={k:pin(proofdir/k)for k in selected},second_native_phase_complete=prior_native,second_full_phase_complete=prior_full,
        second_process_receipt_present="relocation-2/PROCESS.json"in selected,bundle_members=len(bundle),
        bundle_file_bytes=sum(r["size"]for r in bundle if r["type"]=="0"),bundle_kinds={k:sum(r["type"]==k for r in bundle)for k in sorted({r["type"]for r in bundle})},
        applications_executed=0,retained_code_executed=0,completed_refusals_replayed=0,completed_first_relocation_replayed=0,
        old_failures_preserved=True,next="none"if prior_full and prior_native else"only missing original second-relocation pure phase")
    (a.output/"MEMBERS.json").write_bytes(members[0]);(a.output/"BIND.json").write_bytes(canonical(result))
    need(source_evidence(a.source)==binding,"metadata binding source changed");print(canonical(result).decode(),end="")
if __name__=="__main__":main()
