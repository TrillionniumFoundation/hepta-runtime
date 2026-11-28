#!/usr/bin/env python3
"""Exact fixture delta and retained pre-entry failure; no native execution."""
from pathlib import Path
import gzip,hashlib,json,stat
from common import decode,pin,require,sha

def frozen(root,expected=None):
    root=Path(root);raw=(root/"SOURCE_MANIFEST.json").read_bytes();value=decode(raw);rows=value["files"]
    require(expected is None or sha(raw)==expected,"continuation source manifest changed")
    actual={p.relative_to(root).as_posix() for p in root.rglob("*")if p.is_file()}
    require(len(rows)==len({r["path"]for r in rows}) and actual=={r["path"]for r in rows}|{"SOURCE_MANIFEST.json"},
        "continuation complete source set changed")
    for row in rows:
        p=root/row["path"];body=p.read_bytes()
        require(p.resolve()==p.absolute() and stat.S_ISREG(p.lstat().st_mode)and stat.S_IMODE(p.stat().st_mode)==0o644,
            "continuation ordinary source mode changed")
        require(dict(bytes=len(body),sha256=sha(body))=={k:row[k]for k in("bytes","sha256")}
            and hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],
            "continuation full source bytes changed")
    binding=decode((root/"BINDING.json").read_bytes())
    for role,name in(("native","native_capture"),("reader","run_ci")):
        change=binding[role+"_change"];old=(root/("scripts/"+name+"_original.py.txt")).read_text()
        actual=(root/("scripts/"+name+".py")).read_text();updated=old
        replacements=change.get("replacements",[change.get("replacement")])
        for row in replacements:
            require(updated.count(row["before"])==1,"exact continuation edit point changed")
            updated=updated.replace(row["before"],row["after"])
        require(actual==updated and sha(old.encode())==change["original_sha256"]
            and sha(actual.encode())==change["patched_sha256"],"continuation exceeded exact fixture/reader delta")
    return sha(raw),binding

def validate(output):
    output=Path(output);source=output/"source";continued=output/"continuation-source"
    manifest,binding=frozen(continued)
    require(pin(source/"SOURCE_MANIFEST.json")["sha256"]==binding["manifest_sha256"],
        "original source manifest changed")
    for name in("native_capture","run_ci"):
        require((source/("scripts/"+name+".py")).read_bytes()==
            (continued/("scripts/"+name+"_original.py.txt")).read_bytes(),"original frozen reader/fixture changed")
    require(pin(source/"native/config_directory_owner_span.hepta")["sha256"]==
        binding["immutable_actual_hia_source_sha256"],"actual HIA owner source changed")
    origin=decode((output/"ORIGIN.json").read_bytes());at=Path(origin["output"])
    failed=output/"original-failure";row=decode((failed/"processes/native-controls.json").read_bytes())
    require(row["argv"]==[origin["python"],"-I","-S","-B",str(at/"source/scripts/native_capture.py"),
        "--qualification",str(at),"--controls"] and row["cwd"]==str(at)and row["returncode"]==1
        and row["timed_out"]is False and row["limit_seconds"]==60 and 0<=row["elapsed_ns"]<61000000000,
        "original capacity fixture failure changed")
    require(set(row["streams"])=={"stdin","stdout","stderr"},"original failure stream omitted")
    for suffix,want in row["streams"].items():
        require(pin(failed/("processes/native-controls."+suffix))==want,"complete original failure bytes changed")
    error=(failed/"processes/native-controls.stderr").read_bytes()
    require(b"ctypes.ArgumentError: argument 2: TypeError: wrong type" in error
        and b"workspace=Borrow(work,size)"in error,"original failure reason changed")
    partial=failed/"controls"
    require({p.name for p in partial.iterdir()}=={"installed-owner.bin","SEED.json","calls.bin.gz"},
        "original capacity domain had already started")
    with gzip.open(partial/"calls.bin.gz","rb")as stream:
        require(stream.read()==b"","original failed fixture contains a native entry")
    for name in("installed-owner.bin","SEED.json"):
        require((partial/name).read_bytes()==(output/"controls"/name).read_bytes(),
            "continuation changed the actual installed state seed")
    return dict(status="EXACT_PRE_ENTRY_FAILURE_AND_CONTINUATION_PASS",continuation_manifest_sha256=manifest,
        old_135_cases_replayed=False,old_12_wire_controls_replayed=False,rust_reexecuted=False,
        hia_source_unchanged=True,new_capacity_controls=14)
