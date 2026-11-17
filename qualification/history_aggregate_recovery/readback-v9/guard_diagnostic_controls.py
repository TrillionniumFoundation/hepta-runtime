#!/usr/bin/env python3
"""Diagnostic retention controls. The original read-only permissions do not change."""
from __future__ import annotations
import ctypes
import hashlib
import os
from pathlib import Path
import tempfile
import read_only_guard as guard

NAMES=("complete-read-with-diagnostics","swallowed-foreign-read","uncaught-native-load")

def need(value,message):
    if not value:
        raise ValueError(message)


def unchanged_guard_policy():
    current=Path(guard.__file__).read_text()
    prefix="\ndef _diagnostic_value(value):\n"
    suffix="def guarded(operation, *, roots, foreign_path, external_files=(), diagnostics=None):"
    need(current.count(prefix)==current.count(suffix)==1,"exact diagnostic helper insertion")
    start=current.index(prefix);end=current.index(suffix,start)
    restored=current[:start]+current[end:]
    replacements=(
        (suffix,"def guarded(operation, *, roots, foreign_path, external_files=()):"),
        ('    require(diagnostics is None or type(diagnostics) is list, "owned diagnostic list required")\n',""),
        ('    diagnostic_phase = ["probes"]\n',""),
        ('        if diagnostics is not None:\n            diagnostics.append(_denial_trace(kind, diagnostic_phase[0]))\n',""),
        ('        diagnostic_phase[0] = "reader"\n',""),
    )
    for before,after in replacements:
        need(restored.count(before)==1,"one exact diagnostic-only insertion")
        restored=restored.replace(before,after)
    digest=hashlib.sha256(restored.encode()).hexdigest()
    need(digest=="989cc4f469b490031f3953284a9983311137badf6f6ecb1baf92d4d80747fb98",
         "all original guard source bytes preserved by diagnostic inverse")
    return {"original_guard_sha256":digest,"current_guard_sha256":
            hashlib.sha256(current.encode()).hexdigest(),
            "complete_original_source_reproduced":True}

def run():
    source=unchanged_guard_policy()
    rows=[]
    with tempfile.TemporaryDirectory(prefix="history-guard-diagnostic-") as temporary:
        root=Path(temporary)
        owned=root/"owned";owned.mkdir()
        retained=owned/"CAPTURE.json";retained.write_bytes(b'{"retained":true}\n')
        foreign=root/"foreign";foreign.write_bytes(b"not admitted")
        expected=retained.read_bytes()
        original_open=os.open
        original_hooks=list(guard._ACTIVE_AUDITS)

        def complete_read():
            return retained.read_bytes().hex()

        def swallowed_read():
            try:
                foreign.read_bytes()
            except PermissionError:
                return "caught-for-diagnostic-control"
            raise ValueError("foreign read unexpectedly admitted")

        def native_load():
            ctypes.CDLL(None)
            raise ValueError("native load unexpectedly admitted")

        for name,operation in zip(NAMES,(complete_read,swallowed_read,native_load)):
            before=guard.snapshot([owned])
            events=[];outcome=None;proof=None
            try:
                proof=guard.guarded(operation,roots=[owned],foreign_path=foreign,diagnostics=events)
            except (PermissionError,ValueError) as error:
                outcome={"type":type(error).__name__,"message":str(error)}
            after=guard.snapshot([owned])
            need(before==after,"diagnostic control changed complete bytes/metadata")
            need(os.open is original_open and guard._ACTIVE_AUDITS==original_hooks,
                 "guard cleanup after retained denial")
            probes=[row for row in events if row["phase"]=="probes"]
            readers=[row for row in events if row["phase"]=="reader"]
            need(len(probes)==12 and len(events)==len(probes)+len(readers),
                 "all twelve original guard probes retained")
            for row in events:
                need(row["frames"] and all(type(frame["file"]) is str
                     and type(frame["function"]) is str and type(frame["line"]) is int
                     and frame["line"]>0 for frame in row["frames"]),
                     "complete metadata-only refusal stack")
            if name==NAMES[0]:
                need(outcome is None and proof is not None and readers==[]
                     and proof["evidence"]==expected.hex() and len(proof["probes"])==12
                     and proof["before"]==proof["after"],
                     "positive complete diagnostic admission")
            else:
                need(proof is None and len(readers)==1,"one retained reader denial")
                row=readers[0]
                actual=[frame["arguments"] for frame in row["frames"]
                        if frame["file"]==guard.__file__ and frame["function"]=="audit"]
                need(len(actual)==1,"exact audit event arguments retained")
                if name==NAMES[1]:
                    need(outcome=={"type":"ValueError","message":"reader attempted a forbidden operation"}
                         and row["kind"]=="foreign-read" and actual[0]["event"]=="open"
                         and actual[0]["args"][0]==str(foreign)
                         and any(frame["function"]=="swallowed_read" for frame in row["frames"]),
                         "caught foreign read remains a final guard failure")
                else:
                    need(outcome=={"type":"PermissionError",
                                   "message":"history-aggregate read-only guard: native-mapping"}
                         and row["kind"]=="native-mapping" and actual[0]["event"]=="ctypes.dlopen"
                         and any(frame["function"]=="native_load" for frame in row["frames"]),
                         "native load remains rejected before execution")
            rows.append({"name":name,"outcome":outcome,"events":events,
                         "before":before,"after":after,"cleanup_restored":True,
                         "native_or_rust_executions":0})
    return {"schema":"hepta.history.guard-diagnostic-controls.v1","status":"PASS",
            "complete_admissions":1,"refusals":2,"original_guard_probes":36,
            "permissions_changed":False,"source":source,"native_or_rust_executions":0,"cases":rows}
