#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Input-only owned native-worker lifecycle. Never supplies a response or file result."""
from pathlib import Path
import struct
DIRECT=("unpolled_drop","started_drop","started_complete","queued_drop","queued_complete",
    "two_started_drop_first","started_drop_then_second","queued_drop_then_second")
EXTRA=("borrow_lifetime","close_queued","fifo_growth","invalid_lifecycle")
def cases(root):
    rows=[]
    for observer in (True,False):
        for name in DIRECT+EXTRA:
            rows.append(dict(case=len(rows),name=name,observer=observer,
                root=str(Path(root)/("%s-%s"%("on" if observer else "off",name))),
                limit=1 if name.startswith("queued") or name in ("close_queued","fifo_growth") else 512,
                original_direct=name if name in DIRECT else None))
    return rows
def declaration():
    return dict(schema="hepta.runtime.publication-worker.native-inputs.v1",cases=24,
        observer_on=12,observer_off=12,original_direct_cases=list(DIRECT),additional=list(EXTRA),
        maximum_queued_jobs=33,exchange_timeout_seconds=60,process_timeout_seconds=180,
        ci_job_timeout_minutes=15,expected_wire_supplied=False,expected_file_effect_supplied=False,
        scope="private executor; no SDK/cache/handler continuation is simulated",
        full_sdk=False,public_async_qualified=False,production_installed=False)
def body(root,path):
    path=(str(Path(root)/path)).encode()
    content=("ordinary publication: "+Path(path.decode()).relative_to(root).as_posix()+"\n").encode()
    expected=b"absent"
    return b"HTPBQ001"+struct.pack("<7Q",1,0,1,len(path),len(content),len(expected),
        len(path)+len(content)+len(expected))+path+content+expected
def frame(command,job=0,tag=0,payload=b"",argument=0,flags=0):
    raw=b"HPTWFQ01"+struct.pack("<7Q",command,job,tag,len(payload),argument,flags,0)+payload
    return struct.pack("<Q",len(raw))+raw
