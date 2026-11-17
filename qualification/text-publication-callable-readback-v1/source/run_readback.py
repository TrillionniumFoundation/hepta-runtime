#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Restore and qualify already captured bytes. Never launches a native or Rust process."""
from pathlib import Path
import argparse
import ast
import json
import signal
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from callable_common import decode,encoded,owned,pin,require,sources,syntax,SCOPE

def bounded(operation):
    def expired(signum,frame):raise TimeoutError("pure reader boundary exceeded retained 180 seconds")
    old=signal.signal(signal.SIGALRM,expired);signal.alarm(180)
    try:return operation()
    finally:signal.alarm(0);signal.signal(signal.SIGALRM,old)

def prepare(source,capture):
    source,capture=Path(source),Path(capture)
    own=syntax(source)
    expected=dict(bytes=15480,sha256="982cb3ad3fe24da3019ebc9b3cdd847b34b78877a65e3a1cbb94f69b9b657226")
    require(pin(owned(capture/"source","SOURCE_MANIFEST.json"))==expected,"frozen callable source manifest differs")
    identity=syntax(capture/"source")
    require(identity["source"]["files"]==60,"frozen capture source set differs")
    require((source/"callable_common.py").read_bytes()==(capture/"source/scripts/callable_common.py").read_bytes(),
        "reader byte identity helper differs from admitted capture")
    sys.path.insert(0,str(capture/"source/scripts"))
    sys.path.insert(0,str(capture/"source/body-source/scripts"))
    from read_callable_all import read_all
    from callable_reader_controls import create,verify
    from readonly import guarded
    from archive import verify as archive_verify
    return own,identity,read_all,create,verify,guarded,archive_verify

def run(source,output):
    require(not output.exists(),"readback output exists");output.mkdir(parents=True)
    from restore_capture import fetch
    extracted=fetch(output/"restored");capture=extracted/"capture"
    require(sources(extracted/"recipe-source")==sources(capture/"source"),"two retained source copies differ")
    own,identity,read_all,create,verify,guarded,archive_verify=prepare(source,capture)
    result=bounded(lambda:read_all(capture))
    (output/"BASELINE.json").write_bytes(encoded(result))
    controls=output/"physical-controls"
    bounded(lambda:create(capture,controls))
    def operation():
        result=read_all(capture)
        result["physical_controls"]=verify(capture,controls)
        outer=output/"restored"
        archive=archive_verify(outer/"evidence.tar.gz",decode(owned(outer,"FILES.json").read_bytes()))
        require(archive==decode(owned(outer,"ARCHIVE.json").read_bytes()),"complete retained archive receipt changed")
        result["retained_archive"]=archive;return result
    proof=bounded(lambda:guarded(operation,roots=[source,output/"restored",controls]))
    (output/"READONLY.json").write_bytes(encoded(proof))
    summary=dict(status=proof["evidence"]["status"],cases=proof["evidence"]["cases"],
        private_controls=proof["evidence"]["physical"]["controls"],original_tests=8,
        physical_reader_controls=len(proof["evidence"]["physical_controls"]["controls"]),guard_probes=len(proof["probes"]),
        unchanged_entries=proof["entries"],native_executed=False,rust_executed=False,
        reader_source=own,capture_source=identity,readback=pin(output/"READONLY.json"),scope=SCOPE)
    (output/"RESULT.json").write_bytes(encoded(summary));print(json.dumps(summary,sort_keys=True))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("mode",choices=("check","run"))
    p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True)
    if a.mode=="check":print(json.dumps(syntax(source),sort_keys=True))
    else:run(source,a.output.absolute())
if __name__=="__main__":main()
