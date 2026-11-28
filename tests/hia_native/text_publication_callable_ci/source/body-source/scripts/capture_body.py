#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Run one unchanged input domain against actual original code or the two HIA owners."""
from pathlib import Path
import argparse
import json
import os
import selectors
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical, decode, pin, require, source_evidence
from body_cases import cases, request, domain
from body_filesystem import reset, snapshot, retire
from buffer_store import Writer

class Original:
    def __init__(self,binary,folder):
        self.folder=Path(folder);self.binary=Path(binary)
        self.stderr=(self.folder/"original.stderr").open("xb")
        self.input=(self.folder/"original.stdin").open("xb")
        self.output=(self.folder/"original.stdout").open("xb")
        self.child=subprocess.Popen([str(self.binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=self.stderr,bufsize=0)
        os.set_blocking(self.child.stdin.fileno(),False)
        os.set_blocking(self.child.stdout.fileno(),False)
        self.buffer=b"";self.receipt=dict(argv=[str(self.binary)],pid=self.child.pid,
            binary=pin(self.binary),same_outer_process_group=True,started_ns=time.monotonic_ns())

    def exchange(self,value):
        raw=canonical(value);self.input.write(raw);self.input.flush()
        pending=memoryview(raw);out=b"";deadline=time.monotonic()+60
        selector=selectors.DefaultSelector()
        selector.register(self.child.stdin,selectors.EVENT_WRITE)
        selector.register(self.child.stdout,selectors.EVENT_READ)
        try:
            while pending or not out.endswith(b"\n"):
                require(time.monotonic()<deadline,"original exchange exceeded 60 seconds")
                ready=selector.select(max(0,deadline-time.monotonic()))
                require(ready,"original exchange timeout")
                for key,mask in ready:
                    if key.fileobj is self.child.stdin:
                        count=os.write(key.fd,pending);pending=pending[count:]
                        if not pending:selector.unregister(self.child.stdin)
                    else:
                        chunk=os.read(key.fd,65536)
                        require(chunk,"original stdout EOF before response")
                        self.output.write(chunk);self.output.flush();out+=chunk
                        require(out.count(b"\n")<=1,"original extra response")
                require(len(out)<32<<20,"original response unbounded")
            return decode(out),out
        finally:
            selector.close()

    def finish(self):
        self.child.stdin.close()
        selector=selectors.DefaultSelector();selector.register(self.child.stdout,selectors.EVENT_READ)
        deadline=time.monotonic()+60
        try:
            while True:
                ready=selector.select(max(0,deadline-time.monotonic()))
                require(ready,"original EOF timeout")
                chunk=os.read(self.child.stdout.fileno(),65536)
                if not chunk:break
                self.output.write(chunk);self.output.flush()
                raise ValueError("original extra bytes after input EOF")
            self.receipt["returncode"]=self.child.wait(timeout=max(.001,deadline-time.monotonic()))
            require(self.receipt["returncode"]==0,"original process failed")
        finally:
            selector.close();self.child.stdout.close()
        self.receipt["elapsed_ns"]=time.monotonic_ns()-self.receipt["started_ns"]
        self.input.close();self.output.close();self.stderr.close()
        self.receipt["streams"]={k:pin(self.folder/("original."+k)) for k in ("stdin","stdout","stderr")}
        require((self.folder/"original.stderr").read_bytes()==b"","original semantic stderr")
        (self.folder/"original-process.json").write_bytes(canonical(self.receipt))

    def cleanup(self):
        if self.child.poll() is None:
            self.child.kill();self.child.wait()
        for stream in (self.child.stdin,self.child.stdout,self.input,self.output,self.stderr):
            if stream is not None and not stream.closed:stream.close()

def run(role,qualification,folder,fixture):
    qualification=Path(qualification);folder=Path(folder);fixture=Path(fixture)
    require(not folder.exists(),"capture must be fresh");folder.mkdir(parents=True)
    source=qualification/"source";identity=source_evidence(source)
    (folder/"DOMAIN.json").write_bytes(canonical(domain()))
    store=Writer(folder/"buffers")
    stream=(folder/"cases.jsonl").open("xb");wirestream=(folder/"wire.jsonl").open("xb")
    actor=None;native_calls=None;effects=None
    begin=time.monotonic_ns()
    try:
        if role=="native":
            from mechanical import NativeBody
            native_calls=(folder/"calls.jsonl").open("xb");effects=(folder/"effects.jsonl").open("xb")
            actor=NativeBody(qualification,folder,store,native_calls,effects)
        else:
            actor=Original(qualification/"rust-target/debug/hepta-text-publication-body-original",folder)
        for case in cases():
            root=fixture/("case-%03d"%case["id"]);reset(root,case)
            row=dict(id=case["id"],name=case["name"],fixture=str(root),
                request=request(case,root),before=snapshot(root,store))
            started=time.monotonic_ns()
            try:
                if role=="native":
                    result,chain=actor.run(row["request"]);raw=canonical(result);row["chain"]=chain
                else:
                    result,raw=actor.exchange(row["request"])
                row["elapsed_ns"]=time.monotonic_ns()-started
                require(row["elapsed_ns"]<60_000_000_000,"body exchange exceeded 60 seconds")
                row["response"]=store.put(raw);row["result"]=result
                row["after"]=snapshot(root,store)
                wirestream.write(raw);wirestream.flush()
                stream.write(canonical(row));stream.flush()
            except BaseException as exc:
                row["failure"]={"type":type(exc).__name__,"message":str(exc)}
                row["after_failure"]=snapshot(root,store)
                (folder/"FAILURE.json").write_bytes(canonical(row))
                raise
            finally:
                retire(root,case)
        if role=="original":actor.finish()
        else:
            from private_controls import capture as private_capture
            private_capture(actor,store,folder/"controls.json")
        result=dict(status="COMPLETE_PRIVATE_BODY_CAPTURE",role=role,cases=len(cases()),
            source=identity,elapsed_ns=time.monotonic_ns()-begin,domain=pin(folder/"DOMAIN.json"),
            body_calls=actor.ordinal if role=="native" else 0,effects=actor.effect_ordinal if role=="native" else 0,
            complete_buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
            original_output_read_by_native=False,scope=identity["scope"])
        (folder/"capture.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
    finally:
        stream.close();wirestream.close()
        if native_calls:native_calls.close()
        if effects:effects.close()
        if actor:
            if role=="native":actor.close()
            else:actor.cleanup()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role",choices=("native","original"),required=True)
    p.add_argument("--qualification",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--fixture",type=Path,required=True)
    a=p.parse_args();run(a.role,a.qualification,a.output,a.fixture)

if __name__=="__main__":main()
