#!/usr/bin/env python3
"""Focused actual native/current-original gate; this does not activate a handler."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--phase",choices=("native","original","all","verify-native","verify"),required=True)
    parser.add_argument("--hepta",type=Path)
    parser.add_argument("--bootstrap",type=Path)
    parser.add_argument("--target",type=Path)
    parser.add_argument("--rust-bin",type=Path)
    args=parser.parse_args(argv)
    root=args.source_root.resolve(strict=True)
    sys.path.insert(0,str(root/"tests/hia_native/scope_annotation"))
    if args.phase in ("verify-native","verify"):
        from verify_readonly import ReadOnlyGuard
        with ReadOnlyGuard():
            qualify(args)
    else:
        qualify(args)


def qualify(args):
    root=args.source_root.resolve(strict=True)
    output=args.output.absolute()
    sys.path[:0]=[str(root/"scripts"),str(root/"tests/hia_native/scope_annotation")]
    import hia_native_scope_annotation_qualification as q
    from hia_native_scope_annotation_build import build_scope_annotation,verify_build
    from rust_reference import Recorder,environment,build_reference,put
    q.SOURCE_FILES=tuple(q.SOURCE_FILES)
    source=q.source_evidence(root)
    verify_only=args.phase in ("verify-native","verify")

    def retain_or_compare(path,value):
        if verify_only:
            q.require(q.read(path)==q.encoded(value),"retained qualification report differs: "+path.name)
        else:
            put(path,value)

    original_phase=args.phase in ("original","all")
    native_phase=args.phase in ("native","all")
    if original_phase and (args.rust_bin is None or args.target is None):
        raise ValueError("the explicit original phase requires --rust-bin and an independent --target checkout")
    if native_phase:
        if args.hepta is None:raise ValueError("--hepta required for fresh native build")
        output.mkdir(parents=True,exist_ok=False)
        put(output/"source-before.json",source)
        put(output/"invocation.json",dict(source_root=str(root),output=str(output),parent_pid=os.getpid(),
            compiler=str(args.hepta.resolve(strict=True)),started_ns=time.time_ns(),original_requested=original_phase))
        env,_=environment(os.environ)
        rec=Recorder(root,output/"native-processes",env)
        build_command=[sys.executable,root/"tests/hia_native/scope_annotation/build_native.py","--runtime",root,
            "--hepta",args.hepta.resolve(strict=True),"--output",output/"native-build"]
        if args.bootstrap is not None:build_command.extend(["--bootstrap",args.bootstrap.resolve(strict=True)])
        rec.run("native-build",build_command,timeout=900)
        manifest=output/"native-build/scope-annotation-build.json"
        rec.run("native-corpus",[sys.executable,root/"tests/hia_native/scope_annotation/run_native.py",
            "--runtime",root,"--build",manifest,"--output",output/"native"],timeout=180)
        rec.run("native-controls",[sys.executable,root/"tests/hia_native/scope_annotation/controls.py",
            "--runtime",root,"--build",manifest,"--output",output/"controls"],timeout=180)
        put(output/"source-after-native.json",q.source_evidence(root))
    else:
        if not output.is_dir():raise ValueError("the existing native capture is required")
        if q.parse(q.read(output/"source-before.json"))!=source:raise ValueError("qualification source closure differs")
    manifest=output/"native-build/scope-annotation-build.json"
    verify_build(manifest,source_root=root)
    processes=q.parse(q.read(output/"native-processes/processes.json"))
    q.require([p["name"]for p in processes]==["native-build","native-corpus","native-controls"],"native process set differs")
    q.process_evidence(processes[0],output/"native-processes",name="native-build",timeout=900)
    built=q.parse(q.read(output/"native-processes/native-build.stdout"))
    q.require(built["manifest_sha256"]==hashlib.sha256(manifest.read_bytes()).hexdigest() and built["modules"]==5,"actual build process receipt differs")
    native=q.native_evidence(manifest,output/"native",source_root=root,process=processes[1],process_folder=output/"native-processes")
    controls=q.controls_evidence(manifest,output/"controls",source_root=root,process=processes[2],process_folder=output/"native-processes")
    q.require(q.parse(q.read(output/"source-after-native.json"))==source,"native source changed")
    retain_or_compare(output/"native-evidence.json",native)
    retain_or_compare(output/"control-evidence.json",controls)
    if native_phase:
        env,_=environment(os.environ)
        reader=Recorder(root,output/"reader-processes",env)
        reader.run("native-evidence-controls",[sys.executable,root/"tests/hia_native/scope_annotation/evidence_controls.py",
            "--runtime",root,"--capture",output,"--output",output/"reader-controls"],timeout=180)
    if original_phase:
        binary,build,reference=build_reference(root,args.target,output/"original",args.rust_bin)
        with gzip.open(output/"native/inputs.bin.gz","rb")as stream:
            inputs=stream.read()
        q.require(len(inputs)==q.EXPECTED["input_bytes"] and hashlib.sha256(inputs).hexdigest()==q.EXPECTED["input_sha256"],"complete replay input differs")
        stdout,process=reference.run("original-replay",[binary],stdin=inputs,timeout=180)
        q.require(process["stderr"]["bytes"]==0,"original replay produced stderr")
        comparison=q.compare_original(output/"native",output/"original/processes/original-replay.stdout")
        put(output/"original-comparison.json",comparison)
        put(output/"source-after-original.json",q.source_evidence(root))
        env,_=environment(os.environ)
        original_reader=Recorder(root,output/"original-reader-processes",env)
        original_reader.run("original-evidence-controls",[sys.executable,
            root/"tests/hia_native/scope_annotation/original_evidence_controls.py",
            "--runtime",root,"--capture",output,"--output",output/"original-reader-controls"],timeout=180)
    complete=args.phase in ("all","original","verify")
    original=None
    if complete:
        original=q.original_evidence(output/"original",output/"native",source_root=root)
        q.require(q.parse(q.read(output/"source-after-original.json"))==source,"original source closure changed")
        retain_or_compare(output/"original-evidence.json",original)
    reader_report=q.reader_controls_evidence(output,source_root=root)
    original_reader_report=q.reader_controls_evidence(output,source_root=root,original=True) if complete else None
    q.require(q.source_evidence(root)==source,"final source closure changed")
    report=dict(schema="hepta.scope-annotation.focused-qualification.v1",status="QUALIFIED_BOUNDED_FUNCTION"if complete else"NATIVE_ONLY_PASS",
        sources=source,native=native,controls=controls,original=original,
        reader_controls=reader_report,original_reader_controls=original_reader_report,reference_pending=not complete,
        qualified_input_text_bytes=8<<20,actual_wire_budget_bytes=65536,
        caller_authority_resolution_qualified=False,public_handler_qualified=False,
        production_activated=False,whole_runtime_replaced=False,cold_compiler_qualification=False)
    retain_or_compare(output/"QUALIFICATION.json",report)
    print(json.dumps(dict(status=report["status"],cases=native["cases"],native_calls=native["native_calls"],
        controls=controls["controls"],original_pending=not complete,source_sha256=source["sha256"]),sort_keys=True))


if __name__=="__main__":main()
