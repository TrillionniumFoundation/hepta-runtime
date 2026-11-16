"""Read-only physical relocation and negative admission controls; no native replay."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import time

sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NAMES=("native-status", "native-case-omitted", "native-call-count", "native-reference-inflation", "native-process-pid",
    "native-input-changed", "native-result-changed", "native-call-owner", "native-partial-output",
    "native-truncated-footer", "native-unclaimed-record", "shared-constructor-extent", "constructor-growth-required",
    "constructor-refusal-lifecycle", "control-omitted", "control-budget-changed", "control-patch-changed",
    "control-original-inflation", "control-input-changed", "control-complete-workspace-changed",
    "process-timed-out", "process-not-complete", "process-source-command", "process-deadline", "foreign-copy-symlink")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime",type=Path,required=True)
    parser.add_argument("--capture",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    root=args.runtime.resolve(strict=True);capture=args.capture.resolve(strict=True);output=args.output.absolute()
    output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(root/"scripts"))
    import hia_native_scope_annotation_qualification as q
    from hia_native_scope_annotation_build import MODULES
    report=dict(schema="hepta.scope-annotation.reader-controls.v1",status="IN_PROGRESS",controls=[],relocations=[],
        execution=dict(pid=os.getpid(),parent_pid=os.getppid(),cwd=str(Path.cwd().resolve())),
        native_processes_executed=0,original_processes_executed=0)
    save=lambda:(output/"result.json").write_bytes(q.encoded(report))
    started=time.monotonic();save()
    native_processes=q.parse(q.read(capture/"native-processes/processes.json"))
    q.require([p["name"]for p in native_processes]==["native-build","native-corpus","native-controls"],"owned native process set differs")

    def native(folder,processes=None):
        p=native_processes if processes is None else processes
        return q.native_evidence(folder/"native-build/scope-annotation-build.json",folder/"native",source_root=root,
            process=p[1],process_folder=folder/"native-processes")

    def controls(folder,processes=None):
        p=native_processes if processes is None else processes
        return q.controls_evidence(folder/"native-build/scope-annotation-build.json",folder/"controls",source_root=root,
            process=p[2],process_folder=folder/"native-processes")

    baseline_native=native(capture);baseline_controls=controls(capture)
    files={"native-build/scope-annotation-build.json","native-processes/processes.json"}
    build=q.parse(q.read(capture/"native-build/scope-annotation-build.json"))
    files.update("native-build/"+name for name in build["source_reproduction"])
    files.update("native/"+name for name in baseline_native["artifact_sha256"])
    files.update("controls/"+name for name in baseline_controls["artifact_sha256"])
    for name in MODULES:
        relative="native-build/modules/"+name+"/"
        metadata=q.parse(q.read(capture/relative/"manifest.json"))
        files.update(relative+item for item in ("manifest.json",metadata["source"],metadata["image"]))
    for process in native_processes:
        for field in ("stdout","stderr"):
            files.add("native-processes/"+process[field]["file"])
    identities={name:q.file_pin(capture/name)for name in sorted(files)}
    def copy(destination):
        destination.mkdir(parents=True,exist_ok=False)
        for name in sorted(files):
            target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
            with q.opened(capture/name)as source,target.open("xb")as out:
                shutil.copyfileobj(source,out,1<<20)
            q.require(q.file_pin(target)==identities[name],"physical evidence copy differs")
    one=output/"copies/one";two=output/"copies/two"
    copy(one);copy(two)
    try:
        for folder in (one,two):
            n=native(folder);c=controls(folder)
            q.require(n==baseline_native and c==baseline_controls,"relocated strict read differs")
            report["relocations"].append(dict(name=folder.name,status="PASS",files=len(files),
                same_complete_source_and_artifact_identity=True,processes_executed=0))
        save()

        def refuse(name,reader,path,modify):
            original=q.read(path,256<<20)
            try:
                path.write_bytes(modify(original))
                try:reader(one)
                except (ValueError,AssertionError,KeyError,EOFError,OSError,UnicodeDecodeError)as error:
                    report["controls"].append(dict(name=name,status="REFUSED",error_type=type(error).__name__,reason=str(error)[:240]))
                    save()
                else:raise AssertionError("strict reader accepted mutation: "+name)
            finally:path.write_bytes(original)

        def edited(raw,fn):
            value=q.parse(raw);fn(value);return q.encoded(value)

        def first_packet(raw,fn):
            data=gzip.decompress(raw);size=struct.unpack_from("<Q",data)[0]
            first=bytearray(data[8:8+size]);fn(first)
            return gzip.compress(struct.pack("<Q",len(first))+bytes(first)+data[8+size:],compresslevel=1,mtime=0)

        path=one/"native/result.json"
        for name,fn in (
            ("native-status",lambda v:v.update(status="IN_PROGRESS")),
            ("native-case-omitted",lambda v:v["cases"].pop()),
            ("native-call-count",lambda v:v.update(native_calls=v["native_calls"]-1)),
            ("native-reference-inflation",lambda v:v.update(original_execution_qualified=True)),
            ("native-process-pid",lambda v:v["execution"].update(pid=v["execution"]["pid"]+1)),
        ):refuse(name,native,path,lambda raw,fn=fn:edited(raw,fn))
        refuse("native-input-changed",native,one/"native/inputs.bin.gz",lambda raw:first_packet(raw,lambda b:b.__setitem__(48,91)))
        refuse("native-result-changed",native,one/"native/native.bin.gz",lambda raw:first_packet(raw,lambda b:b.__setitem__(32+8,1)))
        refuse("native-call-owner",native,one/"native/calls.bin.gz",lambda raw:first_packet(raw,lambda b:struct.pack_into("<Q",b,24,2)))
        def published(b):
            input_size=struct.unpack_from("<Q",b,40)[0]
            b[64+input_size]=1
        refuse("native-partial-output",native,one/"native/calls.bin.gz",lambda raw:first_packet(raw,published))
        refuse("native-truncated-footer",native,one/"native/native.bin.gz",lambda raw:raw[:-6])
        refuse("native-unclaimed-record",native,one/"native/native.bin.gz",lambda raw:gzip.compress(gzip.decompress(raw)+struct.pack("<Q",1)+b"x",compresslevel=1,mtime=0))
        def constructor_extent(raw):
            data=bytearray(gzip.decompress(raw));at=0
            while at < len(data):
                size=struct.unpack_from("<Q",data,at)[0];record=at+8
                if struct.unpack_from("<Q",data,record+24)[0] == 5:
                    input_size=struct.unpack_from("<Q",data,record+40)[0]
                    field=record+64+input_size+40
                    struct.pack_into("<Q",data,field,struct.unpack_from("<Q",data,field)[0]+1)
                    return gzip.compress(data,compresslevel=1,mtime=0)
                at=record+size
            raise AssertionError("actual constructor call missing")
        refuse("shared-constructor-extent",native,one/"native/calls.bin.gz",constructor_extent)
        refuse("constructor-growth-required",controls,one/"controls/constructor-output-growth.child-after.bin",
            lambda raw:raw[:16]+struct.pack("<Q",356)+raw[24:])
        refuse("constructor-refusal-lifecycle",controls,one/"controls/constructor-output-growth.state-after.bin",
            lambda raw:raw[:8]+struct.pack("<Q",3)+raw[16:])
        controlpath=one/"controls/result.json"
        for name,fn in (
            ("control-omitted",lambda v:v["controls"].pop()),
            ("control-budget-changed",lambda v:v.update(full_refusal_workspace_bytes_hashed=1)),
            ("control-patch-changed",lambda v:v["controls"][9]["patches"][0].update(bytes="0000000000000000")),
            ("control-original-inflation",lambda v:v.update(original_execution_qualified=True)),
        ):refuse(name,controls,controlpath,lambda raw,fn=fn:edited(raw,fn))
        refuse("control-input-changed",controls,one/"controls/control-0.input.bin",lambda raw:b"x"+raw[1:])
        refuse("control-complete-workspace-changed",controls,one/"controls/initial.workspace.gz",
            lambda raw:gzip.compress(b"x"+gzip.decompress(raw)[1:],compresslevel=1,mtime=0))
        # Process mutations are made in the actual complete records consumed by
        # the same strict reader, with the actual stream files still reread.
        for name,fn in (("process-timed-out",lambda p:p[1].update(timed_out=True)),
                        ("process-not-complete",lambda p:p[1].update(completed=False)),
                        ("process-source-command",lambda p:p[1]["argv"].__setitem__(1,p[1]["argv"][1]+".wrong")),
                        ("process-deadline",lambda p:p[1].update(timeout_seconds=181))):
            changed=json.loads(json.dumps(native_processes));fn(changed)
            try:native(one,changed)
            except (ValueError,AssertionError,KeyError,OSError)as error:
                report["controls"].append(dict(name=name,status="REFUSED",error_type=type(error).__name__,reason=str(error)[:240]));save()
            else:raise AssertionError("strict reader accepted process mutation: "+name)
        # A physical symlink to another valid capture must not substitute for
        # the current copy's owned evidence file.
        linked=one/"native/result.json";original=q.read(linked)
        linked.unlink();linked.symlink_to(two/"native/result.json")
        try:
            try:native(one)
            except (ValueError,OSError)as error:
                report["controls"].append(dict(name="foreign-copy-symlink",status="REFUSED",error_type=type(error).__name__,reason=str(error)[:240]));save()
            else:raise AssertionError("cross-copy symbolic link accepted")
        finally:
            linked.unlink();linked.write_bytes(original)
        q.require(all(q.file_pin(one/name)==identities[name] and q.file_pin(two/name)==identities[name]for name in files),"control copies not fully restored")
        q.require(native(one)==baseline_native and controls(one)==baseline_controls,"post-refusal complete reader differs")
        q.require(tuple(row["name"] for row in report["controls"]) == NAMES and len(report["relocations"])==2,"reader control domain incomplete")
        report["status"]="READER_CONTROLS_PASS"
        report["admitted_files"]=identities
    finally:
        report["elapsed_seconds"]=time.monotonic()-started;save()
    # Retire only these exact disposable copies after every complete reader and
    # refusal has passed; failures retain their full diagnostic bytes.
    shutil.rmtree(one);shutil.rmtree(two)
    print(json.dumps(dict(status=report["status"],controls=len(report["controls"]),relocations=len(report["relocations"]),
        native_processes_executed=0,elapsed_seconds=report["elapsed_seconds"]),sort_keys=True))


if __name__=="__main__":main()
