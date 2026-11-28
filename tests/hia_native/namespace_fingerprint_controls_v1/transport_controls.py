"""Actual native exported admission refusals and same-buffer recovery; no effect substitute."""
from pathlib import Path
import ctypes as C,gzip,os,struct,sys,time
from contextlib import ExitStack
CONTROL_ROOT=Path(__file__).resolve().parent
from common import ROOT,encoded,loads,pin,read,require,source
from callable_loader import Callable
from callable_contract import CONTEXT_BYTES,semantic,word
from fixture import setup,snapshot,retire
from transport_cases import SPECS,wire,sequence,argv,mutate,source_case
import control_common as rc
ORDER=("input","output","context","table")
def run(build,output,fixture):
    identity=source();control_identity=rc.source();output.mkdir(parents=True,exist_ok=False)
    require(not fixture.exists()and not fixture.is_symlink(),"fresh exclusively owned control fixture")
    fixture.mkdir(mode=0o700,parents=True)
    rows=[];observations=[];retirements=[];completed=False
    with ExitStack()as resources:
        machine=Callable(build/"callable/manifest.json",loads(read(build/"callable/BINDING.json")))
        resources.callback(machine.close)
        loaded_image=dict(address=machine.module._address,bytes=machine.module._size)
        exports={name:machine.module._address+machine.composition["offsets"][name]for name in("entry","initialize","dispose")}
        raw_stream=resources.enter_context((output/"buffers.bin.gz").open("xb"))
        stream=resources.enter_context(gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=raw_stream,mtime=0))
        stream.write(b"NFCTLOG1")
        try:
            (output/"LIBC.bin").write_bytes(machine.libc_bytes)
            (output/"LIBC-BINDINGS.json").write_bytes(encoded(machine.bindings))
            (output/"PROCESS-MAPS.txt").write_bytes(Path("/proc/self/maps").read_bytes())
            for index,spec in enumerate(SPECS):
                folder=fixture/("case-%04d"%index);setup(folder,source_case())
                descriptor=os.open(folder,os.O_RDONLY|os.O_CLOEXEC)
                try:
                    bodies=dict(input=wire()+b"\xc3"*16,output=b"\xa5"*144,context=bytes(CONTEXT_BYTES)+b"\x5a"*16,
                                table=bytes(machine.table))
                    allocated={name:C.create_string_buffer(value,len(value))for name,value in bodies.items()}
                    addresses={name:C.addressof(value)for name,value in allocated.items()};addresses["root"]=descriptor
                    before_fs=snapshot(folder)
                    for phase,function,parameters,mutations,expected in sequence(spec):
                        prior={name:value.raw for name,value in allocated.items()};changed=mutate(prior,mutations)
                        for name in ORDER:C.memmove(addresses[name],changed[name],len(changed[name]))
                        before=[allocated[name].raw for name in ORDER];arguments=argv(function,parameters,addresses)
                        start=time.monotonic_ns();returned=int(getattr(machine,function)(*arguments));elapsed=time.monotonic_ns()-start
                        after=[allocated[name].raw for name in ORDER]
                        row=dict(index=len(rows),case=index,name=spec[0]+"/"+spec[1],phase=phase,function=function,parameters=parameters,
                            mutations=[list(x)for x in mutations],expected=expected,returned=returned,addresses=addresses,
                            arguments=arguments,elapsed_ns=elapsed,before=[pin(x)for x in before],after=[pin(x)for x in after])
                        meta=encoded(row);stream.write(b"NFCTCALL"+struct.pack("<7Q",len(rows),returned,len(meta),*map(len,before))+meta)
                        for body in before+after:stream.write(body)
                        rows.append(row)
                        require(returned==expected,"actual complete exported result: "+row["name"]+"/"+phase)
                        if phase=="refusal":
                            require(before==after,"all actual admission-refusal buffers unchanged")
                            for name in ORDER:C.memmove(addresses[name],prior[name],len(prior[name]))
                        elif phase=="recovery-run":
                            require(after[0]==before[0]and after[3]==before[3]and after[1][128:]==b"\xa5"*16 and
                                    after[2][CONTEXT_BYTES:]==b"\x5a"*16 and word(after[2],8)==0,"whole real recovery and guards")
                            result=semantic(after[1][:128])
                            require(result==dict(kind=1,errno=20,digest="00"*32),"actual unchanged original non-directory error")
                            observations.append(dict(case=index,name=row["name"],native_frame_hex=after[1][:128].hex(),
                                semantic=result,before=before_fs,after=snapshot(folder)))
                    require(allocated["context"].raw==bytes(CONTEXT_BYTES)+b"\x5a"*16 and before_fs==snapshot(folder),
                            "whole actual context disposal and untouched original fixture")
                    actual=os.fstat(descriptor);root=before_fs["entries"][0]
                    require((actual.st_dev,actual.st_ino,actual.st_mode)==(root["device"],root["inode"],root["type"]|root["mode"]),
                            "borrowed root remains open through disposal")
                finally:os.close(descriptor)
                retirements.append(retire(folder,snapshot(folder)))
            require(len(rows)==4*len(SPECS)and len(observations)==len(SPECS),"entire admission and same-buffer recovery domain")
            stream.write(b"NFCTEND1"+struct.pack("<Q",len(rows)));completed=True
        finally:
            (output/"CALLS.json").write_bytes(encoded(rows));(output/"OBSERVATIONS.json").write_bytes(encoded(observations))
            (output/"RETIREMENT.json").write_bytes(encoded(dict(owned_root=str(fixture),cases=retirements,completed=completed)))
    require(completed,"complete exported native controls");fixture.rmdir()
    require(source()==identity and rc.source()==control_identity,"whole fixed native/control source unchanged")
    report=dict(schema="hepta.namespace-fingerprint.transport-controls.v1",status="PASS",
        source_manifest_sha256=identity,control_source_sha256=control_identity,cases=len(SPECS),actual_calls=len(rows),
        refusals=len(SPECS),recoveries=len(SPECS),original_rust_replay=0,
        pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),
        source_root=str(CONTROL_ROOT),original_source_root=str(ROOT),output_root=str(output),fixture=str(fixture),build_root=str(build),
        callable=pin(read(build/"callable/callable.image.bin")),loaded_image=loaded_image,exports=exports,
        files={name:pin(read(output/name))for name in("CALLS.json","OBSERVATIONS.json","RETIREMENT.json","buffers.bin.gz",
            "LIBC.bin","LIBC-BINDINGS.json","PROCESS-MAPS.txt")},
        admission_only_refusal_atomicity=True,foreign_executable_capabilities=False,
        namespace_version_qualified=False,public_handler_qualified=False)
    (output/"CONTROLS.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
