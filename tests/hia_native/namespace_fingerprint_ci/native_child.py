"""One native process; the fixed callable owns all fingerprint effects."""
from pathlib import Path
import argparse,ctypes as C,os,struct,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import encoded,loads,pin,read,require,source
from protocol import line,require_semantic
from environment_policy import reserve,open_root,install,ROOT_FD
from callable_loader import Callable
from callable_contract import CONTEXT_BYTES,initial,response,semantic,word
from observe_callable import Observe
from outer import Outer
def emit(value):sys.stdout.buffer.write(line(value));sys.stdout.buffer.flush()
def mark(tag,case,generation):
    raw=tag+struct.pack("<2Q",case,generation);require(os.write(2,raw)==len(raw),"complete native syscall marker")
def run(build,output,group,observed):
    identity=source();output.mkdir(parents=True,exist_ok=False)
    require(os.geteuid()!=0,"unprivileged ordinary and permission domains")
    machine=observer=outer=None;selected=directory=context=None
    contexts=[];observations=[];counts=dict(owner_calls=0,boundary_calls=0)
    installed=None;completed=False;layout=None
    try:
        component=loads(read(build/"callable/BINDING.json"));machine=Callable(build/"callable/manifest.json",component)
        loaded=dict(address=machine.module._address,bytes=machine.module._size)
        for name,raw in (("LIBC.bin",machine.libc_bytes),("LIBC-BINDINGS.json",encoded(machine.bindings)),
                         ("PROCESS-MAPS.txt",Path("/proc/self/maps").read_bytes())):(output/name).write_bytes(raw)
        outer=Outer(output)
        if observed:observer=Observe(output)
        layout=reserve()
        ready=dict(command="ready",role="native-observed"if observed else"native-off",pid=os.getpid(),
            parent_pid=os.getppid(),pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),group=group,
            layout=layout,source_manifest_sha256=identity,loaded_image=loaded,
            callable=pin(read(build/"callable/callable.image.bin")))
        # No file is left in the vacant stream slot by this complete read.
        emit(ready)
        for raw in sys.stdin.buffer:
            require(raw.endswith(b"\n")and len(raw)<=16384,"complete owned fixture command")
            command=loads(raw);kind=command["cmd"];case=command["case"]
            require(type(case)is int and case>=0,"exact fixture case")
            if kind=="init":
                require(selected is None and directory is None and context is None,"no replaced native context")
                path=bytes.fromhex(command["path_hex"]);require(path.hex()==command["path_hex"]and b"\0"not in path,"complete root bytes")
                directory=open_root(path);info=os.fstat(directory)
                if installed is None:installed=install(group)
                context=machine.new_context();base=C.addressof(context)
                callback=0 if observer is None else C.cast(observer.callback,C.c_void_p).value
                before=(b"",b"",context.raw,bytes(machine.table));began=time.monotonic_ns()
                returned=machine.init(context,directory,None if observer is None else observer.callback)
                elapsed=time.monotonic_ns()-began;after=(b"",b"",context.raw,bytes(machine.table))
                outer.record(case,0,0,returned,before,after,elapsed,dict(directory=directory,table=C.addressof(machine.table),observer=callback,user=0))
                require(returned==0 and after[3]==before[3],"actual native initialization")
                selected=case
                row=dict(case=case,context=base,table=C.addressof(machine.table),observer=callback,root_fd=directory,
                    root_identity=dict(device=info.st_dev,inode=info.st_ino,mode=info.st_mode))
                contexts.append(row)
                emit(dict(command="init",case=case,root_fd=directory,root_identity=row["root_identity"],environment=installed))
            elif kind=="run":
                step=command["step"];generation=command["generation"]
                require(selected==case and context is not None and type(step)is int and type(generation)is int and
                        generation>word(context.raw,16),"actual same-session generation")
                wire=initial(generation);base=C.addressof(context)
                first=None if observer is None else len(observer.rows)
                if observer is not None:observer.select(case,step,base)
                mark(b"NFNATB01",case,generation);table=bytes(machine.table);began=time.monotonic_ns()
                returned,before3,after3=machine.run(wire,context)
                elapsed=time.monotonic_ns()-began;mark(b"NFNATE01",case,generation)
                outer.record(case,step,1,returned,(*before3,table),(*after3,bytes(machine.table)),elapsed,dict(observer=observed))
                require(returned==128,"actual native terminal return")
                full=after3[1][:128];result=response(full)
                require(result["kind"]<2 and result["generation"]==generation,"native terminal generation")
                require(context.raw[:8]==b"HNFCTX01"and word(context.raw,8)==0 and word(context.raw,48)==0 and
                        word(context.raw,112)==(1<<64)-1 and word(context.raw,120)==0 and word(context.raw,136)==0 and
                        word(context.raw,160)==0,"complete quiescent native ownership")
                require(context.raw[64:112]==table[:48] and bytes(machine.table)==table,"fixed actual libc table")
                if observer is not None:
                    require(not observer.errors and observer.pending is None and observer.ack is None,
                            "entire actual callback sequence: "+repr(observer.errors))
                    require(observer.last_terminal==full,"complete HIA terminal delivered by native")
                result=semantic(full);require_semantic(result)
                observations.append(dict(case=case,step=step,generation=generation,initial_hex=wire.hex(),
                    first_record=first,last_record=None if observer is None else len(observer.rows)-1,
                    native_frame_hex=full.hex(),semantic=result))
                emit(dict(command="run",case=case,step=step,generation=generation,semantic=result,
                    native_frame_hex=full.hex(),returned=returned))
            elif kind=="dispose":
                require(selected==case and context is not None,"native owned context disposal")
                base=C.addressof(context);counts["owner_calls"]+=word(context.raw,56);counts["boundary_calls"]+=word(context.raw,184)
                before=(b"",b"",context.raw,bytes(machine.table));began=time.monotonic_ns()
                returned=int(machine.dispose(base,CONTEXT_BYTES));elapsed=time.monotonic_ns()-began
                after=(b"",b"",context.raw,bytes(machine.table))
                outer.record(case,0,2,returned,before,after,elapsed,{})
                require(returned==0 and context.raw==bytes(CONTEXT_BYTES)+b"\x5a"*16 and after[3]==before[3],
                        "complete real native disposal")
                still=os.fstat(directory);expected=contexts[-1]["root_identity"]
                require((still.st_dev,still.st_ino,still.st_mode)==tuple(expected[k]for k in("device","inode","mode")) or
                        (still.st_dev,still.st_ino)==(expected["device"],expected["inode"]),"borrowed directory not closed by callable")
                os.close(directory);directory=None;context=None;selected=None
                emit(dict(command="dispose",case=case,closed_root=True))
            else:raise ValueError("unlisted native fixture command")
        require(selected is None and context is None and directory is None,"EOF after native disposal")
        completed=True
    finally:
        # Cleanup does not synthesize any successful effect or target completion.
        try:
            if directory is not None:os.close(directory)
        finally:
            try:
                if observer is not None:observer.close(completed)
            finally:
                try:
                    if outer is not None:outer.close(completed)
                finally:
                    if machine is not None:machine.close()
        (output/"CONTEXTS.json").write_bytes(encoded(contexts));(output/"OBSERVATIONS.json").write_bytes(encoded(observations))
        (output/"ENVIRONMENT.json").write_bytes(encoded(installed));(output/"LAYOUT.json").write_bytes(encoded(layout))
    report=dict(schema="hepta.namespace-fingerprint.native-child.v1",status="PASS",source_manifest_sha256=identity,
        group=group,observer_enabled=observed,pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),
        uid=os.geteuid(),gid=os.getegid(),source_root=str(ROOT),output_root=str(output),build_root=str(build),
        loaded_image=loaded,callable=pin(read(build/"callable/callable.image.bin")),cases=len(contexts),
        operations=len(observations),outer_calls=len(outer.rows),counts=counts,
        records=0 if observer is None else len(observer.rows),
        files={name:pin(read(output/name))for name in ("LIBC.bin","LIBC-BINDINGS.json","PROCESS-MAPS.txt",
            "CONTEXTS.json","OBSERVATIONS.json","ENVIRONMENT.json","LAYOUT.json","outer.bin.gz","OUTER.json")+
            (()if observer is None else("records.bin.gz","RECORDS.json","OBSERVER-ERRORS.json","FAILED-PENDING.bin"))})
    (output/"NATIVE.json").write_bytes(encoded(report))
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--group",required=True);p.add_argument("--observer",choices=("on","off"),required=True)
    a=p.parse_args();run(a.build.resolve(strict=True),a.output.absolute(),a.group,a.observer=="on")
