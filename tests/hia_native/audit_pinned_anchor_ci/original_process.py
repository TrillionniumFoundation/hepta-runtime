"""Persistent unchanged Rust record-I/O observer with owned setup, complete streams and cleanup."""
from pathlib import Path
import argparse
import os
import selectors
import signal
import struct
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from common import encoded,pin,read,require,source
from protocol import cases,initial,validate_semantic
from fixture import setup,snapshot,retire,apply

def run(binary,output,fixture):
    identity=source();domain=cases(ROOT);output.mkdir(parents=True,exist_ok=False)
    setup(fixture,domain)
    process=None;observations=[];success=False;exception=None
    started=time.monotonic();deadline=started+60
    before_env=dict(os.environ)
    before_env.pop('HEPTA_REQUEST_AUDIT_TRACE',None)
    stderr=(output/'original.stderr').open('xb')
    incoming=(output/'original.stdin').open('xb')
    outgoing=(output/'original.stdout').open('xb')
    selector=selectors.DefaultSelector()
    try:
        process=subprocess.Popen([str(binary),str(fixture)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=stderr,env=before_env)
        require(os.getpgid(process.pid)==os.getpgrp(),'reference retains owned outer process group')
        os.set_blocking(process.stdout.fileno(),False)
        selector.register(process.stdout,selectors.EVENT_READ)
        def exact(size):
            out=bytearray()
            while len(out)<size:
                left=deadline-time.monotonic()
                require(left>0,'original complete process 60 second deadline')
                require(selector.select(min(left,60)),'original bounded response readiness')
                raw=os.read(process.stdout.fileno(),size-len(out))
                require(raw,'original complete response before EOF')
                outgoing.write(raw);out.extend(raw)
            return bytes(out)
        for ci,case in enumerate(domain):
            folder=fixture/('case-%04d'%ci)
            for si,step in enumerate(case['steps']):
                apply(folder,step['actions']);before=snapshot(folder);wire=initial(ci,si,step)
                framed=struct.pack('<2Q',ci,len(wire))+wire
                incoming.write(framed);incoming.flush()
                process.stdin.write(framed);process.stdin.flush()
                size=struct.unpack('<Q',exact(8))[0]
                require(64<=size<=4096,'complete original result bound')
                result=validate_semantic(exact(size))
                observations.append(dict(case=ci,step=si,initial_hex=wire.hex(),
                    semantic_hex=result.hex(),before=before,after=snapshot(folder)))
        process.stdin.close()
        tail=bytearray()
        while True:
            left=deadline-time.monotonic()
            require(left>0,'original terminal 60 second deadline')
            require(selector.select(min(left,60)),'original EOF readiness')
            raw=os.read(process.stdout.fileno(),65536)
            if not raw:break
            outgoing.write(raw);tail.extend(raw)
        require(not tail,'no unframed original stdout')
        require(process.wait(timeout=max(.001,deadline-time.monotonic()))==0,'original actual exit zero')
        success=True
    except BaseException as error:
        exception=error
    finally:
        try:
            if process is not None and process.poll() is None:
                process.kill()
            if process is not None:
                process.wait()
                if process.stdin is not None and not process.stdin.closed:process.stdin.close()
                if process.stdout is not None:process.stdout.close()
        finally:
            selector.close();stderr.close();incoming.close();outgoing.close()
            (output/'OBSERVATIONS.json').write_bytes(encoded(observations))
            (output/'process.json').write_bytes(encoded(dict(
                argv=[str(binary),str(fixture)],pid=process.pid if process is not None else None,
                parent_pid=os.getpid(),pgid=os.getpgrp(),source_root=str(ROOT),owned_root=str(fixture),
                exit_code=process.returncode if process is not None else None,success=success,
                elapsed_seconds=time.monotonic()-started,timeout_seconds=60,
                trace_environment_absent='HEPTA_REQUEST_AUDIT_TRACE' not in before_env,
                stdin=pin(read(output/'original.stdin')),stdout=pin(read(output/'original.stdout')),
                stderr=pin(read(output/'original.stderr')),
                binary=pin(read(binary)))))
    if exception is not None:raise exception
    retirement=retire(fixture,domain)
    (output/'RETIREMENT.json').write_bytes(encoded(retirement))
    require(source()==identity,'original fixture source unchanged')
    result=dict(schema='hepta.audit-pinned-anchor.original.v1',status='PASS',cases=len(domain),operations=sum(len(c['steps']) for c in domain),
        source_manifest_sha256=identity,observations=pin(read(output/'OBSERVATIONS.json')),
        retirement=pin(read(output/'RETIREMENT.json')),process=pin(read(output/'process.json')))
    (output/'ORIGINAL.json').write_bytes(encoded(result))
    print(encoded(result).decode(),end='')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--fixture',type=Path,required=True)
    a=p.parse_args();run(a.binary.resolve(strict=True),a.output.absolute(),a.fixture.absolute())
