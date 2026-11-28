"""Fresh locked original per private service lifetime; complete streams and owned cleanup."""
from pathlib import Path
import argparse,os,selectors,struct,subprocess,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from common import encoded,pin,read,require,source
from protocol import cases,initial,validate_semantic
from fixture import setup,snapshot,finish,apply
def run(binary,output,fixture,group):
    identity=source();rows=cases(ROOT,group);output.mkdir(parents=True,exist_ok=False);setup(fixture,rows)
    observations=[];processes=[];start=time.monotonic();deadline=start+60
    env=dict(os.environ);env.pop("HEPTA_REQUEST_AUDIT_TRACE",None)
    try:
        for ci,case in rows:
            folder=fixture/("case-%04d"%ci);part=output/("case-%04d"%ci);part.mkdir()
            stderr=(part/"stderr").open("xb");incoming=(part/"stdin").open("xb");outgoing=(part/"stdout").open("xb")
            selector=selectors.DefaultSelector();process=None;success=False;failure=None;began=time.monotonic()
            argv=[str(binary),str(folder),group,str(ci)]
            try:
                require(time.monotonic()<deadline,"same complete original group 60-second limit")
                process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,env=env)
                pgid=os.getpgid(process.pid);require(pgid==os.getpgrp(),"child retains owned process group")
                os.set_blocking(process.stdout.fileno(),False);selector.register(process.stdout,selectors.EVENT_READ)
                def exact(size):
                    raw=bytearray()
                    while len(raw)<size:
                        left=deadline-time.monotonic();require(left>0 and selector.select(left),"original bounded response readiness")
                        part_raw=os.read(process.stdout.fileno(),size-len(raw));require(part_raw,"original complete extent before EOF")
                        outgoing.write(part_raw);raw.extend(part_raw)
                    return bytes(raw)
                for si,step in enumerate(case["steps"]):
                    apply(folder,step["actions"]);before=snapshot(folder);wire=initial(ci,si,case)
                    framed=struct.pack("<Q",len(wire))+wire
                    incoming.write(framed);incoming.flush();process.stdin.write(framed);process.stdin.flush()
                    size=struct.unpack("<Q",exact(8))[0];require(size==64,"exact original terminal extent")
                    result=validate_semantic(exact(size))
                    observations.append(dict(case=ci,step=si,initial_hex=wire.hex(),semantic_hex=result.hex(),before=before,after=snapshot(folder)))
                process.stdin.close()
                while True:
                    left=deadline-time.monotonic();require(left>0 and selector.select(left),"original terminal deadline")
                    tail=os.read(process.stdout.fileno(),65536)
                    if not tail:break
                    outgoing.write(tail);raise ValueError("unframed original tail")
                require(process.wait(timeout=max(.001,deadline-time.monotonic()))==0,"original actual successful exit")
                success=True
            except BaseException as error:failure=error
            finally:
                try:
                    if process is not None and process.poll() is None:process.kill()
                    if process is not None:
                        process.wait()
                        if process.stdin is not None and not process.stdin.closed:process.stdin.close()
                        if process.stdout is not None:process.stdout.close()
                finally:
                    selector.close();stderr.close();incoming.close();outgoing.close()
                    row=dict(case=ci,argv=argv,pid=None if process is None else process.pid,parent_pid=os.getpid(),pgid=os.getpgrp(),
                        exit_code=None if process is None else process.returncode,success=success,elapsed_seconds=time.monotonic()-began,
                        source_root=str(ROOT),owned_root=str(folder),group=group,timeout_seconds=60,
                        streams={name:pin(read(part/name)) for name in ("stdin","stdout","stderr")},binary=pin(read(binary)))
                    if failure is not None:row["failure"]=repr(failure)
                    (part/"process.json").write_bytes(encoded(row));processes.append(row)
                    (output/"processes.json").write_bytes(encoded(processes))
                    (output/"OBSERVATIONS.json").write_bytes(encoded(observations))
            if failure is not None:raise failure
    finally:
        (output/"OBSERVATIONS.json").write_bytes(encoded(observations))
    require(len(observations)==sum(len(row["steps"]) for _,row in rows),"all exact original operations")
    retirement=finish(fixture,rows);(output/"RETIREMENT.json").write_bytes(encoded(retirement))
    require(source()==identity,"original fixture entire frozen source unchanged")
    report=dict(schema="hepta.audit-anchor-publish.original.v1",status="PASS",group=group,cases=len(rows),operations=len(observations),
        source_manifest_sha256=identity,pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),elapsed_seconds=time.monotonic()-start,
        source_root=str(ROOT),output_root=str(output),owned_root=str(fixture),timeout_seconds=60,
        observations=pin(read(output/"OBSERVATIONS.json")),processes=pin(read(output/"processes.json")),
        retirement=pin(read(output/"RETIREMENT.json")),binary=pin(read(binary)),uid=os.geteuid(),gid=os.getegid())
    (output/"ORIGINAL.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("binary","output","fixture"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args()
    run(a.binary.resolve(strict=True),a.output.absolute(),a.fixture.absolute(),a.group)
