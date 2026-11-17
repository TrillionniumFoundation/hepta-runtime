"""Three owned processes inspect each one real physical tree, with no semantic replay."""
from pathlib import Path
import argparse,os,selectors,subprocess,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source
from protocol import cases,line,require_semantic
from fixture import setup,apply,snapshot,retire
class Child:
    def __init__(self,role,argv,folder,deadline):
        self.role=role;self.argv=[str(x)for x in argv];self.folder=folder
        self.deadline=deadline;self.process=None;self.selector=None
        self.incoming=self.outgoing=self.error=None;self.buffer=b""
        self.rows=[];self.ready=None;self.started=None;self.success=False;self.failure=None
    def start(self):
        self.folder.mkdir();self.started=time.monotonic()
        self.incoming=(self.folder/"stdin").open("xb")
        self.outgoing=(self.folder/"stdout").open("xb")
        self.error=(self.folder/"stderr").open("xb")
        self.selector=selectors.DefaultSelector()
        self.process=subprocess.Popen(self.argv,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.error)
        require(os.getpgid(self.process.pid)==os.getpgrp(),"child remains within the single owned trace group")
        os.set_blocking(self.process.stdout.fileno(),False)
        self.selector.register(self.process.stdout,selectors.EVENT_READ)
        raw=self.receive();self.ready=loads(raw)
        require(self.ready["command"]=="ready"and self.ready["role"]==self.role and
                self.ready["pid"]==self.process.pid and self.ready["parent_pid"]==os.getpid()and
                self.ready["pgid"]==os.getpgrp(),"actual child identity and ready")
        return self.ready
    def chunk(self):
        left=self.deadline-time.monotonic()
        require(left>0 and self.selector.select(left),"same whole group 60-second deadline")
        raw=os.read(self.process.stdout.fileno(),65536)
        if raw:self.outgoing.write(raw)
        return raw
    def receive(self):
        while b"\n"not in self.buffer:
            raw=self.chunk();require(raw,"complete child line before EOF")
            self.buffer+=raw;require(len(self.buffer)<=65536,"bounded complete child response line")
        value,self.buffer=self.buffer.split(b"\n",1)
        return value+b"\n"
    def exchange(self,command):
        raw=line(command);self.incoming.write(raw);self.incoming.flush()
        self.process.stdin.write(raw);self.process.stdin.flush()
        answer=self.receive();value=loads(answer)
        require(value["command"]==command["cmd"] and value["case"]==command["case"],"same exact control response")
        self.rows.append(dict(index=len(self.rows),request=pin(raw),response=pin(answer),
            request_hex=raw.hex(),response_hex=answer.hex()))
        return value
    def end_input(self):
        if self.process is not None and self.process.stdin is not None and not self.process.stdin.closed:self.process.stdin.close()
    def finish(self):
        self.end_input();require(not self.buffer,"no unclaimed response suffix")
        while True:
            raw=self.chunk()
            if not raw:break
            raise ValueError("unexpected complete child EOF tail")
        require(self.process.wait(timeout=max(.001,self.deadline-time.monotonic()))==0,"actual complete child success exit")
        self.success=True
    def kill(self):
        if self.process is not None and self.process.poll()is None:self.process.kill()
    def wait(self):
        if self.process is not None:self.process.wait()
    def seal(self,group):
        if self.process is not None:
            if self.process.stdin is not None and not self.process.stdin.closed:self.process.stdin.close()
            if self.process.stdout is not None:self.process.stdout.close()
        if self.selector is not None:self.selector.close()
        for handle in (self.incoming,self.outgoing,self.error):
            if handle is not None:handle.close()
        row=dict(role=self.role,argv=self.argv,cwd=str(ROOT),group=group,pid=None if self.process is None else self.process.pid,
            parent_pid=os.getpid(),pgid=os.getpgrp(),timeout_seconds=60,
            elapsed_seconds=None if self.started is None else time.monotonic()-self.started,
            exit_code=None if self.process is None else self.process.returncode,success=self.success,failure=self.failure,
            ready=self.ready,exchanges=len(self.rows),streams={name:pin(read(self.folder/name))for name in("stdin","stdout","stderr")
                if(self.folder/name).exists()})
        (self.folder/"EXCHANGES.json").write_bytes(encoded(self.rows))
        (self.folder/"PROCESS.json").write_bytes(encoded(row));return row
def run(build,binary,output,fixture,group):
    identity=source();wanted=cases(group);output.mkdir(parents=True,exist_ok=False)
    require(not fixture.exists()and not fixture.is_symlink(),"fresh own group fixture")
    fixture.mkdir(parents=True,mode=0o700);(output/"roles").mkdir()
    started=time.monotonic();deadline=started+60;children=[];observations=[];retirements=[];initials=[]
    failure=None;cleanup_errors=[];processes=[]
    try:
        python=Path(sys.executable).resolve(strict=True)
        for role in("native-observed","native-off","original"):
            folder=output/"roles"/role
            if role=="original":argv=[binary,group]
            else:argv=[python,"-I","-B",ROOT/"native_child.py","--build",build,"--output",folder/"capture",
                "--group",group,"--observer","on"if role=="native-observed"else"off"]
            child=Child(role,argv,folder,deadline);children.append(child);child.start()
        require(len({c.ready["pid"]for c in children})==3,"three distinct real processes")
        for case in wanted:
            ci=case["case"];folder=fixture/("case-%04d"%ci);setup(folder,case)
            setup_snapshot=snapshot(folder);inits=[]
            for child in children:inits.append(child.exchange(dict(cmd="init",case=ci,path_hex=os.fsencode(folder).hex())))
            require(all(r["root_fd"]==96 and r["root_identity"]==inits[0]["root_identity"]for r in inits),
                    "same physical borrowed root across native observed/off and original")
            rootrow=setup_snapshot["entries"][0]
            require(inits[0]["root_identity"]==dict(device=rootrow["device"],inode=rootrow["inode"],
                        mode=rootrow["type"]|rootrow["mode"]),"complete captured root identity")
            require(inits[0]["environment"]==inits[1]["environment"]==inits[2]["environment"],
                    "exact same actual seccomp error environment")
            initials.append(dict(case=ci,owned_root=str(folder),snapshot=setup_snapshot,replies=inits))
            for si,step in enumerate(case["steps"]):
                apply(folder,step["actions"]);before=snapshot(folder);answers=[];after=[]
                command=dict(cmd="run",case=ci,step=si,generation=si+1)
                for child in children:
                    value=child.exchange(command)
                    require(value["step"]==si and value["generation"]==si+1,"same complete real operation")
                    require_semantic(value["semantic"]);answers.append(value);after.append(snapshot(folder))
                    require(after[-1]==before,"each real fingerprint leaves the entire owned tree unchanged")
                require(answers[0]["semantic"]==answers[1]["semantic"]==answers[2]["semantic"],
                        "actual observed/off native and unchanged original complete fingerprint/error match")
                require(answers[0]["native_frame_hex"]==answers[1]["native_frame_hex"],
                        "observer absent retains all 128 terminal bytes")
                observations.append(dict(case=ci,step=si,generation=si+1,before=before,after=after,answers=answers))
            for child in children:
                result=child.exchange(dict(cmd="dispose",case=ci))
                require(result==dict(command="dispose",case=ci,closed_root=True),"complete native/original borrowed-root release")
            final=snapshot(folder);retirements.append(dict(case=ci,**retire(folder,final)))
        for child in children:child.end_input()
        for child in children:child.finish()
        require(len(observations)==sum(len(c["steps"])for c in wanted),"entire frozen group domain")
        fixture.rmdir()
    except BaseException as error:
        failure=error
        for child in children:child.failure=repr(error)
        raise
    finally:
        # No evidence write can skip any real process cleanup.
        for child in children:
            try:child.kill()
            except BaseException as error:cleanup_errors.append(repr(error))
        for child in children:
            try:child.wait()
            except BaseException as error:cleanup_errors.append(repr(error))
        try:
            for child in children:processes.append(child.seal(group))
        finally:
            (output/"INITIALS.json").write_bytes(encoded(initials))
            (output/"OBSERVATIONS.json").write_bytes(encoded(observations))
            (output/"RETIREMENT.json").write_bytes(encoded(retirements))
            (output/"PROCESSES.json").write_bytes(encoded(processes))
            if failure is not None or cleanup_errors:
                (output/"FAILURE.json").write_bytes(encoded(dict(error=repr(failure),cleanup_errors=cleanup_errors)))
                if fixture.exists():
                    (output/"FAILED-OWNED-TREE.json").write_bytes(encoded(snapshot(fixture)))
    require(not cleanup_errors and not fixture.exists()and not fixture.is_symlink(),"owned cleanup and exact fixture retirement")
    require(source()==identity,"complete frozen source unchanged")
    report=dict(schema="hepta.namespace-fingerprint.same-tree-pair.v1",status="PASS",source_manifest_sha256=identity,
        group=group,cases=len(wanted),operations=len(observations),processes=3,source_root=str(ROOT),build_root=str(build),
        original_binary=pin(read(binary)),output_root=str(output),fixture_root=str(fixture),pid=os.getpid(),
        parent_pid=os.getppid(),pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),timeout_seconds=60,
        elapsed_seconds=time.monotonic()-started,
        files={name:pin(read(output/name))for name in("INITIALS.json","OBSERVATIONS.json","RETIREMENT.json","PROCESSES.json")},
        compared_complete_terminal_bytes=True,namespace_watch_qualified=False,public_handler_qualified=False)
    (output/"PAIRED.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in("build","binary","output","fixture"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args()
    run(a.build.resolve(strict=True),a.binary.resolve(strict=True),a.output.absolute(),a.fixture.absolute(),a.group)
