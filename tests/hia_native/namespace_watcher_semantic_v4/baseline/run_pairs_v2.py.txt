"""Three owned processes inspect each one real physical tree, with no semantic replay."""
from pathlib import Path
import argparse,os,selectors,subprocess,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source
from protocol import cases,line,require_semantic
from fixture import setup,apply,snapshot,retire,root_path
from trace_scope import Reaper,traced,process_identity
class Child:
    def __init__(self,role,argv,folder,deadline):
        self.role=role;self.argv=[str(x)for x in argv];self.folder=folder
        self.deadline=deadline;self.process=None;self.selector=None
        self.incoming=self.outgoing=self.error=None;self.buffer=b""
        self.rows=[];self.ready=None;self.started=None;self.success=False;self.failure=None
        self.trace_argv=None;self.application_identity=None;self.tracer_identity=None
    def start(self):
        self.folder.mkdir();self.started=time.monotonic()
        self.incoming=(self.folder/"stdin").open("xb")
        self.outgoing=(self.folder/"stdout").open("xb")
        self.error=(self.folder/"stderr").open("xb")
        self.selector=selectors.DefaultSelector()
        self.trace_argv=traced(self.argv,self.folder/"syscalls.strace")
        self.process=subprocess.Popen(self.trace_argv,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.error)
        require(os.getpgid(self.process.pid)==os.getpgrp(),"tracer remains within the single owned group")
        os.set_blocking(self.process.stdout.fileno(),False)
        self.selector.register(self.process.stdout,selectors.EVENT_READ)
        raw=self.receive();self.ready=loads(raw)
        require(self.ready["command"]=="ready"and self.ready["role"]==self.role and
                self.ready["parent_pid"]==self.process.pid and self.ready["pgid"]==os.getpgrp(),
                "actual application ready from its one owned tracer")
        self.application_identity=process_identity(self.ready["pid"])
        self.tracer_identity=process_identity(self.process.pid)
        require(self.application_identity["parent_pid"]==self.process.pid and
                self.tracer_identity["parent_pid"]==os.getpid()and
                self.application_identity["pgid"]==self.tracer_identity["pgid"]==os.getpgrp()and
                self.application_identity["session"]==self.tracer_identity["session"]==os.getsid(0),
                "complete real application/tracer/owner PID, process group and session chain")
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
            self.buffer+=raw;require(len(self.buffer)<=16*1024*1024,"complete full callback buffers within frozen response bound")
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
        row=dict(role=self.role,argv=self.argv,cwd=str(ROOT),group=group,
            pid=None if self.ready is None else self.ready.get("pid"),
            parent_pid=None if self.process is None else self.process.pid,owner_pid=os.getpid(),
            tracer_pid=None if self.process is None else self.process.pid,tracer_argv=self.trace_argv,
            application_identity=self.application_identity,tracer_identity=self.tracer_identity,
            pgid=os.getpgrp(),timeout_seconds=60,
            elapsed_seconds=None if self.started is None else time.monotonic()-self.started,
            exit_code=None if self.process is None else self.process.returncode,success=self.success,failure=self.failure,
            ready=self.ready,exchanges=len(self.rows),streams={name:pin(read(self.folder/name))for name in("stdin","stdout","stderr","syscalls.strace")
                if(self.folder/name).exists()})
        (self.folder/"EXCHANGES.json").write_bytes(encoded(self.rows))
        (self.folder/"PROCESS.json").write_bytes(encoded(row));return row
def run(retained,binary,output,fixture,group):
    identity=source();wanted=cases(group);output.mkdir(parents=True,exist_ok=False)
    require(os.geteuid()>0,"actual unprivileged OS permission domain")
    require(not fixture.exists()and not fixture.is_symlink(),"fresh own group fixture")
    fixture.mkdir(parents=True,mode=0o700);(output/"roles").mkdir()
    started=time.monotonic();deadline=started+60;children=[];observations=[];retirements=[];initials=[]
    failure=None;cleanup_errors=[];processes=[];reaper=Reaper();adopted=[]
    try:
        python=Path(sys.executable).resolve(strict=True)
        for role in("native-observed","native-off","original"):
            folder=output/"roles"/role
            if role=="original":argv=[binary,group]
            else:argv=[python,"-I","-B",ROOT/"native_child.py","--retained",retained,"--output",folder/"capture",
                "--group",group,"--observer","on"if role=="native-observed"else"off"]
            child=Child(role,argv,folder,deadline);children.append(child);child.start()
        require(len({c.ready["pid"]for c in children})==3 and
            all(c.ready["layout"]==children[0].ready["layout"]for c in children),"three actual processes and same real descriptor placement")
        for case in wanted:
            ci=case["case"];folder=fixture/("case-%04d"%ci);setup(folder,case)
            initial=snapshot(folder)
            roots=[dict(path_hex=root_path(folder,case,i).hex(),late=r["late"])for i,r in enumerate(case["roots"])]
            command=dict(cmd="prepare",case=ci,roots=roots);answers=[];after=[]
            for child in children:
                answers.append(child.exchange(command));after.append(snapshot(folder))
                require(after[-1]==initial,"prepare preserves complete physical tree")
            require(answers[0]==answers[1]==answers[2],"exact same actual root descriptors/metadata/Arc state")
            require(answers[0]["state"]["watchers"]==[],"fresh original Watcher set")
            rootrows={r["path_hex"]:r for r in initial["entries"]}
            expected=[]
            for i,r in enumerate(case["roots"]):
                if r["late"]:continue
                actual=rootrows[r["name"].encode().hex()]
                expected.append(dict(root=i,fd=512+i,strong_count=1,device=actual["device"],
                    inode=actual["inode"],mode=actual["type"]|actual["mode"]))
            require(answers[0]["state"]["roots"]==expected,"same full actual initial root identity")
            initials.append(dict(case=ci,owned_root=str(folder),snapshot=initial,after=after,replies=answers))
            for si,step in enumerate(case["steps"]):
                apply(folder,case,step["actions"]);before=snapshot(folder);answers=[];after=[]
                command=dict(cmd="run",case=ci,step=si,operation=step["operation"])
                for child in children:
                    value=child.exchange(command)
                    require(value["step"]==si and value["operation"]==step["operation"]["op"],"same complete source operation")
                    require_semantic(value["semantic"]);answers.append(value);after.append(snapshot(folder))
                    require(after[-1]==before,"each actual Watcher leaves the entire owned tree unchanged")
                for name in("semantic","state","callback"):
                    require(answers[0][name]==answers[1][name]==answers[2][name],
                        "all complete original/native states, results and original callback buffers: "+name)
                require(answers[0]["native_frame_hex"]==answers[1]["native_frame_hex"],
                    "observer absent preserves every actual terminal byte")
                observations.append(dict(case=ci,step=si,operation=step["operation"]["op"],
                    before=before,after=after,answers=answers))
            for child in children:
                answer=child.exchange(dict(cmd="finish",case=ci))
                require(answer==dict(command="finish",case=ci,all_owned_descriptors_closed=True),
                    "every original/native Watcher and caller root actually closed")
            final=snapshot(folder);retirements.append(dict(case=ci,**retire(folder,final)))
        for child in children:child.end_input()
        for child in children:child.finish()
        require(len(observations)==sum(len(c["steps"])for c in wanted),"every frozen case and source operation")
        fixture.rmdir()
    except BaseException as error:
        failure=error
        for child in children:child.failure=repr(error)
        raise
    finally:
        # No write, close or failed child can skip cleanup of any other child.
        for child in children:
            try:child.kill()
            except BaseException as error:cleanup_errors.append("kill:"+repr(error))
        for child in children:
            try:child.wait()
            except BaseException as error:cleanup_errors.append("wait:"+repr(error))
        try:adopted=reaper.finish()
        except BaseException as error:cleanup_errors.append("reap-and-restore:"+repr(error))
        for child in children:
            try:processes.append(child.seal(group))
            except BaseException as error:cleanup_errors.append("seal:"+repr(error))
        writes={"INITIALS.json":initials,"OBSERVATIONS.json":observations,
            "RETIREMENT.json":retirements,"PROCESSES.json":processes,
            "TRACE-CUSTODY.json":dict(owner_pid=os.getpid(),owner_pgid=os.getpgrp(),
                prior_subreaper=reaper.prior,restored=not reaper.active,adopted_reaps=adopted,
                kill_on_tracer_exit=True,trace_scope="all-three-applications-entire-lifetimes",
                complete_driver_snapshots_retained=True)}
        if failure is not None or cleanup_errors:
            writes["FAILURE.json"]=dict(error=repr(failure),cleanup_errors=cleanup_errors)
            if fixture.exists():writes["FAILED-OWNED-TREE.json"]=snapshot(fixture)
        errors=[]
        for name,value in writes.items():
            try:(output/name).write_bytes(encoded(value))
            except BaseException as error:errors.append(repr(error))
        require(not errors,"all original success/failure evidence writes completed: "+repr(errors))
    require(not cleanup_errors and not adopted and not fixture.exists()and not fixture.is_symlink(),
        "complete normal tracer reaps, no unexpected adopted child, and exact tree retirement")
    require(source()==identity,"complete frozen source unchanged")
    report=dict(schema="hepta.namespace-watcher.same-tree-pair.v1",status="PASS",source_manifest_sha256=identity,
        group=group,cases=len(wanted),operations=len(observations),processes=3,source_root=str(ROOT),retained_root=str(retained),
        original_binary=pin(read(binary)),output_root=str(output),fixture_root=str(fixture),pid=os.getpid(),
        parent_pid=os.getppid(),pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),timeout_seconds=60,
        elapsed_seconds=time.monotonic()-started,
        files={name:pin(read(output/name))for name in("INITIALS.json","OBSERVATIONS.json","RETIREMENT.json","PROCESSES.json","TRACE-CUSTODY.json")},
        compared_complete_terminal_bytes=True,compared_complete_watcher_and_arc_state=True,
        application_processes=3,tracer_processes=3,driver_snapshots="unchanged-complete-before-and-after-each-application",
        namespace_version_qualified=False,public_handler_qualified=False)
    require(report["elapsed_seconds"]<=60,"same whole source group deadline includes every stream and cleanup")
    (output/"PAIRED.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in("retained","binary","output","fixture"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args()
    run(a.retained.resolve(strict=True),a.binary.resolve(strict=True),a.output.absolute(),a.fixture.absolute(),a.group)
