"""Fixed adapter fault controls; synthetic errno is separate from original parity."""
from pathlib import Path
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import shutil
import signal
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from directory_service_kernel import LIBC, WALL, OPTIONS, ptrace, syscall_info, cstring
from directory_service_support import configuration, exclusive, require, words

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CASES = (
    ('wake-pipe', 293, 1, 24, 'parent', False),
    ('fence-input-pipe', 293, 2, 24, 'parent', False),
    ('fence-output-pipe', 293, 3, 24, 'parent', False),
    ('fence-exec-error-pipe', 293, 4, 24, 'parent', False),
    ('embedded-memfd', 319, 1, 24, 'parent', False),
    ('fence-fork', 57, 1, 11, 'parent', False),
    ('fence-exec', 322, 1, 8, 'fence', False),
    ('fence-parent-death-setup', 157, 1, 1, 'fence', False),
    ('mkdir-result-pipe', 293, 5, 24, 'parent', True),
    ('mkdir-fork', 57, 2, 11, 'parent', True),
    ('actual-broken-fence-pipe', 1, 3, 32, 'parent', False),
    ('actual-mkdir-worker-death', 258, 1, 0, 'worker', True),
)


def change_register(tid, index, value):
    registers = (ctypes.c_ulonglong * 27)()
    ptrace(12, tid, 0, ctypes.byref(registers))
    old = int(registers[index])
    registers[index] = value & ((1 << 64) - 1)
    ptrace(13, tid, 0, ctypes.byref(registers))
    return old


def run_case(binary, spec, root, output):
    name, number, ordinal, error, role, recover = spec
    base = root / name
    work, config, environment = configuration(base, fence=True)
    lock = os.open(base / 'authority/.owner.lock', os.O_RDONLY | os.O_CLOEXEC)
    target, following = work / 'held-effect', work / 'following-effect'
    ir, iw = os.pipe2(os.O_CLOEXEC)
    out_r, out_w = os.pipe2(os.O_CLOEXEC)
    err_r, err_w = os.pipe2(os.O_CLOEXEC)
    sr, sw = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            keep = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 16) for fd in (ir, out_w, err_w, sr)]
            for source, destination in zip(keep, (0, 1, 2, 4)):
                os.dup2(source, destination, inheritable=True)
            for value in os.listdir('/proc/self/fd'):
                fd = int(value)
                if fd not in (0, 1, 2, 4):
                    try: os.close(fd)
                    except OSError: pass
            ptrace(0, 0)
            os.execve(binary, [str(binary), '--runtime-config', str(config), '--session-root', str(work)],
                      {'PATH':'', 'USER':'operator', **environment})
        except BaseException as caught:
            os.write(2, (repr(caught)+'\n').encode()); os._exit(76)
    for fd in (ir, out_w, err_w, sr): os.close(fd)
    os.write(sw, words(b'HMDINIT1', 0, 0, 0)); os.close(sw)
    os.set_blocking(out_r, False); os.set_blocking(err_r, False)
    live, announced, deferred = {pid}, {pid}, {}
    exits, entries, counts = {}, {}, {}
    events, replies = [], []
    incoming, outgoing, errors = bytearray(), bytearray(), bytearray()
    cursor, fence_pid = 0, None
    selected = None
    injected = False
    injected_return = False
    held_parent = None
    actual_broken_return = False
    worker_killed = False
    program_kills = set()
    observer_kills = set()
    terminal_resume_races = set()
    terminal_observation_races = set()
    follow_sent = False
    follow_done = False
    closed = False
    started = time.monotonic()

    def begin(identifier, leaf):
        body = words(b'HMDCRQ02', len(leaf), 0, 0, 0) + leaf
        frame = words(b'HMDCTL01', 1, identifier, len(body)) + body
        wire = struct.pack('<Q', len(frame)) + frame
        require(os.write(iw, wire) == len(wire), 'short qualification input')
        incoming.extend(wire)

    def collect():
        nonlocal cursor, follow_sent, follow_done, closed
        for fd, target_bytes in ((out_r,outgoing),(err_r,errors)):
            while True:
                try: raw = os.read(fd, 65536)
                except BlockingIOError: break
                if not raw: break
                target_bytes.extend(raw)
        while len(outgoing)-cursor >= 8:
            count = struct.unpack_from('<Q',outgoing,cursor)[0]
            require(40 <= count <= 134217768, 'fault response bound')
            if len(outgoing)-cursor < count+8: break
            raw = bytes(outgoing[cursor+8:cursor+8+count]); cursor += count+8
            require(raw[:8] == b'HMDCTR01', 'fault response magic')
            event, identifier, code, length = struct.unpack_from('<4Q',raw,8)
            require(count == length+40, 'fault response shape')
            data = raw[40:]
            replies.append({'event':event,'id':identifier,'code':code,'payload_hex':data.hex()})
            if event == 1:
                require(identifier in (1,2) and code == 0 and not data, 'begin acknowledgement')
            elif event == 2:
                require(recover and code == len(data) and data[:8] == b'HMDCRS01', 'fault completion shape')
                tag, zero, length = struct.unpack_from('<3Q',data,8)
                require(zero == 0 and length == len(data)-32, 'fault result length')
                if identifier == 1:
                    require(tag == 1 and data[32:] == b'directory creation task failed', 'adapter failure diagnostic')
                    require(exclusive(lock) and not target.exists(), 'failed job retained authority/effect')
                    require(not follow_sent, 'duplicate failed-job completion')
                    follow_sent = True; begin(2,b'following-effect')
                elif identifier == 2:
                    require(tag == 0 and json.loads(data[32:]) == {'created':True,'exists_as_directory':True,'path':str(following)}, 'recovery effect')
                    require(follow_sent and not closed, 'recovery sequence')
                    follow_done = True; os.close(iw); closed = True
                else: raise AssertionError('unexpected completed id')
            else: raise AssertionError('unexpected event')

    try:
        got,status = os.waitpid(pid,0)
        if not (got == pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP):
            collect(); raise AssertionError(('owned trace initialization', status, errors.decode(errors='replace')))
        require(Path(f'/proc/{pid}/exe').resolve() == binary, 'trace executable identity')
        ptrace(0x4200,pid,0,OPTIONS); ptrace(24,pid)
        begin(1,b'held-effect')
        while live:
            require(time.monotonic()-started < 30, ('fixed adapter observation deadline',events,errors.decode(errors='replace')))
            collect()
            tid,status = os.waitpid(-1,WALL|os.WNOHANG)
            if not tid: time.sleep(0.0002); continue
            if tid not in live:
                require(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP and status >> 16 == 0,
                        ('unbound trace event',tid,status))
                state = dict(x.split(':',1) for x in Path(f'/proc/{tid}/status').read_text().splitlines() if ':' in x)
                require(int(state['TracerPid']) == os.getpid(), 'unowned tracee')
                live.add(tid); deferred[tid]=status; continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                live.remove(tid); exits[tid]=os.waitstatus_to_exitcode(status); entries.pop(tid,None)
                if tid == fence_pid and held_parent is not None:
                    require(exits[tid] == -9,'fence was not actually killed')
                    ptrace(24,held_parent); held_parent=None
                continue
            require(os.WIFSTOPPED(status),'unexpected wait state')
            stop,pe = os.WSTOPSIG(status),status >> 16
            delivery = 0
            if pe in (1,2,3):
                child=ctypes.c_ulonglong();ptrace(0x4201,tid,0,ctypes.byref(child))
                require(child.value not in announced,'duplicate task event')
                announced.add(child.value);live.add(child.value)
                events.append({'kind':'actual_task_created','parent':tid,'tid':child.value,'event':pe})
                if tid == pid and fence_pid is None: fence_pid=child.value
                if child.value in deferred: deferred.pop(child.value);ptrace(24,child.value)
            elif pe == 4:
                entries.pop(tid,None)
                events.append({'kind':'actual_exec','tid':tid,'executable':os.readlink(f'/proc/{tid}/exe')})
            elif stop == signal.SIGSTOP and tid != pid: pass
            elif stop == (signal.SIGTRAP|0x80):
                try:
                    stage,args=syscall_info(tid)
                except ProcessLookupError:
                    # A registered child can receive the adapter's SIGKILL
                    # after waitpid queued this stop. Do not invent its syscall
                    # or resume it: require the later fatal wait and a recorded
                    # successful owned kill before accepting this observation.
                    terminal_observation_races.add(tid)
                    events.append({'kind':'observation_raced_with_terminal_task','tid':tid})
                    continue
                if stage == 1:
                    entries[tid]=args
                    key=(tid,args[0]);counts[key]=counts.get(key,0)+1
                    match_role = tid == pid if role == 'parent' else tid == fence_pid if role == 'fence' else tid not in (pid,fence_pid)
                    hit = match_role and args[0] == number and counts[key] == ordinal and selected is None
                    if role == 'worker' and hit:
                        hit = cstring(tid,args[2]) == b'held-effect' and os.readlink(f'/proc/{tid}/fd/{args[1]}') == str(work)
                    if hit:
                        selected=tid
                        if name == 'actual-broken-fence-pipe':
                            require(args[3] == 8 and args[1] not in (0,1,2) and fence_pid in live,'selected actual fence pipe differs')
                            events.append({'kind':'actual_pipe_reader_killed','parent':pid,'reader':fence_pid,'fd':args[1],
                                'pipe':os.readlink(f'/proc/{tid}/fd/{args[1]}'),'write_bytes':args[3]})
                            held_parent=tid;observer_kills.add(fence_pid);os.kill(fence_pid,signal.SIGKILL);continue
                        if name == 'actual-mkdir-worker-death':
                            require(args[3] == 0o700 and not exclusive(lock),'worker lacks real permit')
                            worker_killed=True
                            observer_kills.add(tid)
                            events.append({'kind':'actual_submitted_worker_sigkill','tid':tid,'number':number})
                            os.kill(tid,signal.SIGKILL);continue
                        require(change_register(tid,15,-1) == number,'selected syscall register differs')
                        injected=True
                        events.append({'kind':'qualification_syscall_suppressed','tid':tid,'number':number,'ordinal':ordinal,
                            'synthetic_errno':error,'arguments':list(args[1:])})
                    if args[0] == 62 and args[2] == signal.SIGKILL:
                        require(args[1] in announced and args[1] != pid,'adapter killed an unregistered task')
                        events.append({'kind':'adapter_sigkill_entry','sender':tid,'target':args[1]})
                else:
                    old=entries.pop(tid,None)
                    if old is not None and old[0] == 62 and old[2] == signal.SIGKILL and args == 0:
                        program_kills.add(old[1])
                        events.append({'kind':'adapter_sigkill_success','sender':tid,'target':old[1]})
                    if tid == selected and injected and not injected_return:
                        require(args == -38,'suppressed syscall did not return ENOSYS')
                        change_register(tid,10,-error);injected_return=True
                        events.append({'kind':'qualification_errno_return','tid':tid,'synthetic_errno':error})
                    elif name == 'actual-broken-fence-pipe' and not actual_broken_return and tid == selected and old and old[0] == 1:
                        require(args == -32,'broken pipe did not produce actual EPIPE')
                        actual_broken_return=True
                        events.append({'kind':'actual_epipe_return','tid':tid,'value':args})
            elif stop == signal.SIGCHLD: delivery=signal.SIGCHLD
            elif stop == signal.SIGPIPE and name == 'actual-broken-fence-pipe': delivery=signal.SIGPIPE
            else: raise AssertionError(('unexpected task signal',tid,stop,pe))
            try:
                ptrace(24,tid,0,delivery)
            except ProcessLookupError:
                # A real, recorded SIGKILL may win between waitpid's stop and
                # resume. This is accepted only after its actual fatal wait and
                # successful owned kill are both checked below.
                terminal_resume_races.add(tid)
                events.append({'kind':'resume_raced_with_terminal_task','tid':tid})
        collect()
        require(selected is not None and not deferred and set(exits) == announced,'fault domain/reaping incomplete')
        require(not errors and cursor == len(outgoing),'unexpected process output')
        require(all(not Path('/proc',str(tid)).exists() for tid in exits),'tracee survived completion')
        require(all(exits.get(tid) == -9 and tid in program_kills | observer_kills
                    for tid in terminal_resume_races),'unexplained trace resume failure')
        require(all(exits.get(tid) == -9 and tid in program_kills | observer_kills
                    for tid in terminal_observation_races),'unexplained trace observation failure')
        require(not target.exists() and exclusive(lock),'fault left effect or authority')
        if name == 'actual-broken-fence-pipe':
            require(actual_broken_return and not injected and exits[fence_pid] == -9,'actual pipe domain incomplete')
        elif name == 'actual-mkdir-worker-death':
            require(worker_killed and not injected and exits[selected] == -9,'worker-death domain incomplete')
        else: require(injected and injected_return,'synthetic errno domain incomplete')
        if recover:
            require(exits[pid] == 0 and follow_done and closed and following.is_dir(),'same-process recovery incomplete')
        else:
            require(exits[pid] == 111 and not following.exists(),'startup/IPC failure was not closed')
        for path in (base/'state/controller.lock',base/'state/controller.owner.lock'):
            with path.open('rb') as fd:require(exclusive(fd),'configuration lock retained after termination')
        return {'status':'PASS','case':name,'elapsed_seconds':time.monotonic()-started,'exit_statuses':exits,
            'events':events,'replies':replies,'actual_processes':1,'original_executions':0,
            'synthetic_errno_injections':int(injected),'actual_broken_pipe':actual_broken_return,
            'actual_worker_sigkill':worker_killed,'same_process_recovery':recover,'all_owned_tasks_reaped':True,
            'stdin_bytes':len(incoming),'stdin_sha256':SHA(incoming),'stdout_bytes':len(outgoing),
            'stdout_sha256':SHA(outgoing),'stderr_bytes':len(errors),'stderr_sha256':SHA(errors)}
    except BaseException:
        for tid in live:
            try:os.kill(tid,signal.SIGKILL)
            except ProcessLookupError:pass
        while live:
            try:tid,status=os.waitpid(-1,WALL)
            except ChildProcessError:break
            if os.WIFSTOPPED(status):
                try:ptrace(24,tid,0,signal.SIGKILL)
                except OSError:pass
            else:live.discard(tid)
        collect();raise
    finally:
        if not closed:os.close(iw)
        for fd in (out_r,err_r,lock):os.close(fd)
        for suffix,raw in (('stdin',incoming),('stdout',outgoing),('stderr',errors)):
            (output/(name+'.'+suffix)).write_bytes(raw)
        (output/(name+'.events.json')).write_text(json.dumps(events,sort_keys=True,indent=2)+'\n')
        if not live:shutil.rmtree(base)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output=args.output.resolve();args.output.mkdir(parents=True,exist_ok=False)
    m=json.loads(args.manifest.read_bytes());binary=(args.manifest.parent/m['executable']).resolve(strict=True)
    require(SHA(binary.read_bytes()) == m['elf_sha256'],'actual static ELF differs')
    require(LIBC.prctl(36,1,0,0,0) == 0,'qualification subreaper unavailable')
    source_names=['directory_service_faults.py','directory_service_kernel.py','directory_service_support.py']
    source={n:SHA(Path(__file__).with_name(n).read_bytes()) for n in source_names}
    report={'schema':'hepta.directory-service.actual-adapter-faults.v1','status':'FAIL','cases':[],
        'source_sha256':source,'native_elf_sha256':m['elf_sha256'],'expected_cases':[r[0] for r in CASES],
        'original_executions':0,'production_activated':False,'whole_runtime_replaced':False}
    fixture=args.output/'fixtures';fixture.mkdir(mode=0o700)
    try:
        for spec in CASES:
            report['cases'].append(run_case(binary,spec,fixture,args.output))
            (args.output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        require(len(report['cases']) == 12 and sum(r['synthetic_errno_injections'] for r in report['cases']) == 10,'fixed domain count')
        report['source_unchanged']=source == {n:SHA(Path(__file__).with_name(n).read_bytes()) for n in source_names}
        require(report['source_unchanged'] and SHA(binary.read_bytes()) == m['elf_sha256'],'source/artifact drift')
        report['test_summary']=dict(tests_run=2,failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0)
        report['status']='PASS'
    except BaseException as error:
        report['error']=repr(error);raise
    finally:(args.output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('cases','source_sha256')}))


if __name__ == '__main__':main()
