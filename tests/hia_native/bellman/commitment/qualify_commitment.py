"""Exercise real HIA typed serialization; unchanged Rust must replay its stream."""
import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
import math
import os, signal, shutil, subprocess
from pathlib import Path
import random
import struct
import sys
import time

LIMIT = 8 << 20
ORIGINAL_SHA = '254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
DOMAIN = b'hepta.weight.bellman-plan.v1\0finite_dag_ordered_f64_v1\0'
BUDGET_ERROR = b'Bellman canonical request exceeds 8 MiB'
BITS = lambda value: struct.unpack('<Q', struct.pack('<d', value))[0]
FLOAT = lambda value: struct.unpack('<d', struct.pack('<Q', value))[0]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()

def load_core(path):
    spec = importlib.util.spec_from_file_location('bellman_commitment_core_corpus', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def encode(graph, core, source_sha=ORIGINAL_SHA):
    return b'HBCMT001' + bytes.fromhex(source_sha) + core.pack_graph(graph)

def check_typed(actual, graph):
    parsed = json.loads(actual, object_pairs_hook=dict)
    assert list(parsed) == ['states'] and len(parsed['states']) == len(graph)
    for got, row in zip(parsed['states'], graph):
        assert list(got) == ['actions'] and len(got['actions']) == 6
        for rendered, action in zip(got['actions'], row):
            if action is None:
                assert rendered is None
            elif action['kind'] == 'terminal':
                assert list(rendered) == ['kind', 'value'] and rendered['kind'] == 'terminal'
                assert BITS(rendered['value']) == BITS(action['value'])
            else:
                assert list(rendered) == ['kind', 'branches'] and rendered['kind'] == 'continue'
                assert len(rendered['branches']) == len(action['branches'])
                for got_branch, (p, s, r, f) in zip(rendered['branches'], action['branches']):
                    assert list(got_branch) == ['probability', 'successor', 'reward', 'fee']
                    assert type(got_branch['successor']) is int and got_branch['successor'] == s
                    for name, value in [('probability', p), ('reward', r), ('fee', f)]:
                        assert BITS(got_branch[name]) == BITS(value)

def verify_result(result, graph, source_sha=ORIGINAL_SHA, expected_size=None):
    assert result[:8] == b'HBCMTRES' and result[112:128] == bytes(16)
    canonical = result[128:]
    assert struct.unpack_from('<Q', result, 8)[0] == len(canonical) <= LIMIT
    if expected_size is not None:
        assert len(canonical) == expected_size, (len(canonical), expected_size)
    request = hashlib.sha256(canonical).digest()
    identity = hashlib.sha256(DOMAIN + source_sha.encode() + b'\0' + request.hex().encode()).digest()
    assert result[16:48] == request and result[48:80] == bytes.fromhex(source_sha)
    assert result[80:112] == identity
    check_typed(canonical, graph)

def exact_budget_graphs(core):
    # These typed fixtures intentionally bypass numerical admission. Their
    # probabilities/fees need not be feasible; the public solver validates first.
    long = -1.2345678901234568e16
    def action_bytes(action):
        if action is None:
            return b'null'
        if action['kind'] == 'terminal':
            return b'{"kind":"terminal","value":' + repr(action['value']).encode() + b'}'
        branches = []
        for p, s, r, f in action['branches']:
            branches.append(b'{"probability":' + repr(p).encode() + b',"successor":' + str(s).encode()
                            + b',"reward":' + repr(r).encode() + b',"fee":' + repr(f).encode() + b'}')
        return b'{"kind":"continue","branches":[' + b','.join(branches) + b']}'
    choices = [None, core.terminal(0.), core.terminal(long)]
    for count in range(4):
        for width in range(1, 11):
            successor = 0 if width == 1 else 10 ** (width - 1)
            choices.append(core.continuation(*[core.branch(long, successor, long, long)] * count))
    by_size = {len(action_bytes(a)): a for a in choices}
    full = core.continuation(*[core.branch(long, 4294967295, long, long)] * 3)
    row = [full] * 6
    row_size = len(b'{"actions":[' + b','.join(action_bytes(a) for a in row) + b']}')
    base_count = (LIMIT - 12) // (row_size + 1)
    # A complete last state can realize every needed target here; use a small
    # exact integer search, independent from the HIA cursor implementation.
    sums = {0: []}
    for _ in range(6):
        sums = {total + size: actions + [action] for total, actions in sums.items()
                for size, action in by_size.items()}
    for delta in (-1, 0, 1):
        target = LIMIT + delta
        last_size = target - 12 - base_count * (row_size + 1) - 1
        action_total = last_size - len(b'{"actions":[') - len(b']}') - 5
        assert action_total in sums, (delta, action_total)
        graph = [row] * base_count + [sums[action_total]]
        assert len(graph) <= 4096
        yield 'byte-budget-' + str(delta), graph, target, target > LIMIT

def corpus(core):
    yield 'typed-empty', [], None, False
    yield 'typed-all-null', [[None]*6], None, False
    yield 'typed-empty-branches', [[core.continuation()]*6], None, False
    for name, graph, error in core.corpus():
        if error is None:
            yield 'numerical-' + name, graph, None, False
    values = {0, 1, (1 << 52)-1, 1 << 52, (1 << 52)+1,
              0x7fefffffffffffff, 0x8000000000000000, 0x8000000000000001}
    for exponent in range(1, 2047):
        values.add((exponent << 52) | ((exponent & 1) << 63))
    for value in (1e-6, 1e-5, 1e-4, 1e14, 1e15, 1e16, 1e17, 1e-100, 1e100, 1e-300, 1e300):
        for item in (math.nextafter(value, 0.), value, math.nextafter(value, math.inf)):
            values.add(BITS(item)); values.add(BITS(-item))
    rng = random.Random(6780737)
    for _ in range(2048):
        raw = rng.getrandbits(64)
        if (raw >> 52) & 2047 != 2047:
            values.add(raw)
    values = sorted(values)
    for at in range(0, len(values), 6):
        row = [core.terminal(FLOAT(v)) for v in values[at:at+6]]
        yield 'binary64-text-' + str(at), [row + [None]*(6-len(row))], None, False
    successors = {0, 1, 9, 10, 99, 100, 4294967294, 4294967295}
    for exponent in range(1, 10):
        successors.update((10**exponent-1, 10**exponent, 10**exponent+1))
    successors.update(rng.randrange(1 << 32) for _ in range(128))
    for at, successor in enumerate(sorted(successors)):
        action = core.continuation(core.branch(-0., successor, -0., 0.),
                                   core.branch(1., successor, 0., -0.))
        yield 'u32-successor-' + str(at), [[action]*6], None, False
    for index, values in enumerate(itertools.product((-0., 0.), repeat=3)):
        yield 'zero-fields-' + str(index), [[core.continuation(core.branch(values[0],0,values[1],values[2]))]*6], None, False
    yield from exact_budget_graphs(core)

def qualify_worker(runtime, manifest, output, core_corpus, group):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(runtime / 'scripts'))
    from hia_native_loader import NativeModule
    core = load_core(core_corpus)
    module = NativeModule(manifest, manifest_sha256=SHA(manifest.read_bytes()))
    assert output.is_dir() and not output.is_symlink()
    assert group in GROUPS
    rows = []
    start = time.monotonic()
    with module.session(output_capacity=LIMIT+128, workspace_capacity=LIMIT+16384) as session, \
         (output/'inputs.bin').open('xb') as inputs, (output/'native.bin').open('xb') as native:
        previous_result = None
        selected = itertools.islice(corpus(core), 0, 1139) if group == "ordinary" else itertools.islice(corpus(core), 1139, None)
        for name, graph, expected_size, refusal in selected:
            wire = encode(graph, core)
            before = time.monotonic()
            if not refusal:
                result = session.invoke(wire)
                verify_result(result, graph, expected_size=expected_size)
                kind, status = 0, len(result)
                previous_result = result
            else:
                status, buffer, workspace = session.invoke_raw(wire)
                assert status == 0xffffff00, (name, status)
                assert len(previous_result) == LIMIT + 128 and buffer == previous_result
                kind, result = 1, BUDGET_ERROR
            inputs.write(struct.pack('<Q', len(wire)) + wire)
            native.write(struct.pack('<QQ', kind, len(result)) + result)
            rows.append({'name':name, 'states':len(graph), 'input_bytes':len(wire), 'status':status,
                         'kind':kind, 'output_bytes':len(result), 'output_sha256':SHA(result),
                         'wall_seconds':time.monotonic()-before})
            if name.startswith('byte-budget-'):
                print(json.dumps(rows[-1]), flush=True)
        if group == "budget":
            # The same workspace must recover from a sticky budget refusal.
            graph = [[core.terminal(-0.)] + [None]*5]
            recovered = session.invoke(encode(graph, core))
            verify_result(recovered, graph)
    controls, trusted_inputs = [], []
    if group == "ordinary":
        controls = []
        graph = [[core.terminal(1.)] + [None]*5]
        base = encode(graph, core)
        valid = module.invoke(base, output_capacity=4096, workspace_capacity=32768)
        malformed = [('empty',b''), ('short',base[:55]), ('bad-magic',b'X'+base[1:]),
                     ('short-body',base[:-1]), ('trailing',base+b'X')]
        for name, at, value in [('graph-magic',40,0), ('count',48,4097), ('kind',56,3),
                                ('terminal-padding',72,1), ('null-padding',184,1),
                                ('infinity',64,0x7ff0000000000000), ('nan',64,0x7ff8000000000001)]:
            wire=bytearray(base);struct.pack_into('<Q',wire,at,value);malformed.append((name,bytes(wire)))
        continuation = encode([[core.continuation(core.branch(1.,0))]+[None]*5],core)
        for name, at, value in [('continue-reserved',64,1), ('branches',72,4), ('unused-branch',112,1),
                                ('successor-width',88,1<<32), ('probability-nan',80,0x7ff8000000000000),
                                ('reward-infinity',96,0x7ff0000000000000), ('fee-infinity',104,0xfff0000000000000)]:
            wire=bytearray(continuation);struct.pack_into('<Q',wire,at,value);malformed.append((name,bytes(wire)))
        for name, wire in malformed:
            code, out, work = module.invoke_raw(wire, output_capacity=4096, workspace_capacity=32768,
                                                output_fill=0xcc, workspace_fill=0xa7)
            assert code == 0xffffffff and out == bytes([0xcc])*4096, name
            assert work == bytes([0xa7])*32768, ('invalid frame mutated scratch', name)
            controls.append({'name':name,'code':code})
        for outcap, workcap in [(127,32768), (4096,16383), (len(valid)-1,32768), (4096,16384+len(valid)-129)]:
            code, out, work = module.invoke_raw(base, output_capacity=outcap, workspace_capacity=workcap,
                                                output_fill=0xcc, workspace_fill=0xa7)
            assert code == 0xfffffffd and out == bytes([0xcc])*outcap, (outcap,workcap,code)
            controls.append({'name':'capacity','output_capacity':outcap,'workspace_capacity':workcap,'code':code})
        trusted_inputs = []
        for index in range(33):
            source = bytes(32) if index == 32 else bytes([0xff if i==index else 0 for i in range(32)])
            result=module.invoke(encode(graph,core,source.hex()), output_capacity=4096, workspace_capacity=32768)
            verify_result(result, graph, source.hex())
            assert result[128:] == valid[128:] and result[16:48] == valid[16:48]
            trusted_inputs.append({'source_sha256':source.hex(),'plan_sha256':result[80:112].hex()})
    report = {'status':'NATIVE_TYPED_COMMITMENT_PASS_RUST_REPLAY_REQUIRED',
              'source_sha256':module.metadata['source_sha256'], 'manifest_sha256':SHA(manifest.read_bytes()),
              'core_fixture_sha256':SHA(core_corpus.read_bytes()), 'cases':rows, 'native_cases':len(rows),
              'refusal_controls':controls, 'trusted_installation_digest_controls':trusted_inputs,
              'same_session_refusal_recovery':group == 'budget', 'wall_seconds':time.monotonic()-start,
              'worker_identity':dict(group=group,pid=os.getpid(),parent_pid=os.getppid(),process_group=os.getpgrp(),
                  source_inputs=source_inputs(runtime,core_corpus)),
              'files':{name:{'bytes':(output/name).stat().st_size,'sha256':SHA((output/name).read_bytes())}
                       for name in ('inputs.bin','native.bin')},
              'public_handler_qualified':False,'whole_runtime_replaced':False,
              'scope':'typed-frame canonical serialization and hash identity only; public validation, installed digest authority, rendering, deadline and async admission excluded'}
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('status','native_cases','wall_seconds','files')}),flush=True)
    return report

PROCESS_TIMEOUT = 180
GROUPS = ('ordinary', 'budget')
GROUP_COUNTS = {'ordinary':1139, 'budget':3}

def pin(raw):
    return {'bytes':len(raw),'sha256':SHA(raw)}

def source_inputs(runtime,core_corpus):
    names=('tests/hia_native/bellman/commitment/qualify_commitment.py',
           'tests/hia_native/bellman/qualify_bellman.py','scripts/hia_native_loader.py')
    result={name:pin((runtime/name).read_bytes()) for name in names}
    assert core_corpus==runtime/'tests/hia_native/bellman/qualify_bellman.py'
    assert (runtime/names[0]).read_bytes()==Path(__file__).read_bytes()
    return result

def worker_command(runtime,manifest,folder,core_corpus,group):
    return [sys.executable,'-I','-B',str(runtime/'tests/hia_native/bellman/commitment/qualify_commitment.py'),
        '--runtime',str(runtime),'--manifest',str(manifest),'--output',str(folder),
        '--core-corpus',str(core_corpus),'--group',group]

def summary(report):
    return {key:report[key] for key in ('status','native_cases','wall_seconds','files')}

def joined_report(workers):
    assert set(workers)==set(GROUPS)
    first=workers['ordinary'];common=('status','source_sha256','manifest_sha256','core_fixture_sha256',
        'public_handler_qualified','whole_runtime_replaced','scope')
    for name,worker in workers.items():
        assert all(worker[key]==first[key] for key in common)
        assert worker['native_cases']==len(worker['cases'])==GROUP_COUNTS[name]
        assert worker['same_session_refusal_recovery'] is (name=='budget')
        assert len(worker['refusal_controls'])==(23 if name=='ordinary' else 0)
        assert len(worker['trusted_installation_digest_controls'])==(33 if name=='ordinary' else 0)
        assert all(row['name'].startswith('byte-budget-') is (name=='budget') for row in worker['cases'])
    result={key:first[key] for key in common}
    result.update(cases=first['cases']+workers['budget']['cases'],native_cases=1142,
        refusal_controls=first['refusal_controls'],
        trusted_installation_digest_controls=first['trusted_installation_digest_controls'],
        same_session_refusal_recovery=True)
    return result

def capture_evidence(runtime,folder,manifest_sha,*,outer_pid=None):
    """Reread two actual source-bound workers; never start a semantic owner."""
    from hia_native_bellman_qualification import read,decode,exact
    def need(value,reason):
        if not value:raise ValueError('Bellman commitment workers: '+reason)
    runtime,folder=Path(runtime).resolve(),Path(folder).resolve()
    report=decode(read(folder/'report.json'));execution=report.get('execution',{})
    need(execution.get('schema')=='hepta.bellman-commitment.worker-execution.v1'
        and execution.get('max_parallel_workers')==2 and execution.get('timeout_seconds')==180
        and execution.get('groups') is not None and [row.get('name') for row in execution['groups']]==list(GROUPS),
        'complete fixed worker domain is missing')
    parent=execution.get('parent_pid');need(type(parent)is int and parent>0 and execution.get('process_group')==parent,'owning parent/group')
    if outer_pid is not None:need(type(outer_pid)is int and parent==outer_pid,'parent is not the actual outer Popen PID')
    begin,end=execution.get('start_monotonic_ns'),execution.get('end_monotonic_ns')
    need(type(begin)is int and type(end)is int and 0<begin<=end
        and (end-begin)/1e9==report.get('wall_seconds')<=180,'unchanged parent deadline')
    original=execution.get('capture_root');need(type(original)is str and Path(original).is_absolute()
        and '..' not in Path(original).parts and '\x00' not in original,'captured path')
    original=Path(original);manifest=execution.get('manifest')
    need(type(manifest)is str and Path(manifest).is_absolute() and '..' not in Path(manifest).parts,
        'actual module path')
    need(execution.get('manifest_sha256')==manifest_sha==report.get('manifest_sha256'),'module source custody')
    inputs=source_inputs(runtime,runtime/'tests/hia_native/bellman/qualify_bellman.py')
    need(execution.get('source_inputs')==inputs,'complete worker source inputs')
    workers={};pids=set();seals={}
    for group in execution['groups']:
        name=group['name'];root=folder/'workers'/name
        process_raw=read(root/'process.json');worker_raw=read(root/'report.json')
        exact(group,dict(name=name,cases=GROUP_COUNTS[name],process=pin(process_raw),result=pin(worker_raw)),
            'worker completion seal differs')
        process=decode(process_raw);worker=decode(worker_raw)
        need(process.get('schema')=='hepta.bellman-commitment.worker-process.v1'
            and process.get('command')==worker_command(runtime,Path(manifest),original/'workers'/name,
                runtime/'tests/hia_native/bellman/qualify_bellman.py',name)
            and process.get('cwd')==str(runtime) and process.get('parent_pid')==parent
            and process.get('process_group')==parent and process.get('timeout_seconds')==180
            and type(process.get('pid'))is int and process['pid']>0
            and process['pid']!=parent and process['pid']not in pids
            and process.get('exit_code')==0 and process.get('reaped')is True
            and process.get('timed_out')is False and process.get('start_error')is None,
            'actual worker process custody/completion')
        pids.add(process['pid']);start,finish=process.get('start_monotonic_ns'),process.get('end_monotonic_ns')
        need(type(start)is int and type(finish)is int and begin<=start<=finish<=end
            and (finish-start)/1e9==process.get('elapsed_seconds')<=180
            and type(worker.get('wall_seconds'))in (int,float)
            and math.isfinite(worker['wall_seconds']) and 0<=worker['wall_seconds']<=process['elapsed_seconds'],
            'actual worker lifetime differs')
        exact(worker.get('worker_identity'),dict(group=name,pid=process['pid'],parent_pid=parent,
            process_group=parent,source_inputs=inputs),'executed worker identity/domain/source')
        stdout,stderr=read(root/'stdout'),read(root/'stderr')
        need(process.get('stdout')==pin(stdout) and process.get('stderr')==pin(stderr) and not stderr,
            'complete worker streams')
        expected=[*worker['cases'],summary(worker)] if name=='budget' else [summary(worker)]
        exact([decode(line) for line in stdout.splitlines()],expected,'actual worker stdout differs')
        exact(worker.get('files'),{n:pin(read(root/n))for n in ('inputs.bin','native.bin')},'complete worker corpus differs')
        workers[name]=worker;seals[name]=group
    try:expected=joined_report(workers)
    except (AssertionError,KeyError,TypeError)as error:raise ValueError('Bellman commitment fixed worker domain')from error
    for name in ('inputs.bin','native.bin'):
        actual=read(folder/name)
        need(actual==b''.join(read(folder/'workers'/group/name)for group in GROUPS),'ordered complete corpus join')
    expected.update(wall_seconds=report['wall_seconds'],execution=execution,
        files={n:pin(read(folder/n))for n in ('inputs.bin','native.bin')})
    exact(report,expected,'complete joined worker report')
    return dict(status='PASS',max_parallel_workers=2,timeout_seconds=180,parent_pid=parent,
        ordinary_cases=1139,budget_cases=3,budget_and_recovery_same_session=True,groups=seals)

def qualify(runtime,manifest,output,core_corpus):
    """Schedule two independent arenas; the budget refusal/recovery stays one session."""
    runtime,manifest,output,core_corpus=map(lambda p:Path(p).resolve(),(runtime,manifest,output,core_corpus))
    output.mkdir();(output/'workers').mkdir()
    if os.getpgrp()!=os.getpid():os.setpgid(0,0)
    assert os.getpgrp()==os.getpid()
    source=source_inputs(runtime,core_corpus);manifest_sha=SHA(manifest.read_bytes())
    begin=time.monotonic_ns();live=[];workers={};passed=False
    try:
        for name in GROUPS:
            folder=output/'workers'/name;folder.mkdir()
            command=worker_command(runtime,manifest,folder,core_corpus,name)
            stdout=(folder/'stdout').open('xb');stderr=(folder/'stderr').open('xb')
            process=None;row=dict(schema='hepta.bellman-commitment.worker-process.v1',command=command,
                cwd=str(runtime),parent_pid=os.getpid(),process_group=os.getpgrp(),timeout_seconds=180,
                start_monotonic_ns=time.monotonic_ns(),pid=None,exit_code=None,reaped=False,timed_out=False,start_error=None)
            try:
                process=subprocess.Popen(command,cwd=runtime,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=False)
                row['pid']=process.pid
            except BaseException as error:row['start_error']=repr(error);raise
            finally:
                live.append((name,folder,process,stdout,stderr,row))
                (folder/'process.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
        for name,folder,process,stdout,stderr,row in live:
            remaining=180-(time.monotonic_ns()-begin)/1e9
            try:
                if remaining<=0:raise subprocess.TimeoutExpired(row['command'],180)
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:row['timed_out']=True;raise
            row.update(exit_code=process.returncode,reaped=True,end_monotonic_ns=time.monotonic_ns())
            row['elapsed_seconds']=(row['end_monotonic_ns']-row['start_monotonic_ns'])/1e9
            stdout.close();stderr.close()
            for channel in ('stdout','stderr'):row[channel]=pin((folder/channel).read_bytes())
            (folder/'process.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
            assert row['exit_code']==0 and row['stderr']['bytes']==0,row
            workers[name]=json.loads((folder/'report.json').read_bytes())
        report=joined_report(workers)
        for name in ('inputs.bin','native.bin'):
            with (output/name).open('xb')as target:
                for group in GROUPS:
                    with (output/'workers'/group/name).open('rb')as source_stream:shutil.copyfileobj(source_stream,target)
        end=time.monotonic_ns();report['wall_seconds']=(end-begin)/1e9;assert report['wall_seconds']<=180
        assert source==source_inputs(runtime,core_corpus) and manifest_sha==SHA(manifest.read_bytes())
        report['files']={n:pin((output/n).read_bytes())for n in ('inputs.bin','native.bin')}
        report['execution']=dict(schema='hepta.bellman-commitment.worker-execution.v1',max_parallel_workers=2,
            timeout_seconds=180,parent_pid=os.getpid(),process_group=os.getpgrp(),capture_root=str(output),
            manifest=str(manifest),manifest_sha256=manifest_sha,source_inputs=source,start_monotonic_ns=begin,end_monotonic_ns=end,
            groups=[dict(name=n,cases=GROUP_COUNTS[n],process=pin((output/'workers'/n/'process.json').read_bytes()),
                result=pin((output/'workers'/n/'report.json').read_bytes()))for n in GROUPS])
        (output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        capture_evidence(runtime,output,manifest_sha,outer_pid=os.getpid())
        passed=True
    finally:
        retire_owned_workers(live, failed=not passed)
    for row in report['cases'][-3:]:print(json.dumps(row),flush=True)
    print(json.dumps(summary(report)),flush=True)
    return report


def retire_owned_workers(live, *, failed):
    """A failed evidence write cannot skip child retirement or the group kill."""
    if not failed:
        for _,_,_,stdout,stderr,_ in live:
            stdout.close();stderr.close()
        return
    try:
        # First retire every directly owned worker, even if one kill/wait races.
        for _,_,process,_,_,_ in live:
            if process is None:continue
            try:
                if process.poll() is None:process.kill()
            except BaseException:
                pass
            try:process.wait(timeout=3)
            except BaseException:pass
    finally:
        try:
            for _,folder,process,stdout,stderr,row in live:
                for stream in (stdout,stderr):
                    try:stream.close()
                    except BaseException:pass
                try:
                    if process is not None:row.update(exit_code=process.returncode,reaped=process.returncode is not None)
                    for channel in ('stdout','stderr'):row[channel]=pin((folder/channel).read_bytes())
                    (folder/'process.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
                except BaseException:
                    # Preserve what is writable; ENOSPC must not strand peers.
                    pass
        finally:
            os.killpg(os.getpid(),signal.SIGKILL)

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('runtime','manifest','core-corpus','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--group',choices=GROUPS)
    a=parser.parse_args();args=[a.runtime.resolve(),a.manifest.resolve(),a.output.resolve(),a.core_corpus.resolve()]
    if a.group:qualify_worker(*args,a.group)
    else:qualify(*args)
