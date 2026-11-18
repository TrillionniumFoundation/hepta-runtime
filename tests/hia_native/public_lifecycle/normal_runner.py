# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Normal serial stdio replay; complete captures, ordinary business errors only."""
from pathlib import Path
import copy,gzip,hashlib,json,os,selectors,stat,subprocess,time,traceback,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import normal_projection as q
H=q.H
ENC=lambda x:(json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
ALLOWED={"host_list","effective_config","execution_shadow_admit"}

def root_stat(path):
    value=path.stat()
    return dict(mode=stat.S_IMODE(value.st_mode),device=value.st_dev,inode=value.st_ino,
                nlink=value.st_nlink,uid=value.st_uid,gid=value.st_gid,kind='directory')


def pin(p):
    b=p.read_bytes()
    return dict(bytes=len(b),sha256=H(b))

def line(stream,buffer):
    deadline=time.monotonic()+30
    with selectors.DefaultSelector()as selector:
        selector.register(stream,selectors.EVENT_READ)
        while b'\n'not in buffer:
            left=deadline-time.monotonic()
            assert left>0 and selector.select(left),'public response deadline'
            data=os.read(stream.fileno(),65536)
            assert data,'unexpected response EOF'
            buffer+=data
            assert len(buffer)<=134217728
    end=buffer.index(b'\n')+1
    return buffer[:end],buffer[end:]

def configuration(state,case):
    value={'state_dir':str(state),'hosts':{
        'h':{'ssh_target':'private-target','remote_state_dir':'/private-state','allow_write':True},
        'secondary':{'ssh_target':'another-private-target','remote_state_dir':'/other'}}}
    if 'hosts'in case:value['hosts']=case['hosts']
    return value

def request(method,params,ident):
    return q.compact(dict(jsonrpc='2.0',id=ident,method=method,params=params))

def run(binary,side,folder,case,update,*,retained_common=None):
    d=folder/side;d.mkdir(mode=0o700)
    common=folder/'common' if retained_common is None else Path(retained_common)
    if retained_common is not None:
        assert side=='original' and common.is_dir() and not common.is_symlink()
        assert (common/'config.json').is_file() and not (common/'state').exists()
    common.mkdir(mode=0o700,exist_ok=True)
    state=common/'state';state.mkdir(mode=0o700)
    config=common/'config.json';config_bytes=q.compact(configuration(state,case))
    if config.exists():assert config.read_bytes()==config_bytes
    else:config.write_bytes(config_bytes);config.chmod(0o600)
    conflict=state/'request-results'
    if case.get('legacy_file_conflict'):conflict.write_bytes(b'ordinary pre-existing application file\n')
    command=[str(binary),'--runtime-config',str(config)]
    row=dict(side=side,status='RUNNING',argv=command,cwd=str(d),response_timeout_seconds=30,frames=0)
    update(row);start=time.monotonic();child=None
    raw_input=bytearray();raw_output=bytearray();buffer=b''
    requests={};responses={};bounds={};provenance={'owner':None,'request_ids':{}}
    wires=[];projections=[]
    try:
        with (d/'stderr').open('xb')as stderr,gzip.open(d/'observations.jsonl.gz','wb')as log:
            child=subprocess.Popen(command,cwd=d,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,
                bufsize=0,close_fds=True,env={'PATH':'','LC_ALL':'C','HEPTA_REQUEST_AUDIT_TRACE':'0'})
            row['pid']=child.pid;update(row)
            for frame,event_hex in enumerate(case['events'],1):
                event=bytes.fromhex(event_hex);declared=json.loads(event)
                assert declared.get('method')in('initialize','server/discover','tools/call')
                if declared['method']=='tools/call':assert declared['params']['name']in ALLOWED
                before=dict(wall_before=time.time_ns(),mono_before=time.monotonic_ns())
                payload=event+b'\n';raw_input+=payload;child.stdin.write(payload)
                response,buffer=line(child.stdout,buffer);raw_output+=response
                before.update(wall_after=time.time_ns(),mono_after=time.monotonic_ns())
                requests[frame]=declared;bounds[frame]=before
                parsed=q.checked_json(response[:-1]);assert parsed['id']==declared['id']
                responses[frame]=parsed
                q.observe_identities(state,frame,declared,parsed,provenance)
                parsed,projected_wire=q.wire(response,frame,provenance)
                full,logical,counts=q.snapshot(state,requests,responses,bounds,provenance)
                log.write(q.compact(dict(frame=frame,input_hex=payload.hex(),output_hex=response.hex(),bounds=before,
                    identity_relation=copy.deepcopy(provenance),root_stat=root_stat(state),filesystem=full,logical=logical))+b'\n')
                wires.append(projected_wire);projections.append(logical)
                row.update(frames=frame,counts=counts);update(row)
                if case.get('legacy_file_conflict')and frame==2:
                    error=parsed.get('error',{})
                    assert error.get('code')==-32603 and error.get('message')=='result admission unavailable; tool was not dispatched',parsed
                    assert conflict.read_bytes()==b'ordinary pre-existing application file\n'
                    conflict.unlink()
            child.stdin.close()
            child.wait(timeout=30)
            remainder=child.stdout.read()
            raw_output+=remainder
            assert child.returncode==0 and remainder==b'' and buffer==b''
            assert not Path('/proc',str(child.pid)).exists()
            full,eof,counts=q.snapshot(state,requests,responses,bounds,provenance)
            (d/'eof-filesystem.json').write_bytes(ENC(dict(root_stat=root_stat(state),full=full,logical=eof,counts=counts)))
            if case.get('legacy_file_conflict'):
                assert responses[3]['result']['isError']is False
                assert responses[4]['result']['isError']is False
            assert (d/'stderr').read_bytes()==b''
            row.update(status='PASS',exit_code=0,reaped=True,counts=counts)
        os.rename(state,d/'final-state')
        return b''.join(wires),projections,eof,counts
    finally:
        if child is not None:
            if child.poll()is None:child.kill();child.wait(timeout=3)
            row['exit_code']=child.returncode
            if child.stdout is not None:child.stdout.close()
        (d/'input.bin').write_bytes(raw_input);(d/'stdout.bin').write_bytes(raw_output)
        for name in('input.bin','stdout.bin','stderr','observations.jsonl.gz','eof-filesystem.json'):
            path=d/name
            if path.exists():row[name]=pin(path)
        row['elapsed_seconds']=time.monotonic()-start;update(row)


def retire_fixture(directory):
    """Retire only the completed owned fixture after its complete byte capture."""
    root = directory / 'final-state'
    final = json.loads((directory / 'eof-filesystem.json').read_bytes())
    expected = final['full']
    assert root.is_dir() and not root.is_symlink()
    assert root_stat(root) == final['root_stat']
    paths = sorted(root.rglob('*'))
    assert {p.relative_to(root).as_posix() for p in paths} == set(expected)
    for path in paths:
        name = path.relative_to(root).as_posix()
        row, info = expected[name], path.lstat()
        for key, observed in dict(mode=stat.S_IMODE(info.st_mode), device=info.st_dev,
                inode=info.st_ino, nlink=info.st_nlink, uid=info.st_uid, gid=info.st_gid).items():
            assert row[key] == observed, (name,key)
        if row['kind'] == 'file':
            raw = path.read_bytes()
            assert raw.hex() == row['hex'] and len(raw) == row['bytes'] and H(raw) == row['sha256']
        elif row['kind'] == 'symlink':
            assert path.is_symlink() and os.readlink(path) == row['target']
        else:
            assert row['kind'] == 'directory' and path.is_dir() and not path.is_symlink()
    receipt = dict(schema='hepta.public-lifecycle.fixture-retirement.v1', status='VERIFIED',
                   snapshot=pin(directory/'eof-filesystem.json'), entries=len(expected),
                   regular_files=sum(r['kind']=='file' for r in expected.values()),
                   source='complete actual EOF observation after process reaping')
    for path in sorted(paths, key=lambda p:len(p.parts), reverse=True):
        if path.is_dir() and not path.is_symlink():
            path.rmdir()
        else:
            path.unlink()
    root.rmdir()
    receipt['status'] = 'RETIRED_AFTER_VERIFICATION'
    (directory/'fixture-retirement.json').write_bytes(ENC(receipt))


def execute(native, output, original=None):
    native = Path(native).resolve(strict=True)
    original = None if original is None else Path(original).resolve(strict=True)
    output = Path(output).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    fixture = Path(__file__).with_name('normal.json.gz')
    values = json.loads(gzip.decompress(fixture.read_bytes()))
    assert len(values)==64 and sum(len(x['case']['events']) for x in values)==359
    assert len({x['case']['name'] for x in values})==64
    assert all(x['case']['rules']==[] for x in values)
    sources = {str(p.resolve()):pin(p) for p in (fixture,Path(__file__),Path(q.__file__))}
    identities = {'native':pin(native)}
    if original is not None:
        identities['original'] = pin(original)
    report = dict(schema='hepta.public-lifecycle.normal.v1', status='RUNNING',
        sources=sources, binaries=identities, processes=[], completed=[],
        native_processes=0, original_processes=0, native_requests=0, original_requests=0,
        retained_original_wire_cases=64, fresh_rust_builds=0,
        entropy_source_qualification=False, identity_consistency_qualified=True,
        syscall_interception=False, fault_injection=False, external_host_operations=0,
        actual_paired_filesystem_comparison=original is not None,
        scope='serial stdio, three fixed tools, Index absent, no async cancellation',
        production_activated=False, whole_runtime_replaced=False)
    begin = time.monotonic()
    def save():
        report['elapsed_seconds'] = time.monotonic()-begin
        (output/'result.json').write_bytes(ENC(report))
    save()
    try:
        for index, declared in enumerate(values):
            case = declared['case']
            folder = output/('case-%03d'%index)
            folder.mkdir(mode=0o700)
            (folder/'case.json').write_bytes(ENC(case))
            answers = []
            implementations = [('native',native)]
            if original is not None:
                implementations.append(('original',original))
            for side, binary in implementations:
                row = {}
                report['processes'].append(row)
                def update(value):
                    row.clear();row.update(value);save()
                answer = run(binary,side,folder,case,update)
                assert answer[0].hex()==declared['wire_hex'] and H(answer[0])==declared['wire_sha256'],case['name']
                answers.append(answer)
                report[side+'_processes']+=1
                report[side+'_requests']+=len(case['events'])
            if original is not None:
                assert answers[0]==answers[1],('full wire/filesystem difference',case['name'])
            for side,_ in implementations:
                retire_fixture(folder/side)
            report['completed'].append(dict(name=case['name'],requests=len(case['events']),
                normalized_wire_sha256=H(answers[0][0]),normalized_wire_bytes=len(answers[0][0]),
                **answers[0][3]))
            save()
        assert (report['native_processes'],report['native_requests'])==(64,359)
        assert original is None or (report['original_processes'],report['original_requests'])==(64,359)
        assert pin(native)==identities['native']
        assert original is None or pin(original)==identities['original']
        assert all(pin(Path(path))==want for path,want in sources.items())
        report['status']='PASS'
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc())
        raise
    finally:
        save()
    return output/'result.json'


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--original',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=execute(args.native,args.output,args.original)
    from normal_evidence import verify
    evidence=verify(args.output,args.native,args.original)
    print(json.dumps(evidence,sort_keys=True))
