"""Complete actual-kernel corpus runner shared by native and Rust qualification."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,stat,struct,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
if str(HERE) not in sys.path:sys.path.insert(0,str(HERE))
from atomic_write_cases import cases,data,setup,snapshot,semantic_snapshot,normalized_trace
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def wire(case):
    p=bytes.fromhex(case['path']);c=data(case)
    return struct.pack('<8s7Q',b'HRAWI001',1,len(p),len(c),0,0,0,0)+p+c
def request_pieces(case):
    path=bytes.fromhex(case['path']);pattern=bytes.fromhex(case['content']['pattern']);repeat=case['content']['repeat']
    count=len(pattern)*repeat
    yield struct.pack('<Q8s7Q',64+len(path)+count,b'HRAWI001',1,len(path),count,0,0,0,0)+path
    if not pattern:return
    block=pattern*max(1,(1<<20)//len(pattern))
    while count:
        piece=block[:min(count,len(block))];yield piece;count-=len(piece)
def records(raw):
    at=0;rows=[]
    while at<len(raw):
        assert at+4<=len(raw)
        code=struct.unpack_from('<I',raw,at)[0];at+=4;size=code if code<=1024<<20 else 0
        assert at+size<=len(raw);rows.append((code,raw[at:at+size]));at+=size
    return rows
def run(executable,destination,*,selected=None):
    executable=Path(executable).resolve(strict=True);destination=Path(destination).resolve()
    destination.mkdir(mode=0o700)
    corpus=cases() if selected is None else selected
    before_binary=executable.read_bytes();definition=encoded(corpus)
    (destination/'cases.json').write_bytes(definition+b'\n')
    result={'schema':'hepta.runtime.atomic-write-kernel-suite.v1','status':'RUNNING','cases':0,'requests':0,'native_or_original_executable_sha256':sha(before_binary),
      'execution_directory':str(destination),
      'execution_uid':os.geteuid(),'execution_gid':os.getegid(),
      'executable_bytes':len(before_binary),'case_definition_sha256':sha(definition),'total_declared_cases':len(corpus),'observations':[],
      'source_files':{name:sha((HERE/name).read_bytes()) for name in ['atomic_write_cases.py','atomic_write_kernel.py','atomic_write_supervisor.py']}}
    started=time.monotonic();full_inputs=hashlib.sha256();full_outputs=hashlib.sha256();input_bytes=0;output_bytes=0
    try:
        for index,case in enumerate(corpus):
            name=f'{index:04d}-{case["name"]}';entry=destination/name;entry.mkdir(mode=0o700)
            fixture=entry/'fixture';setup(fixture,case)
            before=snapshot(fixture,entry/'before-content')
            request_digest=hashlib.sha256();request_bytes=0
            with (entry/'request.bin').open('xb') as raw,gzip.open(entry/'request.bin.gz','wb') as compressed:
                for _ in range(case.get('requests',1)):
                    for part in request_pieces(case):
                        raw.write(part);compressed.write(part);request_digest.update(part);full_inputs.update(part)
                        request_bytes+=len(part);input_bytes+=len(part)
            (entry/'config.json').write_bytes(encoded(case['config'])+b'\n')
            command=[sys.executable,'-I',str(HERE/'atomic_write_supervisor.py'),'--executable',str(executable),'--fixture',str(fixture),
              '--config',str(entry/'config.json'),'--log',str(entry/'trace.json'),'--timeout','15']
            with (entry/'request.bin').open('rb') as input_file:
                child=subprocess.run(command,stdin=input_file,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            (entry/'stdout.bin').write_bytes(child.stdout);(entry/'stderr.bin').write_bytes(child.stderr)
            after=snapshot(fixture,entry/'after-content');semantic=semantic_snapshot(before,after)
            observation={'name':case['name'],'index':index,'request_bytes':request_bytes,'request_sha256':request_digest.hexdigest(),'request_file':str((entry/'request.bin.gz').relative_to(destination)),
              'fixture_path':str(fixture),
              'exit_code':child.returncode,'stdout_bytes':len(child.stdout),'stdout_sha256':sha(child.stdout),'stdout_hex':child.stdout.hex(),
              'stderr_bytes':len(child.stderr),'stderr_sha256':sha(child.stderr),'before':before,'after':after,'semantic_snapshot':semantic}
            if (entry/'trace.json').exists():
                trace=json.loads((entry/'trace.json').read_bytes());observation['trace']=trace
                observation['normalized_trace']=normalized_trace(trace,fixture)
            (entry/'observation.json').write_bytes(encoded(observation)+b'\n')
            result['observations'].append(observation)
            assert child.returncode==0,(case['name'],child.stderr.decode(errors='replace'))
            assert trace['status']=='PASS' and trace['failure'] is None and trace['exit_code']==0
            assert trace['stdout_sha256']==sha(child.stdout) and trace['stderr_sha256']==sha(child.stderr)
            assert trace['executable_sha256']==sha(before_binary)
            answers=records(child.stdout);assert len(answers)==case.get('requests',1)
            code,response=answers[0]
            if 'cancel' in case['config']:
                assert code==0xfffffff7 and trace['cancel_ack']['worker_syscall_still_held'] is True
                if case.get('requests',1)>1:assert answers[1]==(32,struct.pack('<8s3Q',b'HRAWR001',0,0,0))
            else:
                assert code<=1024<<20 and response[:8]==b'HRAWR001'
                tag,stage,size=struct.unpack_from('<3Q',response,8)
                assert len(response)==32+size and tag in (0,1) and (stage==0)==(tag==0)
                if 'target_mode' in case['checks']:
                    assert tag==0
                    target=next(r for r in after if r['path']==b'target'.hex())
                    assert stat.S_IMODE(target['mode'])==case['checks']['target_mode']
            for fault in case['config'].get('faults',[]):
                events=[e for e in trace['events'] if e['kind']==fault['kind'] and e['ordinal']==fault.get('ordinal',1)]
                assert len(events)==1,(case['name'],'fault was not reached',fault)
                assert events[0]['completion'].startswith('injected_')
            if case['name']=='actual-partial-write':
                temp=next(r for r in after if r['path']==b'.octofs_tmp_target.tmp'.hex())
                assert temp['content_bytes']==3 and temp['content_sha256']==sha(b'012')
                assert trace['counts']['write']==2
            if case['name']=='full-batch-crlf-write-505-mib':
                target=next(r for r in after if r['path']==b'target'.hex())
                assert target['content_bytes']==505<<20 and trace['counts']['write']>=1
                assert struct.unpack_from('<Q',response,8)[0]==0
            # Complete lossless input remains in the checked gzip corpus; the
            # temporary raw stdin file is no longer needed after the child ends.
            (entry/'request.bin').unlink()
            full_outputs.update(child.stdout);output_bytes+=len(child.stdout)
            result['cases']+=1
            result['requests']+=len(answers)
        assert executable.read_bytes()==before_binary
        assert result['source_files']=={name:sha((HERE/name).read_bytes()) for name in result['source_files']}
        result.update(status='PASS',requests_sha256=full_inputs.hexdigest(),requests_bytes=input_bytes,
          outputs_sha256=full_outputs.hexdigest(),outputs_bytes=output_bytes,
          actual_kernel_cases=sum(not (c['config'].get('faults') or 'file_size_limit' in c['config'] or 'cancel' in c['config']) for c in corpus),
          kernel_fault_cases=sum(bool(c['config'].get('faults')) and 'cancel' not in c['config'] for c in corpus),
          actual_partial_limit_cases=sum('file_size_limit' in c['config'] for c in corpus),
          cancellation_cases=sum('cancel' in c['config'] for c in corpus))
    except BaseException as e:
        result.update(status='FAIL',failure=repr(e));raise
    finally:
        result['elapsed']=time.monotonic()-started
        (destination/'result.json').write_bytes(encoded(result)+b'\n')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=run(a.binary,a.output)
    print(json.dumps({k:v for k,v in r.items() if k!='observations'},sort_keys=True))
if __name__=='__main__':main()
