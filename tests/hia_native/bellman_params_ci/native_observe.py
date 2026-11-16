"""Observe full HIA parameter and diagnostic calls against frozen CI originals."""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
sys.dont_write_bytecode=True

def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def u64(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def records(raw):
    at=0
    while at<len(raw):
        size=u64(raw,at);at+=8;value=raw[at:at+size];at+=size
        assert len(value)==size;yield value
    assert at==len(raw)
def request(raw):return b'HBLPAR01'+struct.pack('<7Q',1,len(raw),0,0,0,0,0)+raw
def originals(reference,package):
    report=json.loads((reference/'original.json').read_bytes())
    raw=(reference/'original.stdout').read_bytes();assert pin(raw)==report['complete_output']
    domain=json.loads((package/'corpus-domain.json').read_bytes())['cases']
    assert len(domain)==len(report['cases'])==683
    output=list(records(raw));assert len(output)==len(domain)
    for index,(expected,row,value) in enumerate(zip(domain,report['cases'],output)):
        assert (expected['group'],expected['name'])==(row['group'],row['name'])
        assert {k:expected[k] for k in ('bytes','sha256')}==row['raw']
        assert value[:8]==b'HBPOR001' and len(value)==64+u64(value,16)+u64(value,24)
        canonical=value[64:64+u64(value,16)];body=value[64+u64(value,16):]
        assert pin(canonical)==row['canonical'] and pin(body)==row['body'] and u64(value,8)==row['status']
        yield index,row,canonical,body
def check_source(package):
    manifest=json.loads((package/'package-manifest.json').read_bytes())
    actual={str(path.relative_to(package)) for path in package.rglob('*') if path.is_file()}
    assert actual==set(manifest['files'])|{'package-manifest.json'}
    for name,value in manifest['files'].items():
        relative=Path(name);assert not relative.is_absolute() and '..' not in relative.parts
        path=package/relative;assert not path.is_symlink() and path.resolve()==path
        assert pin(path.read_bytes())==value,name
    return pin((package/'package-manifest.json').read_bytes())

def main(args):
    package=args.package.resolve(strict=True);source_pin=check_source(package)
    build=json.loads((args.build/'build.json').read_bytes());assert build['status']=='BUILD_PASS'
    sys.path.insert(0,str(package/'source/scripts'))
    from hia_native_loader import NativeModule
    output=args.output.resolve();output.mkdir();blobs=output/'blobs';blobs.mkdir()
    def save(raw):
        identity=pin(raw);path=blobs/identity['sha256']
        if not path.exists():path.write_bytes(raw)
        return identity
    calls=[];rows=[];before=time.monotonic()
    call_log=(output/'calls.jsonl').open('x');case_log=(output/'cases.jsonl').open('x')
    with contextlib.ExitStack() as stack:
        modules={name:stack.enter_context(NativeModule(Path(row['manifest']),manifest_sha256=row['sha256']))
                 for name,row in build['files'].items()}
        for name,row in build['files'].items():
            metadata=json.loads(Path(row['manifest']).read_bytes())
            assert metadata['source_sha256']==pin((package/'source/native'/f'{name}.hepta').read_bytes())['sha256']
        def observe(module,wire,outcap,workcap,case,role):
            result,out,work=modules[module].invoke_raw(wire,output_capacity=outcap,workspace_capacity=workcap,
                                                     output_fill=0xcc,workspace_fill=0xa7)
            record={'index':len(calls),'case':case,'role':role,'module':module,'code':result,
                    'output_capacity':outcap,'workspace_capacity':workcap,
                    'input':save(wire),'output':save(out),'workspace':save(work)}
            calls.append(record);call_log.write(json.dumps(record,sort_keys=True)+'\n');call_log.flush()
            return record,out,work
        def invoke(module,wire,case):
            outcap=65536;workcap=262144;attempts=[]
            header=128 if module=='bellman_params' else 64
            magic=b'HBLPAT01' if header==128 else b'HBLPDR01'
            for attempt in range(4):
                record,out,work=observe(module,wire,outcap,workcap,case,'semantic')
                attempts.append(record['index']);code=record['code']
                assert code<0xffff0000,(case,module,code)
                assert out[:8]==magic and code>=header,(case,module,code,out[:128].hex())
                status=u64(out,8)
                if status==2:
                    assert code==header and u64(out,24)>workcap
                    assert out[header:]==b'\xcc'*(outcap-header)
                    workcap=u64(out,24);continue
                if status==3:
                    assert code==header and u64(out,24)>outcap
                    assert out[header:]==b'\xcc'*(outcap-header)
                    outcap=u64(out,24);continue
                assert status in (0,1) and (status==0 or module=='bellman_params')
                assert code==header+u64(out,16) and out[code:]==b'\xcc'*(outcap-code)
                return out[:code],attempts
            raise AssertionError(('nonterminating growth',case,module))
        examples={}
        for index,row,canonical,expected in originals(args.reference,package):
            if row['group']!=args.group:continue
            name=row['name'];wire=request(canonical)
            typed,typed_calls=invoke('bellman_params',wire,name)
            status=u64(typed,8)
            assert status==row['status'],(name,status,row['status'],typed[:128].hex(),row['error'])
            diagnostic=None;diagnostic_calls=[]
            if status==0:
                assert typed[128:]==expected,(name,'graph bytes',pin(typed[128:]),pin(expected))
                assert u64(typed,32)==row['states']
                assert typed[40:128]==bytes(88)
                examples.setdefault('success',(wire,typed))
            else:
                diagnostic,diagnostic_calls=invoke('bellman_params_diagnostic',typed+wire,name)
                assert diagnostic[64:]==expected,(name,'error bytes',diagnostic[64:564],expected[:500])
                assert u64(diagnostic,8)==0 and u64(diagnostic,24)==0 and diagnostic[32:64]==bytes(32)
                examples.setdefault('error',(typed+wire,diagnostic))
            result={'index':index,'name':name,'status':status,'input':save(wire),'typed':save(typed),
                    'diagnostic':None if diagnostic is None else save(diagnostic),'expected':pin(expected),
                    'typed_calls':typed_calls,'diagnostic_calls':diagnostic_calls}
            rows.append(result);case_log.write(json.dumps(result,sort_keys=True)+'\n');case_log.flush()
        controls=[];sessions=[]
        if args.group=='ordinary':
            def control(module,name,wire,outcap,workcap,expectation,expected=None):
                record,out,work=observe(module,wire,outcap,workcap,name,'control')
                code=record['code'];header=128 if module=='bellman_params' else 64
                if expectation in ('refuse','short-output'):
                    assert code==(0xffffffff if expectation=='refuse' else 0xfffffffe)
                    assert out==b'\xcc'*outcap and work==b'\xa7'*workcap
                elif expectation=='grow-workspace':
                    assert code==header and u64(out,8)==2 and u64(out,24)>workcap
                    assert out[header:]==b'\xcc'*(outcap-header) and work==b'\xa7'*workcap
                elif expectation=='grow-output':
                    assert code==header and u64(out,8)==3 and u64(out,24)==len(expected)
                    assert out[header:]==b'\xcc'*(outcap-header)
                elif expectation=='success':
                    assert code==len(expected) and out[:code]==expected and out[code:]==b'\xcc'*(outcap-code)
                else:raise AssertionError(expectation)
                controls.append({'call':record['index'],'expectation':expectation,'expected':save(expected) if expected is not None else None})
            wire,typed=examples['success'];diagwire,diagnostic=examples['error']
            for module,base,good,header in [('bellman_params',wire,typed,128),('bellman_params_diagnostic',diagwire,diagnostic,64)]:
                for name,bad in [('empty',b''),('short-header',base[:header-1]),('truncated',base[:-1]),('trailing',base+b'x')]:
                    control(module,name,bad,65536,262144,'refuse')
                offsets=(0,8,16,24,32,40,48,56) if module=='bellman_params' else (0,8,16,24,32,104,112,120,128,136,144,152,160,168,176,184)
                for offset in offsets:
                    raw=bytearray(base);struct.pack_into('<Q',raw,offset,u64(raw,offset)^1)
                    control(module,f'bad-header-{offset}',bytes(raw),65536,262144,'refuse')
                for capacity in (0,1,header-1):control(module,'short-output-'+str(capacity),base,capacity,262144,'short-output')
                for capacity in (0,1,65535):control(module,'short-workspace-'+str(capacity),base,65536,capacity,'grow-workspace')
                for capacity in (header,len(good)-1):
                    if capacity<len(good):control(module,'grow-output-'+str(capacity),base,capacity,262144,'grow-output',good)
                control(module,'exact-output',base,len(good),262144,'success',good)
            for offset,value in ((40,0),(40,7),(48,7),(56,0),(64,1),(72,1),(80,(1<<64)-1),(88,1),(96,1)):
                raw=bytearray(diagwire);struct.pack_into('<Q',raw,offset,value)
                control('bellman_params_diagnostic',f'bad-descriptor-{offset}',bytes(raw),65536,262144,'refuse')
            for module,base,good in [('bellman_params',wire,typed),('bellman_params_diagnostic',diagwire,diagnostic)]:
                with modules[module].session(output_capacity=65536,workspace_capacity=262144) as session:
                    observations=[];indices=[]
                    for number,value in enumerate((base,b'',base)):
                        code,out,work=session.invoke_raw(value)
                        record={'index':len(calls),'case':'same-session-'+module,'role':'session','module':module,
                                'code':code,'output_capacity':65536,'workspace_capacity':262144,
                                'input':save(value),'output':save(out),'workspace':save(work)}
                        calls.append(record);call_log.write(json.dumps(record,sort_keys=True)+'\n');call_log.flush()
                        observations.append((code,out,work));indices.append(record['index'])
                    assert observations[0]==observations[2]
                    assert observations[1][0]==0xffffffff and observations[1][1:]==observations[0][1:]
                    assert observations[0][0]==len(good) and observations[0][1][:len(good)]==good
                    sessions.append({'module':module,'calls':indices,'expected':save(good)})
        check_source(package)
    call_log.close();case_log.close()
    result={'status':'PASS','group':args.group,'source_manifest':source_pin,'case_count':len(rows),
            'control_count':len(controls),'calls':len(calls),'logical_call_bytes':sum(sum(row[k]['bytes'] for k in ('input','output','workspace')) for row in calls),
            'cases':rows,'controls':controls,'sessions':sessions,'wall_seconds':time.monotonic()-before,'whole_runtime_replaced':False,
            'public_handler_qualified':False,'original_observation':pin((args.reference/'original.stdout').read_bytes()),
            'call_log':pin((output/'calls.jsonl').read_bytes()),'case_log':pin((output/'cases.jsonl').read_bytes())}
    write(output/'report.json',result)
    print(json.dumps({k:result[k] for k in ('status','group','case_count','control_count','calls','logical_call_bytes','wall_seconds')}),flush=True)
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('package','build','reference','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--group',choices=('ordinary','unicode'),required=True)
    main(parser.parse_args())
