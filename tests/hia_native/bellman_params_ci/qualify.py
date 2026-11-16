"""Fresh build, unchanged original observations and complete native qualification."""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
sys.dont_write_bytecode=True
PACKAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(PACKAGE))
from native_observe import check_source,originals,pin,records,request,u64
from cases import all_cases
B3='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
MODULES=('bellman_params','bellman_params_diagnostic')
SCOPE='complete canonical Value to unchanged Bellman typed parameters and full diagnostics; solver/admission/clock/public routing excluded'
def write(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')
def capture(command,cwd,folder,name,timeout):
    folder.mkdir(parents=True,exist_ok=True);before=time.monotonic();timed_out=False
    try:
        result=subprocess.run(command,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        code=result.returncode;out=result.stdout;err=result.stderr
    except subprocess.TimeoutExpired as error:
        code=None;out=error.stdout or b'';err=error.stderr or b'';timed_out=True
    for suffix,raw in (('stdout',out),('stderr',err)):(folder/f'{name}.{suffix}').write_bytes(raw)
    receipt={'command':command,'cwd':str(cwd),'timeout_seconds':timeout,'returncode':code,'timed_out':timed_out,
             'wall_seconds':time.monotonic()-before,'stdout':pin(out),'stderr':pin(err)}
    write(folder/f'{name}.process.json',receipt)
    assert code==0 and not timed_out,(name,receipt)
    return out
def build(args):
    check_source(PACKAGE);root=args.output/'build'
    if args.bootstrap_cache:
        cache=args.bootstrap_cache.resolve(strict=True)
        for name in ('B1.image.bin','B2.image.bin','B3.image.bin'):assert pin((cache/name).read_bytes())=={'bytes':673413,'sha256':B3}
        shutil.copytree(cache,root/'bootstrap')
    else:assert os.environ.get('GITHUB_ACTIONS')=='true','local compiler bootstrap is forbidden'
    sys.path.insert(0,str(PACKAGE/'source/scripts'))
    from hia_native_build import NativeBuild
    builder=NativeBuild(args.hepta,root);rows={};before=time.monotonic()
    for name in MODULES:
        manifest=builder.compile(name,PACKAGE/'source/native'/f'{name}.hepta',standalone=None,buffer_profile='batch-plan.v1')
        metadata=json.loads(manifest.read_bytes());assert metadata['compiler_sha256']==B3
        rows[name]={'manifest':str(manifest),'sha256':pin(manifest.read_bytes())['sha256'],
                    'source_sha256':metadata['source_sha256'],'image_sha256':metadata['image_sha256']}
    result={'status':'BUILD_PASS','files':rows,'wall_seconds':time.monotonic()-before,'fresh_components':2,'reused_components':0}
    write(args.output/'build.json',result);print(json.dumps(result),flush=True)
def original_check(output):
    folder=output/'original';report=json.loads((folder/'original.json').read_bytes())
    assert report['status']=='ORIGINAL_OBSERVED_NATIVE_REQUIRED' and report['case_count']==683
    assert report['successful_typed']==401 and report['typed_errors']==282
    assert report['source_manifest']==check_source(PACKAGE)
    for name,timeout in (('rust-version',15),('resolve',60),('build',180),('original',60)):
        receipt=json.loads((folder/f'{name}.process.json').read_bytes())
        assert receipt['returncode']==0 and receipt['timed_out'] is False and receipt['timeout']==timeout
        assert 0<=receipt['wall_seconds']<=timeout+1
        for suffix,expected in receipt['streams'].items():assert pin((folder/f'{name}.{suffix}').read_bytes())==expected
    assert (folder/'rust-version.stdout').read_bytes().startswith(b'rustc 1.95.0 ')
    expected_input=b''.join(struct.pack('<Q',len(raw))+raw for _,_,raw in all_cases(PACKAGE/'qualify_bellman.py'))
    assert (folder/'original.stdin').read_bytes()==expected_input and pin(expected_input)==report['complete_input']
    resolved=json.loads((folder/'resolved-pins.json').read_bytes())
    assert resolved['status']=='PASS' and resolved['target_registry_pins_exact'] is True
    assert pin((folder/'reference-build/Cargo.lock').read_bytes())==resolved['resolved_lock']
    import tomllib
    target=tomllib.loads((PACKAGE/'reference/target-Cargo.lock').read_text())
    target_pins={(p['name'],p['version']):(p.get('source'),p.get('checksum')) for p in target['package']}
    for package in resolved['packages']:
        if package.get('source'):assert target_pins[(package['name'],package['version'])]==(package['source'],package['checksum'])
    actual=tomllib.loads((folder/'reference-build/Cargo.lock').read_text())['package']
    assert actual==resolved['packages']
    for name in ('oracle.rs','Cargo.toml','weight_bellman.rs','target-Cargo.lock','target-Cargo.toml','extraction.json'):
        assert (folder/'reference-build'/name).read_bytes()==(PACKAGE/'reference'/name).read_bytes()
    return list(originals(folder,PACKAGE))
def control_plan(wire,typed,diagwire,diagnostic):
    for module,base,good,header in [('bellman_params',wire,typed,128),('bellman_params_diagnostic',diagwire,diagnostic,64)]:
        for name,bad in [('empty',b''),('short-header',base[:header-1]),('truncated',base[:-1]),('trailing',base+b'x')]:
            yield module,name,bad,65536,262144,'refuse',None
        offsets=(0,8,16,24,32,40,48,56) if module=='bellman_params' else (0,8,16,24,32,104,112,120,128,136,144,152,160,168,176,184)
        for offset in offsets:
            raw=bytearray(base);struct.pack_into('<Q',raw,offset,u64(raw,offset)^1)
            yield module,f'bad-header-{offset}',bytes(raw),65536,262144,'refuse',None
        for capacity in (0,1,header-1):yield module,'short-output-'+str(capacity),base,capacity,262144,'short-output',None
        for capacity in (0,1,65535):yield module,'short-workspace-'+str(capacity),base,65536,capacity,'grow-workspace',None
        for capacity in (header,len(good)-1):
            if capacity<len(good):yield module,'grow-output-'+str(capacity),base,capacity,262144,'grow-output',good
        yield module,'exact-output',base,len(good),262144,'success',good
    for offset,value in ((40,0),(40,7),(48,7),(56,0),(64,1),(72,1),(80,(1<<64)-1),(88,1),(96,1)):
        raw=bytearray(diagwire);struct.pack_into('<Q',raw,offset,value)
        yield 'bellman_params_diagnostic',f'bad-descriptor-{offset}',bytes(raw),65536,262144,'refuse',None
def verify(args):
    output=args.output;source=check_source(PACKAGE)
    run=json.loads((output/'run.json').read_bytes());assert run['scope']==SCOPE
    assert run['source_manifest']==source and run['fresh_native_components']==2 and run['reused_native_components']==0
    original_root=Path(run['output_root'])
    def relocated(value):return output/Path(value).relative_to(original_root)
    built=json.loads((output/'build.json').read_bytes());assert built['status']=='BUILD_PASS'
    assert built['fresh_components']==2 and built['reused_components']==0 and set(built['files'])==set(MODULES)
    for name,row in built['files'].items():
        manifest=relocated(row['manifest']);raw=manifest.read_bytes();assert pin(raw)['sha256']==row['sha256']
        metadata=json.loads(raw);assert metadata['compiler_sha256']==B3 and metadata['standalone'] is None
        assert metadata['buffer_profile']=='batch-plan.v1'
        for key in ('source','image'):
            raw=(manifest.parent/metadata[key]).read_bytes();assert pin(raw)['sha256']==metadata[key+'_sha256']==row[key+'_sha256']
            if key=='source':assert raw==(PACKAGE/'source/native'/f'{name}.hepta').read_bytes()
    for name in ('B1.image.bin','B2.image.bin','B3.image.bin'):assert pin((output/'build/bootstrap'/name).read_bytes())=={'bytes':673413,'sha256':B3}
    for name,timeout in (('build',180),('original',300),('ordinary',180),('unicode',180)):
        process=json.loads((output/'processes'/f'{name}.process.json').read_bytes())
        assert process['returncode']==0 and process['timed_out'] is False and process['timeout_seconds']==timeout
        assert 0<=process['wall_seconds']<=timeout+1
        for suffix in ('stdout','stderr'):assert pin((output/'processes'/f'{name}.{suffix}').read_bytes())==process[suffix]
    expected=original_check(output);totals={'cases':0,'controls':0,'calls':0,'logical_call_bytes':0}
    for group,count,call_count in (('ordinary',680,1192),('unicode',3,12)):
        folder=output/group;report=json.loads((folder/'report.json').read_bytes())
        assert report['status']=='PASS' and report['group']==group and report['source_manifest']==source
        assert report['case_count']==count and report['calls']==call_count
        assert report['whole_runtime_replaced'] is False and report['public_handler_qualified'] is False
        assert report['original_observation']==pin((output/'original/original.stdout').read_bytes())
        for stem in ('call','case'):assert pin((folder/(stem+'s.jsonl')).read_bytes())==report[stem+'_log']
        calls=[json.loads(line) for line in (folder/'calls.jsonl').read_text().splitlines()]
        assert len(calls)==call_count and [row['index'] for row in calls]==list(range(call_count))
        assert [json.loads(line) for line in (folder/'cases.jsonl').read_text().splitlines()]==report['cases']
        wanted_blobs=set();cache={}
        def blob(value):
            assert set(value)=={'bytes','sha256'} and isinstance(value['bytes'],int) and value['bytes']>=0
            digest=value['sha256'];assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest)
            wanted_blobs.add(digest)
            if digest in cache:raw=cache[digest]
            else:
                raw=(folder/'blobs'/digest).read_bytes();assert pin(raw)==value
                if len(raw)<65536:cache[digest]=raw
            assert len(raw)==value['bytes'];return raw
        for row in calls:
            for key in ('input','output','workspace'):blob(row[key])
            assert row['output_capacity']==row['output']['bytes'] and row['workspace_capacity']==row['workspace']['bytes']
        used=set();examples={}
        def chain(indices,module,wire,result,name):
            outcap=65536;workcap=262144;header=128 if module=='bellman_params' else 64
            magic=b'HBLPAT01' if header==128 else b'HBLPDR01'
            assert 1<=len(indices)<=4
            for position,index in enumerate(indices):
                assert index not in used;used.add(index);row=calls[index]
                assert row['role']=='semantic' and row['case']==name and row['module']==module
                assert row['output_capacity']==outcap and row['workspace_capacity']==workcap and blob(row['input'])==wire
                raw=blob(row['output']);code=row['code'];assert raw[:8]==magic and header<=code<=len(raw)
                assert raw[code:]==b'\xcc'*(len(raw)-code)
                status=u64(raw,8)
                if position+1==len(indices):assert status in (0,1) and raw[:code]==result and code==header+u64(raw,16)
                else:
                    assert code==header and status in (2,3) and u64(raw,16)==0
                    needed=u64(raw,24)
                    if status==2:assert needed>workcap;workcap=needed
                    else:assert needed>outcap;outcap=needed
        selected=[item for item in expected if item[1]['group']==group];assert len(report['cases'])==len(selected)==count
        for observed,(index,original,canonical,body) in zip(report['cases'],selected):
            assert observed['index']==index and observed['name']==original['name'] and observed['status']==original['status']
            wire=request(canonical);typed=blob(observed['typed']);assert blob(observed['input'])==wire
            assert observed['expected']==pin(body)
            assert typed[:8]==b'HBLPAT01' and u64(typed,8)==original['status'] and u64(typed,24)==0
            chain(observed['typed_calls'],'bellman_params',wire,typed,original['name'])
            if original['status']==0:
                assert typed[128:]==body and u64(typed,32)==original['states'] and typed[40:128]==bytes(88)
                assert observed['diagnostic'] is None and observed['diagnostic_calls']==[]
                examples.setdefault('success',(wire,typed))
            else:
                assert len(typed)==128 and u64(typed,16)==u64(typed,32)==0 and typed[104:128]==bytes(24)
                diagnostic=blob(observed['diagnostic']);assert diagnostic[:8]==b'HBLPDR01' and u64(diagnostic,8)==0
                assert diagnostic[64:]==body and u64(diagnostic,24)==0 and diagnostic[32:64]==bytes(32)
                chain(observed['diagnostic_calls'],'bellman_params_diagnostic',typed+wire,diagnostic,original['name'])
                examples.setdefault('error',(typed+wire,diagnostic))
        plans=list(control_plan(*examples['success'],*examples['error'])) if group=='ordinary' else []
        assert report['control_count']==len(report['controls'])==len(plans)==(59 if group=='ordinary' else 0)
        for observed,plan in zip(report['controls'],plans):
            module,name,wire,outcap,workcap,kind,good=plan;index=observed['call'];assert index not in used;used.add(index)
            row=calls[index];out=blob(row['output']);work=blob(row['workspace']);header=128 if module=='bellman_params' else 64
            assert (row['module'],row['case'],blob(row['input']),row['output_capacity'],row['workspace_capacity'],row['role'])==(module,name,wire,outcap,workcap,'control')
            assert observed['expectation']==kind and observed['expected']==(pin(good) if good is not None else None)
            if good is not None:assert blob(observed['expected'])==good
            if kind in ('refuse','short-output'):
                assert row['code']==(0xffffffff if kind=='refuse' else 0xfffffffe)
                assert out==b'\xcc'*outcap and work==b'\xa7'*workcap
            elif kind=='grow-workspace':
                assert row['code']==header and u64(out,8)==2 and u64(out,24)>workcap
                assert out[header:]==b'\xcc'*(outcap-header) and work==b'\xa7'*workcap
            elif kind=='grow-output':
                assert row['code']==header and u64(out,8)==3 and u64(out,24)==len(good) and out[header:]==b'\xcc'*(outcap-header)
            else:assert kind=='success' and row['code']==len(good) and out==good
        assert len(report['sessions'])==(2 if group=='ordinary' else 0)
        for session in report['sessions']:
            module=session['module'];base,good=examples['success' if module=='bellman_params' else 'error']
            assert blob(session['expected'])==good and len(session['calls'])==3;actual=[]
            for index,wire in zip(session['calls'],(base,b'',base)):
                assert index not in used;used.add(index);row=calls[index]
                assert row['module']==module and row['role']=='session' and row['case']=='same-session-'+module
                assert row['output_capacity']==65536 and row['workspace_capacity']==262144 and blob(row['input'])==wire
                actual.append((row['code'],blob(row['output']),blob(row['workspace'])))
            assert actual[0]==actual[2] and actual[1][0]==0xffffffff and actual[1][1:]==actual[0][1:]
            assert actual[0][0]==len(good) and actual[0][1][:len(good)]==good
        assert used==set(range(call_count))
        assert {p.name for p in (folder/'blobs').iterdir()}==wanted_blobs
        logical=sum(sum(row[key]['bytes'] for key in ('input','output','workspace')) for row in calls)
        assert logical==report['logical_call_bytes']
        for key,value in [('cases',count),('controls',len(plans)),('calls',call_count),('logical_call_bytes',logical)]:totals[key]+=value
    return {'status':'PASS','source_manifest':source,'scope':SCOPE,'fresh_native_components':2,'reused_native_components':0,
            'complete_original_typed_bytes_compared':True,'public_handler_qualified':False,'whole_runtime_replaced':False,**totals}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=('build','all','verify'),required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--hepta',type=Path);parser.add_argument('--bootstrap-cache',type=Path)
    args=parser.parse_args();args.output=args.output.resolve()
    if args.phase=='build':build(args);return
    if args.phase=='verify':print(json.dumps(verify(args)),flush=True);return
    assert os.environ.get('GITHUB_ACTIONS')=='true';args.output.mkdir()
    shutil.copytree(PACKAGE,args.output/'recipe-source')
    write(args.output/'run.json',{'scope':SCOPE,'source_manifest':check_source(PACKAGE),'output_root':str(args.output),'fresh_native_components':2,'reused_native_components':0})
    capture([sys.executable,'-I','-B',str(PACKAGE/'qualify.py'),'--phase','build','--output',str(args.output),'--hepta',str(args.hepta.resolve())],PACKAGE,args.output/'processes','build',180)
    capture([sys.executable,'-I','-B',str(PACKAGE/'observe_original.py'),'--output',str(args.output/'original')],PACKAGE,args.output/'processes','original',300)
    for group in ('ordinary','unicode'):
        capture([sys.executable,'-I','-B',str(PACKAGE/'native_observe.py'),'--package',str(PACKAGE),'--build',str(args.output),
                 '--reference',str(args.output/'original'),'--group',group,'--output',str(args.output/group)],PACKAGE,args.output/'processes',group,180)
    result=verify(args);write(args.output/'result.json',result);print(json.dumps(result),flush=True)
if __name__=='__main__':main()
