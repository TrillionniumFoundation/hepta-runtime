"""Actual fixed-boundary refusals, descriptor recovery and transport controls."""
from __future__ import annotations
import argparse,json,os,struct,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
for p in (HERE,ROOT/'scripts'):
    if str(p) not in sys.path:sys.path.insert(0,str(p))
from hia_native_atomic_write_build import (NativeBuild,inspect_bundle,inspect_elf,native_receipt,
 COMPILE_FILES,COMPILER,PACKER_IMAGE,read,sha,obj,file_record,exact,require,json_bytes,write_new)
from atomic_write_harness import frame,stream
from atomic_write_cases import make,setup,snapshot
PROBE_SOURCE='c6d89613aa38bd714d023bd8b047c3a61998375fb5b4bfef61ba2bc4e636b870'
SOURCE_FILES=('tests/hia_native/test_atomic_write_boundary.py','tests/hia_native/atomic_write_contract_probe.hepta',
 'tests/hia_native/atomic_write_supervisor.py','tests/hia_native/atomic_write_harness.py','tests/hia_native/atomic_write_cases.py')

def supervised(binary,entry,request,config,fixture):
    write_new(entry/'config.json',json_bytes(config));write_new(entry/'input.bin',request)
    command=[sys.executable,'-I',str(HERE/'atomic_write_supervisor.py'),'--executable',str(binary),
      '--fixture',str(fixture),'--config',str(entry/'config.json'),'--log',str(entry/'trace.json'),'--timeout','5']
    actual=subprocess.run(command,input=request,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    write_new(entry/'stdout.bin',actual.stdout);write_new(entry/'stderr.bin',actual.stderr)
    files={name:file_record(entry/name) for name in ('input.bin','stdout.bin','stderr.bin','config.json','trace.json')}
    return actual,obj(entry/'trace.json'),files

def build_probe(builder,manifest,destination):
    source=read(HERE/'atomic_write_contract_probe.hepta');exact(sha(source),PROBE_SOURCE,'contract fixture source differs')
    name='atomic-write-contract-'+PROBE_SOURCE[:16];path=builder.root/'modules'/name/'manifest.json';reused=path.exists()
    if not reused:path=builder.compile(name,HERE/'atomic_write_contract_probe.hepta',standalone=None)
    meta=obj(path);image=read(path.parent/meta['image'])
    exact(meta['source_sha256'],PROBE_SOURCE,'actual probe source differs')
    exact(read(path.parent/meta['source']),source,'actual compiled fixture differs')
    exact(meta['compiler_sha256'],COMPILER,'actual probe compiler differs')
    exact(meta['image_sha256'],sha(image),'actual fixture image differs')
    receipt=native_receipt(path.parent,'module',source=source,produced=image,producer=COMPILER)
    exact(obj(path.parent/'build.json')['compile_receipt'],receipt,'probe compile invocation differs')
    compiled=destination/'probe-compile';compiled.mkdir()
    for name in COMPILE_FILES:write_new(compiled/name,read(path.parent/name))
    write_new(compiled/'source.hepta',source)
    from tools.qualify_hia_selfhost import invoke
    packed=destination/'probe-pack';packed.mkdir();pack_input=b'HIAATPK1'+struct.pack('<Q',len(image))+image
    native_record,output=invoke(packed,'pack',manifest.parent/'packer.image.bin',pack_input)
    count=native_record.get('core_u32');require(type(count)is int and 0<count<=1<<20,'fixture packer rejected')
    elf=output[:count];inspection=inspect_elf(elf,image)
    native_receipt(packed,'pack',source=pack_input,produced=elf,producer=PACKER_IMAGE)
    binary=packed/'probe.elf';write_new(binary,elf,0o500)
    report={'source_sha256':PROBE_SOURCE,'image_sha256':sha(image),'executable_sha256':sha(elf),
      'inspection':inspection,'compile_reused':reused,'compilation':{n:file_record(compiled/n) for n in (*COMPILE_FILES,'source.hepta')},
      'pack_files':{p.name:file_record(p) for p in packed.iterdir() if p.is_file()}}
    return binary,report

def run(manifest,hepta,build_root,destination):
    manifest=Path(manifest).resolve(strict=True);destination=Path(destination).resolve();destination.mkdir(mode=0o700)
    before=inspect_bundle(manifest);source_files={p:file_record(ROOT/p) for p in SOURCE_FILES}
    result={'schema':'hepta.runtime.atomic-write-boundary-suite.v1','status':'RUNNING','artifact_evidence':before,
      'source_files':source_files,'contract_requests':0,'contract_effects':0,'transport_processes':0,
      'parent_death_processes':0,'original_rust_calls':0,'observations':[]}
    started=time.monotonic()
    try:
        builder=NativeBuild(hepta,build_root);exact(sha(builder.bootstrap().read_bytes()),COMPILER,'probe compiler differs')
        binary,result['fixture']=build_probe(builder,manifest,destination)
        for kind in range(19):
            entry=destination/f'contract-{kind:02d}';entry.mkdir();fixture=entry/'fixture';setup(fixture,make('probe'))
            payload=struct.pack('<Q',kind)+bytes(62)+b'abc';request=struct.pack('<Q',len(payload))+payload
            actual,trace,files=supervised(binary,entry,request,{},fixture)
            exact(actual.returncode,70,'invalid native effect was not refused')
            exact(actual.stdout,struct.pack('<I',0xfffffff9),'invalid effect result differs')
            exact(actual.stderr,b'','invalid effect emitted an unaccounted error')
            exact(trace['failure'],None,'descriptor refusal supervisor failed');exact(trace['exit_code'],70,'invalid-effect exit differs')
            exact(trace['counts'],{'open':1,'close':1},'refusal did not retire and close exactly one descriptor')
            exact([e['kind'] for e in trace['events']],['open','close'],'contract refusal performed another effect')
            exact((fixture/'target').read_bytes(),b'original','contract refusal changed the original')
            exact((fixture/'.octofs_tmp_target.tmp').read_bytes(),b'','contract refusal performed a write')
            result['contract_requests']+=1;result['contract_effects']+=2
            result['observations'].append({'kind':kind,'exit_code':actual.returncode,'trace':trace,'files':files,'after':snapshot(fixture)})
        production=manifest.parent/obj(manifest)['executable']
        transport_cases=[('empty',b'',[],0,b''),('short-length',bytes(7),[],74,b''),
          ('short-frame',struct.pack('<Q',64)+bytes(10),[],74,b''),
          ('over-capacity',struct.pack('<Q',(512<<20)+1),[],3,struct.pack('<I',0xfffffffe)),
          ('empty-frame',struct.pack('<Q',0),[],0,struct.pack('<I',0xffffffff)),
          ('bad-frame',stream([bytes(64)]),[],0,struct.pack('<I',0xffffffff)),
          ('extra-argument',b'',['unexpected'],64,b''),
          ('invalid-recovery',stream([bytes(64),frame(b'target',b'after')]),[],0,
             struct.pack('<I',0xffffffff)+struct.pack('<I8s3Q',32,b'HRAWR001',0,0,0))]
        for name,request,args,code,wanted in transport_cases:
            entry=destination/('transport-'+name);entry.mkdir();fixture=entry/'fixture';fixture.mkdir()
            actual=subprocess.run([str(production),*args],cwd=fixture,input=request,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            for filename,raw in [('input.bin',request),('stdout.bin',actual.stdout),('stderr.bin',actual.stderr)]:write_new(entry/filename,raw)
            exact(actual.returncode,code,'native transport exit differs: '+name)
            exact(actual.stdout,wanted,'native transport output differs: '+name);exact(actual.stderr,b'','native transport stderr differs')
            if name=='invalid-recovery':exact((fixture/'target').read_bytes(),b'after','request after refusal did not complete')
            else:exact(list(fixture.iterdir()),[],'refused transport produced filesystem effects')
            result['transport_processes']+=1
            result['observations'].append({'transport':name,'exit_code':actual.returncode,
              'files':{n:file_record(entry/n) for n in ('input.bin','stdout.bin','stderr.bin')}})
        entry=destination/'parent-death';entry.mkdir();fixture=entry/'fixture';setup(fixture,make('death'))
        request=stream([frame(b'target',b'pending')])
        actual,trace,files=supervised(production,entry,request,{'kill_parent':{'kind':'write'}},fixture)
        death=trace['parent_death'];exact(actual.returncode,247,'owned parent death exit differs')
        exact(actual.stdout,b'','killed parent published an unowned result');exact(actual.stderr,b'','parent-death supervisor emitted an error')
        exact(trace['failure'],None,'parent-death supervisor failed');exact(death['exit_code'],-9,'worker survived parent death')
        exact(death['reaped'],True,'worker custody was not reclaimed');exact(death['blocked_effect_completed'],False,'held effect completed')
        exact((fixture/'target').read_bytes(),b'original','parent death changed the original')
        exact((fixture/'.octofs_tmp_target.tmp').read_bytes(),b'','held write unexpectedly completed')
        result['parent_death_processes']=1;result['observations'].append({'parent_death':trace,'after':snapshot(fixture),'files':files})
        exact(inspect_bundle(manifest),before,'production artifacts changed during boundary suite')
        exact(source_files,{p:file_record(ROOT/p) for p in SOURCE_FILES},'boundary source changed during execution');builder._recheck()
        result.update(status='PASS',actual_elf_processes=28,actual_contract_refusals=19,actual_owned_worker_deaths=1,
          production_activated=False,whole_runtime_replaced=False)
    except BaseException as error:
        result.update(status='FAIL',failure=repr(error));raise
    finally:
        result['elapsed']=time.monotonic()-started;(destination/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,default=os.environ.get('HIA_ATOMIC_MANIFEST'))
    p.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'));p.add_argument('--build-root',type=Path,default=os.environ.get('HIA_BUILD_ROOT'))
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not a.manifest or not a.hepta or not a.build_root:p.error('native manifest, compiler checkout and build root are required')
    result=run(a.manifest,a.hepta,a.build_root,a.output);print(json.dumps({k:v for k,v in result.items() if k!='observations'},sort_keys=True))
if __name__=='__main__':main()
