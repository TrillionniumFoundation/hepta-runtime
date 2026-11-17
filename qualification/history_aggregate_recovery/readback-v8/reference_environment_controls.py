"""Physical controls for exact original shell-reference dependency admission."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,stat,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import reference_environment_reads as m
import read_only_guard as guard

NAMES=['changed-bound-reference-source','changed-reference-report-bytes',
 'mismatched-reference-report-dual-pin','unexpected-tool-role','changed-fixed-sysroot',
 'missing-original-target-library','extra-current-target-library','aliased-target-library',
 'changed-current-library','changed-retained-loader-cache','conflicting-external-identity',
 'boolean-dependency-size','wrong-original-loader-cache-path','unexpected-preload-file',
 'changed-current-dependency-mode','unlisted-external-file']
def need(value,label):
    if not value:raise ValueError(label)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def write(path,raw,mode=0o600):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    path.write_bytes(raw);path.chmod(mode)
def fixture(base,actual_source):
    source=base/'source';output=base/'capture';env=base/'environment'
    source.mkdir();output.mkdir();env.mkdir()
    original={'source_sha256':{},'original_rust_comparisons':{}}
    for name,(size,digest) in m.SOURCES.items():
        raw=(actual_source/name).read_bytes()
        need(pin(raw)=={'bytes':size,'sha256':digest},'test must use exact original complete reader sources')
        write(source/name,raw);original['source_sha256'][name]=digest
    sysroot=env/'toolchain';rustc=sysroot/'bin/rustc'
    write(rustc,b'CONTROL RUSTC BYTES, NEVER EXECUTE',0o700)
    linker=env/'bin/linker';ld=env/'bin/ld'
    write(linker,b'CONTROL GCC BYTES, NEVER EXECUTE',0o700)
    write(ld,b'CONTROL LD BYTES, NEVER EXECUTE',0o700)
    libraries={}
    for name,raw,mode in [('libc.so.6',b'COMPLETE TEST OWNED LIBC',0o700),
                           ('libgcc_s.so.1',b'COMPLETE TEST OWNED LIBGCC',0o600),
                           ('ld-linux-x86-64.so.2',b'COMPLETE TEST OWNED INTERPRETER',0o700)]:
        path=env/'lib'/name;write(path,raw,mode);libraries[name]=path
    interpreter=libraries['ld-linux-x86-64.so.2'];alias=env/'bin/interpreter'
    alias.symlink_to(interpreter)
    cache=env/'ld.so.cache';preload=env/'ld.so.preload';write(cache,b'COMPLETE TEST OWNED LOADER CACHE')
    libdir=sysroot/'lib/rustlib'/m.TARGET/'lib'
    write(libdir/'libstd-test.rlib',b'COMPLETE TEST OWNED RLIB')
    write(libdir/'self-contained/test.o',b'COMPLETE TEST OWNED OBJECT')
    def identity(path,mode=False):
        resolved=path.resolve();row={'launch_path':str(path),'resolved_path':str(resolved),**pin(resolved.read_bytes())}
        if mode:row['mode']=stat.S_IMODE(resolved.stat().st_mode)
        return row
    targets={'path':str(libdir),'files':{p.relative_to(libdir).as_posix():pin(p.read_bytes())
        for p in libdir.rglob('*') if p.is_file()},'file_count':2}
    reports={}
    for key in m.KEYS:
        folder=key.replace('_','-')+'-original/build';reportpath=folder+'/result.json'
        tools={'rustc':identity(rustc),'linker':identity(linker),'ld':identity(ld)}
        report={'status':'PASS','error':None,'sysroot':str(sysroot),'tools':tools,'target_libraries':targets}
        retained={}
        reference={}
        if key!='shell_capture_path':
            tools['interpreter']=identity(alias)
            rows=[]
            for i,(name,path) in enumerate(libraries.items()):
                rel=f'dynamic-libraries/{i:02d}-{name}.bin';raw=path.read_bytes();write(output/folder/rel,raw)
                retained[folder+'/'+rel]=pin(raw)['sha256']
                rows.append({'listing':{'name':name,'path':str(path)},
                    'file':identity(path,True),'retained':{'path':rel,**pin(raw)}})
            raw=cache.read_bytes();rel=folder+'/loader-configuration/ld.so.cache';write(output/rel,raw)
            retained[rel]=pin(raw)['sha256']
            dynamic={'interpreter':identity(alias,True),'configuration':{'cache':identity(cache,True),'preload':{'present':False}},
                'libraries':rows,'library_count':3}
            report['dynamic_binding']=dynamic;reference['dynamic_binding']=dynamic
        raw=encoded(report);write(output/reportpath,raw);retained[reportpath]=pin(raw)['sha256']
        reference['report_sha256']=pin(raw)['sha256']
        original['original_rust_comparisons'][key]={'reference_build':reference,'retained_files_sha256':retained}
        reports[key]=report
    write(base/'foreign',b'UNLISTED')
    return {'base':base,'source':source,'output':output,'env':env,'sysroot':sysroot,
        'cache':cache,'preload':preload,'original':original,'reports':reports,'libdir':libdir,
        'libraries':libraries,'linker':linker}
def repin(f,key):
    rel=key.replace('_','-')+'-original/build/result.json';raw=encoded(f['reports'][key])
    (f['output']/rel).write_bytes(raw)
    row=f['original']['original_rust_comparisons'][key];digest=pin(raw)['sha256']
    row['reference_build']['report_sha256']=digest;row['retained_files_sha256'][rel]=digest
def using(f,operation):
    old=m.SYSROOT,m.CACHE,m.PRELOAD
    m.SYSROOT,m.CACHE,m.PRELOAD=f['sysroot'],f['cache'],f['preload']
    try:return operation()
    finally:m.SYSROOT,m.CACHE,m.PRELOAD=old
def admission(f):
    return using(f,lambda:m.admit(f['source'],f['output'],f['original']))
def mutate(f,name):
    key='shell_capture_file';report=f['reports'][key]
    rel=key.replace('_','-')+'-original/build/result.json'
    if name=='changed-bound-reference-source':
        p=f['source']/next(iter(m.SOURCES));p.write_bytes(p.read_bytes()+b'\n')
    elif name=='changed-reference-report-bytes':(f['output']/rel).write_bytes(b'{}')
    elif name=='mismatched-reference-report-dual-pin':
        f['original']['original_rust_comparisons'][key]['reference_build']['report_sha256']='0'*64
    elif name=='unexpected-tool-role':
        report['tools']['extra']=dict(report['tools']['ld']);repin(f,key)
    elif name=='changed-fixed-sysroot':report['sysroot']=str(f['env']);repin(f,key)
    elif name=='missing-original-target-library':
        report['target_libraries']['files'].pop('self-contained/test.o');report['target_libraries']['file_count']=1;repin(f,key)
    elif name=='extra-current-target-library':write(f['libdir']/'extra.o',b'EXTRA')
    elif name=='aliased-target-library':
        p=f['libdir']/'self-contained/test.o';p.unlink();p.symlink_to(f['libdir']/'libstd-test.rlib')
    elif name=='changed-current-library':
        p=f['libraries']['libc.so.6'];p.write_bytes(p.read_bytes()+b'!')
    elif name=='changed-retained-loader-cache':
        p=f['output']/(key.replace('_','-')+'-original/build/loader-configuration/ld.so.cache')
        p.write_bytes(p.read_bytes()+b'!')
    elif name=='conflicting-external-identity':
        report['tools']['ld']['sha256']='0'*64;repin(f,key)
    elif name=='boolean-dependency-size':
        report['tools']['linker']['bytes']=True;repin(f,key)
    elif name=='wrong-original-loader-cache-path':
        report['dynamic_binding']['configuration']['cache']['launch_path']=str(f['linker']);repin(f,key)
    elif name=='unexpected-preload-file':write(f['preload'],b'')
    elif name=='changed-current-dependency-mode':f['libraries']['libgcc_s.so.1'].chmod(0o700)
    else:raise ValueError('unknown physical mutation')
def run(actual_source):
    started=time.monotonic_ns();admissions=[];refusals=[]
    with tempfile.TemporaryDirectory(prefix='history-reference-environment-controls-') as root:
        root=Path(root)
        for i in range(2):
            base=root/f'admission-{i}';base.mkdir();f=fixture(base,actual_source)
            binding=admission(f)
            g=using(f,lambda:guard.guarded(lambda:m.admit(f['source'],f['output'],f['original']),
                  roots=[f['source'],f['output']],foreign_path=base/'foreign',
                  external_files=[Path(p) for p in binding['external_files']]))
            need(g['evidence']==binding,'guarded exact dependency admission changed')
            admissions.append({'binding':binding,'guard':g})
        for name in NAMES:
            base=root/name;base.mkdir();f=fixture(base,actual_source)
            try:
                if name=='unlisted-external-file':
                    binding=admission(f)
                    using(f,lambda:guard.guarded(lambda:(base/'foreign').read_bytes(),
                       roots=[f['source'],f['output']],foreign_path=base/'foreign',
                       external_files=[Path(p) for p in binding['external_files']]))
                else:mutate(f,name);admission(f)
            except (ValueError,PermissionError) as error:
                refusals.append({'name':name,'exception':type(error).__name__,'message':str(error)})
            else:raise ValueError('exact environment control was admitted: '+name)
    return {'schema':'hepta.history.reference-environment-controls.v1','status':'PASS',
        'complete_admissions':2,'complete_reference_reports_per_admission':4,
        'admissions':admissions,'refusals':refusals,'elapsed_ns':time.monotonic_ns()-started,
        'test_owned_dependency_bytes_not_executed':True,'library_loads':0,'native_or_rust_executions':0}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=run(a.source)
    with a.output.open('xb') as f:f.write(encoded(result))
    print(json.dumps({'status':result['status'],'complete_admissions':2,'refusals':len(result['refusals']),
        'elapsed_ns':result['elapsed_ns'],'native_or_rust_executions':0},sort_keys=True))
