"""Exact retained shell-reference environment reads, without executing tools.

This observer adds only files already named and completely pinned by the four
original build reports. Original reference readers remain unchanged and still
perform their full provenance, ELF, standard-library and process validation.
No current path is replaced, no directory prefix is admitted, and no cached
qualification summary is returned.
"""
from __future__ import annotations
import hashlib,json,os,stat
from pathlib import Path

SOURCES={
 'scripts/hia_native_shell_capture_path_reference.py':(17202,'9e780c452c2430b1fe6e01d4494380a1f2d29609e97e79e4905fa2f4202e89c8'),
 'scripts/hia_native_shell_capture_file_reference.py':(33082,'034e3ffa8af009de87215c8f9ad7b0178f2507ed802cc81119e15ee4b6196621'),
 'scripts/hia_native_shell_capture_mkdir_reference.py':(30678,'c16a41acdd136c3fd37d9bf29dee81ebd04bcee8bff96af1dfbb6205d1958e5c'),
 'scripts/hia_native_shell_capture_prepare_reference.py':(35983,'8d2f2ac7735def1be5c4c163fed1e635b9421ffc05e9502762d51cb551b233c4'),
 'scripts/hia_native_shell_process_reference.py':(61723,'d825520f8edc3dafb01abe86426c3fa4cf476eeb0e6c2dd1f105c970261240cc')}
KEYS=('shell_capture_path','shell_capture_file','shell_capture_mkdir','shell_capture_prepare')
SYSROOT=Path('/home/runner/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
TARGET='x86_64-unknown-linux-gnu'
CACHE=Path('/etc/ld.so.cache')
PRELOAD=Path('/etc/ld.so.preload')

def need(value,label):
    if not value:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}
def meta(value):
    return {'mode':value.st_mode,'device':value.st_dev,'inode':value.st_ino,
            'bytes':value.st_size,'mtime_ns':value.st_mtime_ns,'ctime_ns':value.st_ctime_ns,
            'nlink':value.st_nlink}
def expected_pin(value):
    need(type(value)is dict and set(value)=={'bytes','sha256'} and type(value['bytes'])is int
         and value['bytes']>=0 and type(value['sha256'])is str and len(value['sha256'])==64
         and all(c in '0123456789abcdef' for c in value['sha256']),'exact dependency extent and hash types')
    return value
def relative(value):
    need(type(value)is str and value and not value.startswith('/') and '\\' not in value
         and all(p not in ('','.','..') for p in value.split('/')),'canonical relative dependency path')
    return value
def ordinary(path):
    path=Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path and not path.is_symlink(),
         'non-aliased retained dependency file')
    before=path.lstat();need(stat.S_ISREG(before.st_mode),'ordinary retained dependency file')
    raw=path.read_bytes();after=path.lstat()
    need(meta(before)==meta(after) and len(raw)==before.st_size,'complete dependency changed during read')
    return raw
def directory_files(root):
    root=Path(root)
    need(root.is_absolute() and root.resolve(strict=True)==root and stat.S_ISDIR(root.lstat().st_mode),
         'canonical target library directory')
    result=[]
    for folder,dirs,names in os.walk(root,followlinks=False):
        for name in dirs+names:
            p=Path(folder)/name;info=p.lstat()
            need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                 'target library contains alias or special file')
        for name in names:result.append((Path(folder)/name).relative_to(root).as_posix())
    return sorted(result)

def admit(source,output,original):
    source=Path(source).absolute();output=Path(output).absolute()
    need(source.resolve(strict=True)==source and output.resolve(strict=True)==output,
         'canonical original reference roots')
    sources={}
    for name,(size,digest) in SOURCES.items():
        raw=ordinary(source/name)
        need(pin(raw)=={'bytes':size,'sha256':digest} and original['source_sha256'][name]==digest,
             'complete unchanged reference reader source')
        sources[name]=pin(raw)
    claims={};retained=[];reports=[];absent=[]
    def claim(identity,role,*,executable=False):
        needed={'launch_path','resolved_path','bytes','sha256'}
        need(type(identity)is dict and set(identity) in (needed,needed|{'mode'}),
             'exact source-declared external identity fields')
        p=expected_pin({k:identity[k] for k in ('bytes','sha256')})
        logical=Path(identity['launch_path']);resolved=Path(identity['resolved_path'])
        need(type(identity['launch_path'])is str and type(identity['resolved_path'])is str
             and logical.is_absolute() and resolved.is_absolute()
             and str(logical)==identity['launch_path'] and str(resolved)==identity['resolved_path'],
             'canonical absolute dependency identity')
        if 'mode' in identity:
            need(type(identity['mode'])is int and 0<=identity['mode']<=0o7777,'exact dependency mode type')
        for path in (str(logical),str(resolved)):
            item={'path':path,'resolved_path':str(resolved),'pin':p,
                  'mode':identity.get('mode'),'executable':bool(executable)}
            previous=claims.get(path)
            if previous is not None:
                need(previous['resolved_path']==item['resolved_path'] and previous['pin']==p,
                     'one external path has conflicting complete original bytes')
                if previous['mode'] is not None and item['mode'] is not None:
                    need(previous['mode']==item['mode'],'one external path has conflicting mode')
                if item['mode'] is None:item['mode']=previous['mode']
                item['executable']|=previous['executable']
                item['roles']=previous['roles']+[role]
            else:item['roles']=[role]
            claims[path]=item
    for key in KEYS:
        comparison=original['original_rust_comparisons'][key]
        folder=key.replace('_','-')+'-original/build'
        name=folder+'/result.json'
        raw=ordinary(output/name);digest=sha(raw)
        need(digest==comparison['reference_build']['report_sha256']
             and comparison['retained_files_sha256'][name]==digest,
             'original retained reference report dual binding')
        report=json.loads(raw)
        need(report['status']=='PASS' and report['error'] is None,
             'retained reference build was not completed')
        tools=report['tools']
        names={'rustc','linker','ld'}|({'interpreter'} if key!='shell_capture_path' else set())
        need(type(tools)is dict and set(tools)==names,'complete fixed original tool roles')
        need(report['sysroot']==str(SYSROOT)
             and tools['rustc']['resolved_path']==str(SYSROOT/'bin/rustc'),
             'fixed original Rust 1.95 sysroot')
        for role,identity in sorted(tools.items()):claim(identity,key+':'+role,executable=True)
        libs=report['target_libraries'];libdir=SYSROOT/'lib/rustlib'/TARGET/'lib'
        need(type(libs)is dict and set(libs)=={'path','files','file_count'} and libs['path']==str(libdir)
             and type(libs['files'])is dict and type(libs['file_count'])is int
             and libs['file_count']==len(libs['files'])>0,
             'complete fixed original target library set')
        need(sorted(libs['files'])==directory_files(libdir)
             and any(n.startswith('libstd-') and n.endswith('.rlib') for n in libs['files']),
             'current target library set differs from original full set')
        for rel,p in sorted(libs['files'].items()):
            relative(rel);expected_pin(p);path=str(libdir/rel)
            claim({'launch_path':path,'resolved_path':path,**p},key+':target-library')
        item={'key':key,'path':name,'pin':pin(raw),'tools':tools,'target_libraries':libs}
        if key!='shell_capture_path':
            dynamic=report['dynamic_binding']
            need(dynamic==comparison['reference_build']['dynamic_binding'],
                 'original reference complete dynamic binding')
            claim(dynamic['interpreter'],key+':dynamic-interpreter',executable=True)
            configuration=dynamic['configuration']
            need(type(configuration)is dict and set(configuration)=={'cache','preload'}
                 and configuration['cache']['launch_path']==str(CACHE),
                 'exact original loader configuration roles')
            claim(configuration['cache'],key+':loader-cache')
            cache_relative=folder+'/loader-configuration/ld.so.cache'
            retained.append((str(CACHE),cache_relative,comparison['retained_files_sha256'][cache_relative]))
            preload=configuration['preload']
            need(type(preload)is dict and type(preload.get('present'))is bool,
                 'exact original preload presence')
            if preload['present']:
                need(set(preload)=={'present','file'} and preload['file']['launch_path']==str(PRELOAD),
                     'exact original preload file')
                claim(preload['file'],key+':loader-preload')
                rel=folder+'/loader-configuration/ld.so.preload'
                retained.append((str(PRELOAD),rel,comparison['retained_files_sha256'][rel]))
            else:
                need(set(preload)=={'present'} and not os.path.lexists(PRELOAD),
                     'original absent preload configuration changed')
                absent.append(str(PRELOAD))
            need(type(dynamic['libraries'])is list and type(dynamic['library_count'])is int
                 and len(dynamic['libraries'])==dynamic['library_count']>0,
                 'complete original dynamic library rows')
            for row in dynamic['libraries']:
                identity=row['file'];claim(identity,key+':dynamic-library')
                rel=folder+'/'+relative(row['retained']['path'])
                need({k:identity[k] for k in ('bytes','sha256')}==
                     {k:row['retained'][k] for k in ('bytes','sha256')},
                     'original retained/current dynamic library binding')
                retained.append((identity['launch_path'],rel,comparison['retained_files_sha256'][rel]))
            item['dynamic_binding']=dynamic
        reports.append(item)
    files=[];contents={};retained_current_paths={row[0] for row in retained}
    for path,row in sorted(claims.items()):
        logical=Path(path);resolved=logical.resolve(strict=True)
        need(str(resolved)==row['resolved_path'],'current external dependency resolution changed')
        before=logical.lstat();target=resolved.lstat()
        need(stat.S_ISREG(target.st_mode),'current dependency is not a regular target')
        raw=ordinary(resolved)
        need(pin(raw)==row['pin'] and meta(logical.lstat())==meta(before)
             and meta(resolved.lstat())==meta(target),'complete current dependency differs from original')
        if row['mode'] is not None:
            need(stat.S_IMODE(target.st_mode)==row['mode'],'current dependency mode changed')
        need(not row['executable'] or os.access(resolved,os.X_OK),'original executable dependency mode')
        if path in retained_current_paths:contents[path]=raw
        files.append({**row,'logical':meta(before),'target':meta(target)})
    retained_rows=[]
    for path,rel,digest in retained:
        raw=ordinary(output/rel)
        need(raw==contents[path] and sha(raw)==digest,'complete current/retained original library differs')
        retained_rows.append({'path':rel,'current_path':path,'pin':pin(raw)})
    return {'schema':'hepta.history.reference-environment-admission.v1','status':'PASS',
        'source':str(source),'output':str(output),'source_files':sources,'reports':reports,
        'files':files,'external_files':[row['path'] for row in files],'retained_files':retained_rows,
        'absent_paths':sorted(set(absent)),'paths_rewritten':False,'library_loads':0,
        'native_or_rust_executions':0,'original_reference_readers_modified':False,
        'qualification_summary_cached':False}
