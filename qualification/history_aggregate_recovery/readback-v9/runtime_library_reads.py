"""Admit only the original shell manifest's two exact current library files.

The unmodified foreground reader continues its own allocator/interpreter and
complete ELF/build checks. This helper grants no directory prefix, translates
no path, returns no cached build summary and never loads either library.
"""
from __future__ import annotations
import hashlib,json,stat
from pathlib import Path

PINS={
 'scripts/hia_native_shell_foreground_build.py':(51691,'7c82a36902c7d4ae2f9649080a381416ef4679816a1ed3ec66c756a668a9d723'),
 'scripts/hia_native_shell_process_build.py':(29502,'f3e282104f02006d7d54e41fe120ee95ec6523e55aa23da6f47ab28f9d21c036')}
MODULE='shell_foreground'
MANIFEST='build/shell-foreground/manifest.json'
OWNER='native/shell_foreground_controller.hepta'
ROLES=(('allocator','allocator-libc.so.6','libc.so.6'),
       ('interpreter','interpreter.bin','ld-linux-x86-64.so.2'))

def need(value,label):
    if not value:raise ValueError(label)

def digest(raw):return hashlib.sha256(raw).hexdigest()

def identity(path):
    need(type(path)is Path or isinstance(path,Path),'library path type')
    need(path.is_absolute() and path.resolve(strict=True)==path and not path.is_symlink(),
         'non-aliased absolute library input')
    before=path.lstat()
    need(stat.S_ISREG(before.st_mode),'ordinary complete library input')
    raw=path.read_bytes()
    after=path.lstat()
    fields=lambda v:(v.st_mode,v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    need(fields(before)==fields(after) and len(raw)==before.st_size,'library changed during complete read')
    return {'mode':before.st_mode,'inode':before.st_ino,'device':before.st_dev,
            'bytes':len(raw),'mtime_ns':before.st_mtime_ns,'ctime_ns':before.st_ctime_ns,
            'sha256':digest(raw)},raw

def admit(source,output,report):
    source=Path(source).absolute();output=Path(output).absolute()
    need(source.resolve(strict=True)==source and output.resolve(strict=True)==output,
         'non-aliased original library roots')
    sources={}
    for name,(size,expected) in PINS.items():
        row,raw=identity(source/name)
        need(len(raw)==size and digest(raw)==expected,'exact unchanged library reader source: '+name)
        need(report['source_sha256'][name]==expected,'original report library source pin')
        sources[name]={'bytes':size,'sha256':expected}
    selected=report['modules'][MODULE]
    need(selected=={'builder':'shell_foreground','manifest':MANIFEST,
                    'sha256':selected['sha256'],'source':OWNER},'exact original foreground module row')
    manifest=output/MANIFEST;manifest_row,raw=identity(manifest)
    need(digest(raw)==selected['sha256'],'original foreground manifest SHA')
    metadata=json.loads(raw)
    need(metadata['recorded_directory']==str(manifest.parent)
         and metadata['recorded_source_root']==str(source),'original foreground absolute roots')
    artifacts=report['shell_foreground_evidence']['artifact_sha256']
    need(artifacts[MANIFEST]==selected['sha256'],'original report retained manifest binding')
    rows=[]
    for role,filename,basename in ROLES:
        descriptor=metadata[role]
        need(type(descriptor)is dict and set(descriptor)=={'path','pin'},'exact library descriptor fields')
        value=descriptor['path']
        need(type(value)is str and value==str(Path(value)) and Path(value).is_absolute(),
             'canonical absolute original library filename')
        path=Path(value)
        need(path.name==basename,'exact source-declared library basename')
        expected=descriptor['pin']
        need(type(expected)is dict and set(expected)=={'size','sha256'}
             and type(expected['size'])is int and expected['size']>0
             and type(expected['sha256'])is str and len(expected['sha256'])==64
             and all(c in '0123456789abcdef' for c in expected['sha256']),'exact library pin types')
        retained=manifest.parent/filename;retained_row,retained_raw=identity(retained)
        observed,raw=identity(path)
        need(raw==retained_raw and len(raw)==expected['size'] and digest(raw)==expected['sha256'],
             'complete current library differs from original retained bytes')
        relative=retained.relative_to(output).as_posix()
        need(artifacts[relative]==expected['sha256'],'original report retained library binding')
        rows.append({'role':role,'path':str(path),'retained_path':relative,'pin':expected,
                     'current_identity':observed,'retained_identity':retained_row})
    need(len(rows)==2 and rows[0]['path']!=rows[1]['path'],'two distinct exact external libraries')
    return {'schema':'hepta.history.runtime-library-admission.v1','status':'PASS',
            'source_files':sources,'source':str(source),'output':str(output),
            'manifest_path':MANIFEST,'manifest_identity':manifest_row,
            'files':rows,'current_files_read_completely':2,'retained_files_read_completely':2,
            'paths_rewritten':False,'library_loads':0,'native_or_rust_executions':0,
            'original_build_reader_modified':False}
