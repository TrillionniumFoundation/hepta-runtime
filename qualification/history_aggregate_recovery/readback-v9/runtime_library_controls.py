"""Pure byte/path controls for the two pinned external library reads."""
from __future__ import annotations
import copy,hashlib,json,sys,tempfile
from pathlib import Path
import runtime_library_reads as q
import read_only_guard as guard

NAMES=['changed-library-reader-source','changed-module-owner','changed-manifest-bytes',
 'changed-recorded-root','nonabsolute-library-path','wrong-library-basename',
 'host-library-symlink','retained-library-symlink','changed-current-library-byte',
 'changed-retained-library-byte','boolean-library-size','changed-retained-library-pin',
 'unlisted-external-file']

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def run(original_source):
    original_source=Path(original_source).absolute()
    originals={name:(original_source/name).read_bytes() for name in q.PINS}
    for name,(size,digest) in q.PINS.items():
        q.need(len(originals[name])==size and q.digest(originals[name])==digest,'exact library control source')
    with tempfile.TemporaryDirectory(prefix='history-library-controls-') as temporary:
        base=Path(temporary);source=base/'source';capture=base/'capture';host=base/'host'
        source.mkdir();capture.mkdir();host.mkdir()
        for name,raw in originals.items():
            path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        folder=capture/'build/shell-foreground';folder.mkdir(parents=True)
        foreign=base/'foreign';foreign.write_bytes(b'not an admitted runtime dependency')
        metadata={'recorded_directory':str(folder),'recorded_source_root':str(source)}
        artifacts={}
        for i,(role,filename,basename) in enumerate(q.ROLES):
            raw=(b'test-owned library complete body '+bytes([48+i])+b'\0')*3
            (host/basename).write_bytes(raw);(folder/filename).write_bytes(raw)
            pin={'size':len(raw),'sha256':q.digest(raw)}
            metadata[role]={'path':str(host/basename),'pin':pin}
            artifacts['build/shell-foreground/'+filename]=pin['sha256']
        report={'source_sha256':{name:q.digest(raw) for name,raw in originals.items()},
                'modules':{q.MODULE:{'builder':'shell_foreground','manifest':q.MANIFEST,
                    'source':q.OWNER,'sha256':''}},
                'shell_foreground_evidence':{'artifact_sha256':artifacts}}
        manifest=capture/q.MANIFEST
        def save(value,target):
            raw=encoded(value);manifest.write_bytes(raw)
            target['modules'][q.MODULE]['sha256']=q.digest(raw)
            target['shell_foreground_evidence']['artifact_sha256'][q.MANIFEST]=q.digest(raw)
        save(metadata,report)
        baseline={path:path.read_bytes() for path in [*source.rglob('*.py'),manifest,
          *host.iterdir(),*(folder/name for _,name,_ in q.ROLES)]}
        rows=[];admissions=[];attempts=[];active=[False]
        def audit(event,args):
            if active[0] and (event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn',
              'os.fork','os.forkpty','mmap.__new__'} or event.startswith('ctypes.')):
                attempts.append(event);raise PermissionError('library controls cannot load or execute code')
        sys.addaudithook(audit)
        def restore():
            for path,raw in baseline.items():
                if path.is_symlink():path.unlink()
                if not path.exists() or path.read_bytes()!=raw:path.write_bytes(raw)
        def controlled_guard(operation,**kwargs):
            # The complete guard must own its 12 refusal probes; the outer
            # no-execution hook protects only the unguarded fixture checks.
            previous=active[0];active[0]=False
            try:return guard.guarded(operation,**kwargs)
            finally:active[0]=previous
        def admission():
            binding=q.admit(source,capture,report)
            allowed=[Path(row['path']) for row in binding['files']]
            proof=controlled_guard(lambda:q.admit(source,capture,report),
                roots=[source,capture],external_files=allowed,foreign_path=foreign)
            q.need(proof['evidence']==binding and proof['before']==proof['after']
             and proof['external_before']==proof['external_after'] and len(proof['probes'])==12,
             'complete library guard admission and unchanged metadata')
            admissions.append({'binding':binding,'guard':proof})
        def refuses(label,call):
            try:call()
            except (ValueError,OSError,PermissionError,KeyError) as error:
                rows.append({'name':label,'exception':type(error).__name__,'message':str(error)})
            else:raise ValueError('library control admitted '+label)
            finally:restore()
        def change_bytes(path):
            raw=path.read_bytes();path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
            return q.admit(source,capture,report)
        def changed_report(change):
            value=copy.deepcopy(report);change(value);return q.admit(source,capture,value)
        def changed_metadata(change):
            value=copy.deepcopy(metadata);receipt=copy.deepcopy(report);change(value)
            save(value,receipt);return q.admit(source,capture,receipt)
        def alias(path,target):
            path.unlink();path.symlink_to(target);return q.admit(source,capture,report)
        active[0]=True
        try:
            admission()
            refuses(NAMES[0],lambda:change_bytes(source/next(iter(q.PINS))))
            refuses(NAMES[1],lambda:changed_report(lambda r:r['modules'][q.MODULE].update(source='native/other.hepta')))
            refuses(NAMES[2],lambda:change_bytes(manifest))
            refuses(NAMES[3],lambda:changed_metadata(lambda r:r.update(recorded_source_root=str(base))))
            refuses(NAMES[4],lambda:changed_metadata(lambda r:r['allocator'].update(path='libc.so.6')))
            refuses(NAMES[5],lambda:changed_metadata(lambda r:r['allocator'].update(path=str(foreign))))
            refuses(NAMES[6],lambda:alias(host/'libc.so.6',folder/'allocator-libc.so.6'))
            refuses(NAMES[7],lambda:alias(folder/'allocator-libc.so.6',host/'libc.so.6'))
            refuses(NAMES[8],lambda:change_bytes(host/'libc.so.6'))
            refuses(NAMES[9],lambda:change_bytes(folder/'allocator-libc.so.6'))
            refuses(NAMES[10],lambda:changed_metadata(lambda r:r['allocator']['pin'].update(size=True)))
            refuses(NAMES[11],lambda:changed_report(lambda r:r['shell_foreground_evidence']['artifact_sha256'].update(
                {'build/shell-foreground/allocator-libc.so.6':'0'*64})))
            binding=q.admit(source,capture,report)
            refuses(NAMES[12],lambda:controlled_guard(lambda:foreign.read_bytes(),
                roots=[source,capture],external_files=[Path(row['path']) for row in binding['files']],
                foreign_path=foreign))
            admission()
        finally:active[0]=False;restore()
        q.need([row['name'] for row in rows]==NAMES and len(admissions)==2 and not attempts,
             'complete library admissions/refusals and no execution')
        q.need(all(path.read_bytes()==raw for path,raw in baseline.items()),'all control fixture bytes restored')
        q.need({name:(original_source/name).read_bytes() for name in originals}==originals,
             'original source files unchanged')
        return {'schema':'hepta.history.runtime-library-controls.v1','status':'PASS',
                'refusals':rows,'admissions':admissions,'complete_admissions':2,
                'test_owned_library_bytes_not_executed':True,'complete_library_files_per_admission':2,
                'native_or_rust_executions':0,'library_loads':0,'execution_attempts':attempts}
