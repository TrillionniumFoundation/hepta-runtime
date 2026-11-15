"""Retain Batch's owned effect trees before transport and exact-origin replay.

Unreadable private fixture files are opened through a pinned inode after a
temporary owner-read grant. Their original mode is restored before retirement;
the actual permission changes are recorded and are not business invocations.
Pure readers inspect the complete archives and never reconstruct a live path.
"""
from contextlib import contextmanager
import gzip,hashlib,json,os,stat,time,traceback
from pathlib import Path
import hia_native_runtime_mcp_fixtures as archive

NATIVE=tuple('batch-call/output-'+part+'/files' for part in ('small','wide','async'))
ASYNC=('batch-call/async-controls/files',)
PROFILES={'native':(NATIVE,'batch-call/native-fixtures'),'async':(ASYNC,'batch-call/async-fixtures')}
RESTORE='batch-call/fixture-reconstruction.json'
need,exact=archive.require,archive.exact
canonical=archive.encoded
def sha(raw):return hashlib.sha256(raw).hexdigest()
def object_at(output,name):
    value=archive.decode(archive.artifact(output,name).read_bytes());canonical(value);return value
def identity(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink]

@contextmanager
def readable(output,roots,journal):
    output=archive.root_path(output);held={};started=time.monotonic_ns();failure=None
    try:
        for root in roots:
            for parent,dirs,files in os.walk(output/root,followlinks=False):
                for name in sorted(files):
                    path=Path(parent)/name;info=path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_mode&stat.S_IRUSR:continue
                    need(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)<=0o777,'unowned unreadable Batch fixture')
                    key=(info.st_dev,info.st_ino)
                    if key in held:continue
                    relative=os.fsencode(path.relative_to(output))
                    with archive.parent_fd(output,relative) as (parent_fd,leaf):
                        fd=os.open(leaf,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd)
                    exact(identity(os.fstat(fd)),identity(info),'unreadable fixture inode changed before grant')
                    row={'path_hex':relative.hex(),'source_device':info.st_dev,'source_inode':info.st_ino,
                         'original_mode':stat.S_IMODE(info.st_mode),'readable_mode':stat.S_IMODE(info.st_mode)|0o400,
                         'ctime_before_ns':info.st_ctime_ns,'restored':False}
                    held[key]=(fd,row)
                    os.chmod('/proc/self/fd/'+str(fd),row['readable_mode'])
                    exact(stat.S_IMODE(os.fstat(fd).st_mode),row['readable_mode'],'actual private owner-read grant')
        yield {key:row for key,(_,row) in held.items()}
    except BaseException:
        failure=traceback.format_exc();raise
    finally:
        try:
            for fd,row in held.values():
                os.chmod('/proc/self/fd/'+str(fd),row['original_mode'])
                info=os.fstat(fd)
                exact([info.st_dev,info.st_ino,stat.S_IMODE(info.st_mode)],
                      [row['source_device'],row['source_inode'],row['original_mode']],
                      'same private inode restored to its actual mode')
                row.update(restored=True,restored_mode=stat.S_IMODE(info.st_mode),ctime_after_ns=info.st_ctime_ns)
        finally:
            for fd,_ in held.values():os.close(fd)
            value={'schema':'hepta.runtime.batch-fixture-read-permissions.v1','pid':os.getpid(),
                   'cwd':os.getcwd(),'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),
                   'fixture_directories':list(roots),'changes':[row for _,row in held.values()],
                   'new_native_calls':0,'new_original_processes':0,'error':failure}
            archive.dump_new(output,journal,value)

def original_modes(entries,grants):
    for row in entries:
        change=grants.get((row['source_device'],row['source_inode']))
        if change is not None:
            exact(row['mode'],change['readable_mode'],'temporary fixture permission snapshot')
            row['mode']=change['original_mode']
    return entries

def capture(output,roots,prefix):
    name=prefix+'.bin.gz';journal=prefix+'.permissions.json'
    with readable(output,roots,journal) as grants:
        entries=original_modes(archive.snapshot(output,roots),grants)
        archive.validate_entries(entries,roots)
        archive.create_archive(output,roots,entries,name)
        pin=archive.file_pin(archive.artifact(output,name))
        counts=archive.read_archive(output,entries,roots,name,pin)
        exact(original_modes(archive.snapshot(output,roots),grants),entries,'complete Batch tree changed during archival')
    return entries,pin,counts

def permission_evidence(output,name,roots,entries):
    value=object_at(output,name)
    need(set(value)=={'schema','pid','cwd','started_monotonic_ns','finished_monotonic_ns','fixture_directories',
                     'changes','new_native_calls','new_original_processes','error'},'complete private permission journal')
    exact([value['schema'],value['fixture_directories'],value['new_native_calls'],value['new_original_processes'],value['error']],
          ['hepta.runtime.batch-fixture-read-permissions.v1',list(roots),0,0,None],'private read permission scope')
    need(type(value['pid'])is int and value['pid']>0 and Path(value['cwd']).is_absolute(),'actual permission observer identity')
    begin,end=value['started_monotonic_ns'],value['finished_monotonic_ns']
    need(type(begin)is type(end)is int and 0<begin<end,'actual permission journal clocks')
    table={row['path_hex']:row for row in entries};seen=set()
    for change in value['changes']:
        exact(sorted(change),sorted(('path_hex','source_device','source_inode','original_mode','readable_mode',
              'ctime_before_ns','restored','restored_mode','ctime_after_ns')),'complete actual permission grant fields')
        row=table[change['path_hex']];key=(row['source_device'],row['source_inode'])
        need(key not in seen and row['kind']=='file','duplicate or non-file permission grant');seen.add(key)
        exact([change['source_device'],change['source_inode'],change['original_mode'],change['restored_mode']],
              [*key,row['mode'],row['mode']],'same private inode and original restored permission')
        need(change['restored']is True and row['mode']&0o400==0,'unrestored or unnecessary permission change')
        exact(change['readable_mode'],row['mode']|0o400,'only owner-read permission was added')
        need(type(change['ctime_before_ns'])is type(change['ctime_after_ns'])is int and
             0<change['ctime_before_ns']<=change['ctime_after_ns'],'recorded actual fixture metadata change')
    expected={(row['source_device'],row['source_inode'])for row in entries
              if row['kind']=='file'and row['mode']&0o400==0}
    exact(sorted(seen),sorted(expected),'every unreadable private file inode has its actual restored grant')
    return value

def latest_native_trees(output,profile):
    trees={}
    if profile=='native':
        for part in ('small','wide','async'):
            folder='batch-call/output-'+part
            for line in archive.artifact(output,folder+'/native-cases.jsonl').read_bytes().splitlines():
                row=json.loads(line);tree=row['after']['tree']
                if row['cancel'] is not None:tree=row['cancel']['followup']['after']['tree']
                trees[tree['root_hex']]=(folder,tree)
    else:
        for row in object_at(output,'batch-call/async-controls/CONTROLS.json'):
            tree=row['after_late'];trees[tree['root_hex']]=('batch-call/async-controls',tree)
    return trees

def validate_native_entries(output,profile,entries,origin):
    roots,_=PROFILES[profile];archive.validate_entries(entries,roots)
    table={bytes.fromhex(row['path_hex']):row for row in entries};seen={root.encode() for root in roots}
    for folder,tree in latest_native_trees(output,profile).values():
        raw_root=bytes.fromhex(tree['root_hex']);prefix=os.fsencode(origin)+b'/'
        need(raw_root.startswith(prefix),'captured Batch fixture escaped actual output')
        relative=raw_root[len(prefix):]
        for node in tree['nodes']:
            suffix=bytes.fromhex(node['relative_hex']);name=relative+(b'/'+suffix if suffix else b'')
            need(name in table,'last complete native snapshot missing from fixture archive');seen.add(name)
            entry=table[name];meta=node['metadata'];mode=meta['mode']
            kinds={stat.S_IFREG:'file',stat.S_IFDIR:'directory',stat.S_IFLNK:'symlink',stat.S_IFIFO:'fifo'}
            exact([entry['kind'],entry['mode'],entry['source_device'],entry['source_inode'],entry['nlink'],entry['uid'],entry['gid']],
                  [kinds[stat.S_IFMT(mode)],stat.S_IMODE(mode),meta['dev'],meta['ino'],meta['nlink'],meta['uid'],meta['gid']],
                  'all captured native inode, mode and hardlink relationships')
            if entry['kind']=='file':
                body=node['content'];need(body['ok']is True,'missing complete native fixture content')
                blob=body['blob'];raw=gzip.decompress(archive.artifact(output,folder+'/'+blob['artifact']).read_bytes())
                exact({'bytes':len(raw),'sha256':sha(raw)}, {key:blob[key]for key in ('bytes','sha256')},'full final native fixture blob')
                exact([entry['bytes'],entry['sha256']],[len(raw),sha(raw)],'archive equals last actual complete native bytes')
            elif entry['kind']=='symlink':exact(entry['target_hex'],node['target_hex'],'full native symbolic-link target')
    exact(sorted(path.hex()for path in table),sorted(path.hex()for path in seen),'complete final native fixture topology')

def retirement(output,binding,*,create=False):
    output=archive.root_path(output);origin=binding['execution_output_root'];result={};artifacts={}
    for profile,(roots,prefix) in PROFILES.items():
        receipt=prefix+'.json';archive_name=prefix+'.bin.gz';permissions=prefix+'.permissions.json'
        expected={'schema':'hepta.runtime.batch-call-fixture-retirement.v1','status':'PASS','profile':profile,
                  'execution_output_root':origin,'fixture_directories':list(roots),
                  'complete_native_evidence_sha256':sha(canonical(binding)),
                  'semantic_invocations_added':0,'source_inode_identifiers_are_provenance':True}
        if not (output/receipt).exists():
            need(create and str(output)==origin,'fixture retirement requires its actual native execution origin')
            entries,pin,counts=capture(output,roots,prefix)
            validate_native_entries(output,profile,entries,origin)
            permission_evidence(output,permissions,roots,entries)
            archive.remove_roots(output,roots,entries)
            archive.dump_new(output,receipt,dict(expected,entries=entries,archive=pin,
                             permissions=archive.file_pin(archive.artifact(output,permissions))))
        value=object_at(output,receipt)
        exact(sorted(value),sorted(set(expected)|{'entries','archive','permissions'}),'complete Batch retirement receipt fields')
        exact({key:value[key]for key in expected},expected,'retained native fixture evidence binding')
        validate_native_entries(output,profile,value['entries'],origin)
        exact(archive.file_pin(archive.artifact(output,permissions)),value['permissions'],'whole permission observer journal')
        permission_evidence(output,permissions,roots,value['entries'])
        counts=archive.read_archive(output,value['entries'],roots,archive_name,value['archive'])
        archive.absent(output,roots)
        result[profile]=dict(expected,**counts,archive=value['archive'],permissions=value['permissions'])
        for name in (receipt,archive_name,permissions):artifacts[name]=archive.file_pin(archive.artifact(output,name))['sha256']
    return {'schema':'hepta.runtime.batch-call-fixture-retirements.v1','status':'PASS',**result,
            'new_native_calls':0,'new_original_processes':0,'artifact_sha256':dict(sorted(artifacts.items()))}

def write_journal(output,state):
    temporary=output/(RESTORE+'.pending')
    need(not temporary.exists() and not temporary.is_symlink(),'unclaimed Batch reconstruction journal')
    with temporary.open('xb')as stream:stream.write(canonical(state));stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,output/RESTORE)

def reconstruction_evidence(output,binding,retired):
    output=archive.root_path(output);state=object_at(output,RESTORE);origin=binding['execution_output_root']
    exact([state['schema'],state['status'],state['execution_output_root'],state['source_retirement_sha256']],
          ['hepta.runtime.batch-call-fixture-reconstruction.v1','PASS',origin,sha(canonical(retired))],
          'actual original fixture reconstruction binding')
    need(state['source_inodes_recreated']is False and state['same_reconstructed_native_inodes_preserved']is True
         and state['original_fixture_retired']is True and state['error']is None,'complete actual original fixture retirement')
    source=object_at(output,'batch-call/native-fixtures.json')
    before=object_at(output,RESTORE+'.before.json')
    exact(archive.logical(before),archive.logical(source['entries']),'complete reconstructed native tree')
    permission_evidence(output,RESTORE+'.before.permissions.json',NATIVE,before)
    roots=tuple(state['retired_roots']);expected_roots=tuple(
        'batch-call/output-'+part+'/'+kind for part in ('small','wide','async')
        for kind in ('files.before-original-original','files.original-original'))
    exact(roots,expected_roots,'fixed actual original retired trees')
    capture_receipt=object_at(output,'batch-call/original-fixtures.json')
    exact(sorted(capture_receipt),sorted(('entries','archive','permissions')),'complete original fixture archive fields')
    entries=capture_receipt['entries'];archive.validate_entries(entries,roots)
    permission_evidence(output,'batch-call/original-fixtures.permissions.json',roots,entries)
    exact(archive.file_pin(archive.artifact(output,'batch-call/original-fixtures.permissions.json')),
          capture_receipt['permissions'],'whole original fixture permission journal')
    counts=archive.read_archive(output,entries,roots,'batch-call/original-fixtures.bin.gz',capture_receipt['archive'])
    original_events=[json.loads(line)for line in archive.artifact(output,'batch-call/original/fixture-renames.jsonl').read_bytes().splitlines()]
    need(len(original_events)==9,'complete original rename/create/retire events')
    table={bytes.fromhex(row['path_hex']):row for row in entries}
    native=[]
    for row in entries:
        path=bytes.fromhex(row['path_hex'])
        for part in ('small','wide','async'):
            prefix=('batch-call/output-'+part+'/files.before-original-original').encode()
            if path==prefix or path.startswith(prefix+b'/'):
                new=dict(row);new['path_hex']=path.replace(prefix,('batch-call/output-'+part+'/files').encode(),1).hex()
                if 'link_group'in new:
                    new['link_group']=bytes.fromhex(new['link_group']).replace(prefix,('batch-call/output-'+part+'/files').encode(),1).hex()
                native.append(new)
    exact(sorted(native,key=lambda row:row['path_hex']),before,'same reconstructed native inode tree after actual original replay')
    for index,part in enumerate(('small','wide','async')):
        for kind,event_key in [('files.before-original-original','native_fixture'),('files.original-original','identity')]:
            entry=table[('batch-call/output-'+part+'/'+kind).encode()];record=original_events[index*3+1][event_key]
            exact([entry['source_device'],entry['source_inode'],entry['mode'],entry['uid'],entry['gid']],
                  [record['dev'],record['ino'],stat.S_IMODE(record['mode']),record['uid'],record['gid']],
                  'actual original/native fixture inodes are tied to admitted process events')
    archive.absent(output,(*NATIVE,*roots))
    files=[RESTORE,RESTORE+'.before.json',RESTORE+'.before.permissions.json',
           'batch-call/original-fixtures.json','batch-call/original-fixtures.bin.gz','batch-call/original-fixtures.permissions.json']
    return {'schema':'hepta.runtime.batch-call-original-fixture-evidence.v1','status':'PASS',
            'execution_output_root':origin,'source_inodes_recreated':False,'same_reconstructed_native_inodes_preserved':True,
            'original_fixture_retired':True,**counts,
            'artifact_sha256':{name:archive.file_pin(archive.artifact(output,name))['sha256']for name in files}}

@contextmanager
def original_fixture(output,binding,admitted):
    output=archive.root_path(output);exact(str(output),binding['execution_output_root'],'original exact execution origin')
    exact(retirement(output,binding),admitted,'complete native archive before original reconstruction')
    need(not (output/RESTORE).exists() and not (output/RESTORE).is_symlink(),'Batch original fixture already attempted')
    archive.absent(output,NATIVE)
    receipt=object_at(output,'batch-call/native-fixtures.json');created=[]
    state={'schema':'hepta.runtime.batch-call-fixture-reconstruction.v1','status':'RUNNING',
           'execution_output_root':str(output),'source_retirement_sha256':sha(canonical(admitted)),
           'source_inodes_recreated':False,'same_reconstructed_native_inodes_preserved':False,
           'original_fixture_retired':False,'retired_roots':[],'error':None}
    write_journal(output,state)
    try:
        archive.populate(output,receipt['entries'],'batch-call/native-fixtures.bin.gz',receipt['archive'],created,roots=NATIVE)
        with readable(output,NATIVE,RESTORE+'.before.permissions.json')as grants:
            before=original_modes(archive.snapshot(output,NATIVE),grants)
        exact(archive.logical(before),archive.logical(receipt['entries']),'reconstructed complete native private tree')
        archive.dump_new(output,RESTORE+'.before.json',before)
        yield
        roots=tuple('batch-call/output-'+part+'/'+kind for part in ('small','wide','async')
                    for kind in ('files.before-original-original','files.original-original'))
        archive.absent(output,NATIVE)
        entries,pin,counts=capture(output,roots,'batch-call/original-fixtures')
        archive.dump_new(output,'batch-call/original-fixtures.json',{'entries':entries,'archive':pin,
            'permissions':archive.file_pin(archive.artifact(output,'batch-call/original-fixtures.permissions.json'))})
        archive.remove_roots(output,roots,entries)
        state.update(status='PASS',same_reconstructed_native_inodes_preserved=True,original_fixture_retired=True,
                     retired_roots=list(roots));write_journal(output,state)
        reconstruction_evidence(output,binding,admitted)
    except BaseException:
        state.update(status='FAIL',error=traceback.format_exc());write_journal(output,state);raise
