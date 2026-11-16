"""Re-read all public configuration exchanges without executing the graph."""
from pathlib import Path,PurePosixPath
import gzip,json,math,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import public_domain as d
import public_common as shared
pin=shared.pin

def number(value,limit):
    assert type(value) in (int,float) and math.isfinite(value) and 0<=value<=limit

def fixture_before(rows,flags,old_root):
    by={row['path']:row for row in rows};assert len(by)==len(rows)
    expected={'.','workspace'} if not flags else {'.','profile-'+str(flags>>1)}
    if flags:
        prefix='profile-'+str(flags>>1)
        expected|={prefix+'/'+x for x in ('install','input','weight','hia-state','install/worker.py','config.json')}
    assert set(by)==expected
    for name,row in by.items():
        regular=name.endswith(('/worker.py','/config.json'))
        assert stat.S_ISREG(row['mode']) if regular else stat.S_ISDIR(row['mode'])
        assert stat.S_IMODE(row['mode'])==(0o600 if regular else 0o700)
    if not flags:return
    root=old_root+'/profile-'+str(flags>>1)
    marker=b"raise SystemExit('catalog configuration fixture; never dispatched')\n"
    worker=root+'/install/worker.py'
    host={'ssh_target':'catalog-metadata.invalid','remote_state_dir':root+'/remote-state',
        'allow_execute':True,'allow_write':True,'allowed_cwd_prefixes':[root],
        'allowed_read_path_prefixes':[root],'allowed_write_path_prefixes':[root]}
    config={'state_dir':root+'/controller','controller_workspace_roots':[root],'hosts':{'catalog':host}}
    bits=flags>>1
    if bits&1:
        config['hia_worker']={'host':'catalog','python_executable':worker,'working_directory':root+'/install',
            'state_root':root+'/hia-state','artifact_roots':[root+'/input'],'worker_sha256':pin(marker)['sha256'],
            'backend_sha256':pin(marker)['sha256'],'catalog_sha256':d.HIA_CATALOG_SHA256}
    if bits&2:
        config['rea_static_profiles']={'catalog':{'host':'catalog','runtime_executable':worker,
            'runtime_sha256':pin(marker)['sha256'],'provider':'gnu_readelf','backend_executable':worker,
            'backend_sha256':pin(marker)['sha256'],'backend_version':'GNU readelf catalog-fixture',
            'working_directory':root+'/install','input_roots':[root+'/input'],'allowed_operations':['headers']}}
    if bits&4:
        config['weight_workers']={'catalog':{'host':'catalog','python_executable':worker,'worker_path':worker,
            'worker_sha256':pin(marker)['sha256'],'session_root':root+'/weight','input_roots':[root+'/input'],
            'allowed_providers':['catalog_fixture']}}
    assert bytes.fromhex(by[prefix+'/install/worker.py']['content_hex'])==marker
    assert json.loads(bytes.fromhex(by[prefix+'/config.json']['content_hex']))==config

def snapshot_check(rows,reader,prefix,physical):
    assert rows and rows[0]['path']=='.'
    names=[]
    for row in rows:
        name=row['path'];assert type(name)is str and name not in names
        assert name=='.' or (not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts)
        names.append(name)
        for key in ('mode','dev','ino','uid','gid','nlink','mtime_ns','ctime_ns'):
            assert type(row[key])is int and row[key]>=0
        path=reader.root/prefix/name
        if stat.S_ISREG(row['mode']):
            assert set(row)=={'path','mode','dev','ino','uid','gid','nlink','mtime_ns','ctime_ns','bytes','sha256','content_hex'}
            raw=bytes.fromhex(row['content_hex']);assert pin(raw)=={k:row[k] for k in ('bytes','sha256')}
            if physical:assert reader.raw(prefix+'/'+name)==raw
        else:
            assert stat.S_ISDIR(row['mode'])
            assert set(row)=={'path','mode','dev','ino','uid','gid','nlink','mtime_ns','ctime_ns'}
        if physical:
            st=path.lstat();assert not path.is_symlink() and st.st_mode==row['mode']
    if physical:
        actual={'.'}|{p.relative_to(reader.root/prefix).as_posix() for p in (reader.root/prefix).rglob('*')}
        assert actual==set(names)

def verify(source,component,graph,manifest,output,expected_binary=None):
    profile,binding=shared.source_check(source,component,graph)
    sys.path.insert(0,str(component));import configured_common as c
    c.source_check(component)
    r=c.BASE.Reader(output);md=json.loads(manifest.read_bytes());binary=manifest.parent/md['elf']
    binary_pin=pin(binary.read_bytes())
    assert md['status']=='PASS' and md['physical_images']==102 and md['catalog_installed_capability_mask']==1
    assert binary_pin=={'bytes':md['elf_bytes'],'sha256':md['elf_sha256']}
    if expected_binary is not None:assert binary_pin==expected_binary
    assert md['source_binding']=={'manifest_sha256':shared.GRAPH_PROFILE,'files':binding['sources']}
    assert md['catalog_config_presence_child']==6 and md['catalog_config_presence_operation']==3 and md['catalog_config_presence_phase']==18
    assert r.document('DOMAIN.json')==d.domain()
    assert r.document('binary-before.json')==binary_pin
    report=r.document('result.json')
    assert report['schema']=='hepta.runtime.configured-catalog-public-native.v1'
    assert report['status']=='ACTUAL_COMPLETE_PUBLIC_CATALOG_NATIVE_CAPTURE'
    assert report['source_profile']==pin((source/'public-source-profile.json').read_bytes())
    assert report['manifest']==pin(manifest.read_bytes()) and report['binary']==binary_pin
    assert report['source_binding']==md['source_binding']
    for k in ('pid','parent_pid','pgid'):assert type(report[k])is int and report[k]>0
    assert report['pid']==report['pgid']
    assert type(report['native_deadline_seconds'])is int and report['native_deadline_seconds']==180
    assert type(report['elapsed_ns'])is int and 0<report['elapsed_ns']<=180_000_000_000
    for key in ('fresh_original_comparison','public_all_configuration_qualified','whole_runtime_replaced'):assert report[key] is False
    assert type(report['tool_body_executions'])is int and report['tool_body_executions']==0
    assert len(report['processes'])==9 and len(report['observed'])==216
    rows=d.rows();pids=[];observed=[]
    for index,flags in enumerate(d.FLAGS):
        prefix=f'profile-{index}';folder=prefix+'/process';items=[row for row in rows if row['profile_index']==index]
        receipt=r.document(folder+'/capture-process.json');identity=r.document(prefix+'/process-identity.json')
        assert report['processes'][index]=={'profile_index':index,'flags':flags,'process':receipt,'identity':identity}
        assert identity['profile_index']==index and identity['flags']==flags and identity['binary']==binary_pin
        assert type(identity['pid'])is int and identity['pid']>0 and identity['pid'] not in pids
        pids.append(identity['pid']);assert identity['parent_pid']==report['pid'] and identity['pgid']==report['pgid']
        assert receipt['exit_code']==0 and type(receipt['exit_code'])is int
        assert receipt['timed_out'] is False and receipt['failure_cleanup_requested'] is False
        assert type(receipt['timeout_seconds'])is int and receipt['timeout_seconds']==60
        number(receipt['elapsed_seconds'],180)
        assert receipt['unconsumed_stdout_bytes']==0 and receipt['exchanges']==26
        assert receipt['environment']=={'PATH':'','LC_ALL':'C'}
        command=receipt['command'];assert type(command)is list and command
        # Saved execution paths remain provenance after relocation; only the current graph is opened.
        assert Path(command[0]).is_absolute() and command[0]==str(Path(md['manifest_path']).parent/md['elf'])
        cwd=receipt['cwd'];assert type(cwd)is str and Path(cwd).is_absolute()
        old_root=str(Path(cwd).parent)
        if flags:assert command==[command[0],'--runtime-config',cwd+'/config.json'] and Path(cwd).name=='profile-'+str(flags>>1)
        else:assert command==[command[0]] and Path(cwd).name=='workspace'
        before=r.document(prefix+'/fixture-before.json');after=r.document(prefix+'/fixture-after.json')
        snapshot_check(before,r,prefix+'/fixture',False);fixture_before(before,flags,old_root)
        snapshot_check(after,r,prefix+'/fixture',True)
        before_by={row['path']:row for row in before};after_by={row['path']:row for row in after}
        for name,row in before_by.items():
            assert name in after_by
            if stat.S_ISREG(row['mode']):assert row==after_by[name],('configuration input changed',name)
        streams={name:gzip.decompress(r.raw(folder+'/'+name+'.bin.gz')) for name in ('stdin','stdout','stderr')}
        for name,raw in streams.items():assert pin(raw)==receipt[name]
        assert streams['stderr']==b''
        exchanges=r.document(folder+'/exchanges.json');assert len(exchanges)==26
        initialize,initialized=d.initialization(index)
        init_in=r.raw(prefix+'/initialize.input.bin');init_out=r.raw(prefix+'/initialize.output.bin')
        initialized_in=r.raw(prefix+'/initialized.input.bin')
        assert init_in==initialize and initialized_in==initialized
        init=json.loads(init_out)
        assert set(init)=={'jsonrpc','id','result'} and init['jsonrpc']=='2.0' and init['id']=='catalog-init-'+str(index)
        assert init['result']['protocolVersion']=='2024-11-05' and isinstance(init['result']['capabilities'],dict) and isinstance(init['result']['serverInfo'],dict)
        for ordinal,wire,replies in ((0,initialize,[pin(init_out)]),(1,initialized,[])):
            exchange=exchanges[ordinal]
            assert exchange['number']==ordinal and type(exchange['number'])is int
            assert exchange['timeout_seconds']==60 and type(exchange['timeout_seconds'])is int
            number(exchange['elapsed_seconds'],60)
            assert exchange['requested_bytes']==exchange['written_bytes']==len(wire)
            assert exchange['request_sha256']==pin(wire)['sha256'] and exchange['responses']==replies and exchange['error'] is None
        inputs=[initialize,initialized];outputs=[init_out+b'\n']
        for ordinal,(case,exchange) in enumerate(zip(items,exchanges[2:],strict=True),start=2):
            wire=r.raw(prefix+f'/request-{case["sequence"]:03d}.bin');raw=r.raw(prefix+f'/response-{case["sequence"]:03d}.bin')
            assert wire==case['wire']
            expected=b'{"jsonrpc":"2.0","id":'+str(case['sequence']).encode()+c.projected_asset(component,case['modern'],flags,1)
            assert raw==expected
            assert exchange['number']==ordinal and type(exchange['number'])is int
            assert exchange['timeout_seconds']==60 and type(exchange['timeout_seconds'])is int
            number(exchange['elapsed_seconds'],60)
            assert exchange['requested_bytes']==exchange['written_bytes']==len(wire)
            assert exchange['request_sha256']==pin(wire)['sha256'] and exchange['responses']==[pin(raw)]
            assert exchange['error'] is None
            inputs.append(wire);outputs.append(raw+b'\n')
            names=[tool['name'] for tool in json.loads(raw)['result']['tools']]
            assert len(names)==(10 if flags else 7) and 'batch_edit' in names and 'weight_bellman_plan' not in names
            observed.append({k:v for k,v in case.items() if k!='wire'}|{'input':pin(wire),'output':pin(raw),'tools':names})
        assert streams['stdin']==b''.join(inputs) and streams['stdout']==b''.join(outputs)
    assert observed==report['observed']
    actual={p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}
    assert actual==set(r.files),('unread public capture files',sorted(actual-set(r.files)))
    return {'status':'COMPLETE_CONFIGURED_PUBLIC_CATALOG_READONLY_PASS','processes':9,'catalog_exchanges':216,
        'all_exchanges':234,'initialize_calls':9,'initialized_notifications':9,'complete_response_frames':225,
        'binary':binary_pin,'source_profile':report['source_profile'],'files':r.files,'source_binding':shared.GRAPH_PROFILE,
        'no_hia_execution':True,'no_rust_execution':True,'process_launches':0,'tool_body_executions':0,
        'fresh_original_comparison':False,'public_all_configuration_qualified':False,'whole_runtime_replaced':False}
