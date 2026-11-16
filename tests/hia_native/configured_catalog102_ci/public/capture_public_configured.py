"""Exercise the actual production stdio entry; never execute a Rust reference."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,stat,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import public_domain as d
import public_common as shared
sha=lambda raw:hashlib.sha256(raw).hexdigest()
pin=lambda raw:{'bytes':len(raw),'sha256':sha(raw)}

def put(path,value):
    raw=value if type(value)is bytes else (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with path.open('xb') as stream:assert stream.write(raw)==len(raw)

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def snapshot(root):
    rows=[]
    for p in [root,*sorted(root.rglob('*'))]:
        s=p.lstat();row={'path':p.relative_to(root).as_posix(),'mode':s.st_mode,'dev':s.st_dev,'ino':s.st_ino,
            'uid':s.st_uid,'gid':s.st_gid,'nlink':s.st_nlink,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
        assert stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)
        if stat.S_ISREG(s.st_mode):
            raw=p.read_bytes();row.update(pin(raw),content_hex=raw.hex())
        rows.append(row)
    return rows

def run(component,graph,manifest,output):
    shared.source_check(ROOT,component,graph)
    sys.path.insert(0,str(component));import configured_common as c
    c.source_check(component)
    md=json.loads(manifest.read_bytes());assert md['status']=='PASS' and md['physical_images']==102
    assert md['catalog_installed_capability_mask']==1
    assert md['source_binding']['manifest_sha256']==sha((graph/'native/runtime_mcp_sources.json').read_bytes())
    for name,expected in md['source_binding']['files'].items():assert pin((graph/name).read_bytes())==expected
    binary=manifest.parent/md['elf'];assert pin(binary.read_bytes())=={'bytes':md['elf_bytes'],'sha256':md['elf_sha256']}
    capture=module('configured_public_capture',graph/'tests/hia_native/runtime_mcp_public_capture.py')
    fixture=module('configured_reference_fixture',component/'retained/pipeline/policy_base/reference/capture.py')
    output.mkdir(parents=True,exist_ok=False)
    put(output/'DOMAIN.json',d.domain());put(output/'binary-before.json',pin(binary.read_bytes()))
    started=time.monotonic_ns();processes=[];observed=[];active=None
    try:
        for profile_index,flags in enumerate(d.FLAGS):
            folder=output/f'profile-{profile_index}';folder.mkdir(mode=0o700)
            owned=folder/'fixture';owned.mkdir(mode=0o700)
            old_umask=os.umask(0o077)
            try:
                if flags:
                    marker=b"raise SystemExit('catalog configuration fixture; never dispatched')\n"
                    config=fixture.fixture(owned,flags>>1,d.HIA_CATALOG_SHA256,pin(marker))
                    cwd=config.parent
                else:
                    config=None;cwd=owned/'workspace';cwd.mkdir(mode=0o700)
            finally:os.umask(old_umask)
            put(folder/'fixture-before.json',snapshot(owned))
            active=capture.Public(folder/'process',binary,cwd,config)
            identity={'pid':active.process.pid,'parent_pid':os.getpid(),'pgid':os.getpgid(active.process.pid),
                'binary':pin(binary.read_bytes()),'profile_index':profile_index,'flags':flags}
            put(folder/'process-identity.json',identity)
            initialize,initialized=d.initialization(profile_index)
            reply=active.exchange(initialize)[0]
            put(folder/'initialize.input.bin',initialize);put(folder/'initialize.output.bin',reply)
            init=json.loads(reply)
            assert set(init)=={'jsonrpc','id','result'} and init['jsonrpc']=='2.0' and init['id']=='catalog-init-'+str(profile_index)
            assert init['result']['protocolVersion']=='2024-11-05' and isinstance(init['result']['capabilities'],dict) and isinstance(init['result']['serverInfo'],dict)
            assert active.exchange(initialized,expected=0)==[]
            put(folder/'initialized.input.bin',initialized)
            for case in [r for r in d.rows() if r['profile_index']==profile_index]:
                raw=active.exchange(case['wire'])[0]
                expected=(b'{"jsonrpc":"2.0","id":'+str(case['sequence']).encode()+c.projected_asset(component,case['modern'],flags,1)) if case['connection_accepts'] else d.unsupported_wire(case)
                put(folder/f'request-{case["sequence"]:03d}.bin',case['wire'])
                put(folder/f'response-{case["sequence"]:03d}.bin',raw)
                assert raw==expected,(case['sequence'],case['protocol_version'],'complete catalog or admission result differs')
                names=[x['name'] for x in json.loads(raw)['result']['tools']] if case['connection_accepts'] else []
                if case['connection_accepts']:assert len(names)==(10 if flags else 7) and 'weight_bellman_plan' not in names and 'batch_edit' in names
                observed.append({k:v for k,v in case.items() if k!='wire'}|{'input':pin(case['wire']),'output':pin(raw),'tools':names})
            receipt=active.close();active=None
            assert receipt['elapsed_seconds']<=180
            put(folder/'fixture-after.json',snapshot(owned))
            processes.append({'profile_index':profile_index,'flags':flags,'process':receipt,'identity':identity})
        assert len(observed)==216 and len(processes)==9
        assert time.monotonic_ns()-started<=180_000_000_000
        assert pin(binary.read_bytes())=={'bytes':md['elf_bytes'],'sha256':md['elf_sha256']}
        result={'schema':'hepta.runtime.configured-catalog-public-native.v1','status':'ACTUAL_COMPLETE_PUBLIC_CATALOG_NATIVE_CAPTURE',
            'source_profile':pin((ROOT/'public-source-profile.json').read_bytes()),
            'pid':os.getpid(),'parent_pid':os.getppid(),'pgid':os.getpgrp(),'native_deadline_seconds':180,
            'manifest':pin(manifest.read_bytes()),'binary':pin(binary.read_bytes()),'source_binding':md['source_binding'],
            'observed':observed,'processes':processes,'elapsed_ns':time.monotonic_ns()-started,
            'fresh_original_comparison':False,'tool_body_executions':0,'public_all_configuration_qualified':False,'whole_runtime_replaced':False}
        put(output/'result.json',result)
        print(json.dumps({k:v for k,v in result.items() if k not in ('observed','processes','source_binding')},sort_keys=True))
    except BaseException as exc:
        put(output/'FAILURE.json',{'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc(),
            'completed_exchanges':len(observed),'completed_profiles':len(processes),'elapsed_ns':time.monotonic_ns()-started})
        raise
    finally:
        if active is not None:
            try:active.close(failed=True)
            finally:
                put(folder/'fixture-after-failure.json',snapshot(owned))

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('component','graph','manifest','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.component.resolve(strict=True),a.graph.resolve(strict=True),a.manifest.resolve(strict=True),a.output.absolute())
