"""Execute complete original config ownership beside the static HIA owner.

Each executable uses the same exact owned fixture pathname, reconstructed
between processes. Consequently policy-digest bytes are compared directly.
Only native diagnostic codes and opaque host offsets are representation data.
"""
from pathlib import Path
import copy,hashlib,json,os,shutil,struct,subprocess,tempfile,time,tomllib
from test_config_owner import Session,COUNTS,query,startup,config,unlocked
from config_fs_cases import fixture,snapshot
from config_semantics_cases import variants
ROOT=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()

FS_CASES=['new','new_nested','parent_components','inner_dots','trailing_dot_missing','trailing_dot_existing','redundant_slashes','unicode','raw_bytes','short_symlink','long_symlink','absolute_symlink','state_755','state_1777','state_4700',
 'owner_644','owner_4600','owner_hardlink','owner_symlink','owner_fifo','owner_directory','owner_blocked','legacy_644','legacy_4600','legacy_hardlink','legacy_symlink','legacy_fifo','legacy_directory','legacy_blocked',
 'jobs_symlink','jobs_file','jobs_permissive','audit_symlink','audit_file','audit_permissive','regular_state','regular_parent','cycle','long_component','nul']
OTHER_CASES=['env-explicit','env-xdg','env-home','env-tmp','env-raw','env-empty-state','env-empty-xdg','env-empty-home',
 'typed-sequence','typed-last-host','typed-ignored-any','bad-json','bad-null','missing-config','raw-config-path','nonutf8-config-path',
 'all-profiles','name-and-alias-order','changed-file','second-install','second-invalid','second-same-state']

def write_config(path,value):path.write_text(json.dumps(value,ensure_ascii=False,separators=(',',':')))
def unpack(raw,ops,native):
    rows=[];pos=0
    for op in ops:
        assert pos+8<=len(raw);n=struct.unpack_from('<Q',raw,pos)[0];pos+=8;out=raw[pos:pos+n];pos+=n
        assert len(out)==n and out[:8]==b'HRCFGM01';status,code,size=struct.unpack_from('<3Q',out,8);assert size==n-32
        payload=out[32:]
        if native and op in [4,5] and status==0 and payload:
            magic,generation,token,n=struct.unpack_from('<8s3Q',payload);assert magic==b'HRCFHOST' and generation==1 and token>0 and len(payload)==32+n;payload=payload[32:]
        rows.append({'status':status,'payload_hex':payload.hex()})
    assert pos==len(raw)
    return rows

def config_for_case(name,root):
    held=None;env={}
    if name in FS_CASES:
        state,held=fixture(name,root)
        try:state.decode('utf-8');value=config(os.fsdecode(state))
        except UnicodeDecodeError:value=config(None);env['HEPTA_RUNTIME_STATE_DIR']=state
    else:
        root.mkdir(mode=0o700);value=config(root/'state')
    path=root/'config.json'
    if name.startswith('env-'):
        value=config(None)
        suffix=name[4:]
        env={'explicit':{'HEPTA_RUNTIME_STATE_DIR':str(root/'explicit'),'HOME':str(root/'ignored')},
             'xdg':{'XDG_STATE_HOME':str(root/'xdg')},'home':{'HOME':str(root/'home')},'tmp':{'TMPDIR':str(root/'tmp')},
             'raw':{'HEPTA_RUNTIME_STATE_DIR':os.fsencode(root)+b'/raw-\xff'},'empty-state':{'HEPTA_RUNTIME_STATE_DIR':''},
             'empty-xdg':{'XDG_STATE_HOME':''},'empty-home':{'HOME':''}}[suffix]
    if name=='all-profiles':value=variants()['all'];value['state_dir']=str(root/'state')
    if name=='name-and-alias-order':value=config(root/'state',{'a':{'ssh_target':'z','remote_state_dir':'/r'},'z':{'ssh_target':'other','remote_state_dir':'/r'}})
    if name in ['raw-config-path','nonutf8-config-path']:
        path=Path(os.fsdecode(os.fsencode(root)+(b'/cfg-\xff-\xe2\x82-\xed\xa0\x80' if name=='nonutf8-config-path' else b'/cfg-\xe4\xb8\xad')))
    write_config(path,value)
    if name=='typed-sequence':path.write_text(json.dumps([str(root/'state'),[],{'h':{'ssh_target':'target','remote_state_dir':'/r'}}]))
    if name=='typed-last-host':path.write_text('{"state_dir":'+json.dumps(str(root/'state'))+',"hosts":{"h":{"ssh_target":"a","remote_state_dir":"/a"},"h":{"ssh_target":"b","remote_state_dir":"/b"}}}')
    if name=='typed-ignored-any':path.write_bytes(b'{"unknown":[1e99999,"\\ud800","\xff"],"state_dir":'+json.dumps(str(root/'state')).encode()+b',"hosts":{"h":{"ssh_target":"a","remote_state_dir":"/a"}}}')
    if name=='bad-json':path.write_bytes(b'{"hosts":')
    if name=='bad-null':path.write_bytes(b'null')
    if name in ['missing-config','nonutf8-config-path']:path.unlink()
    return path,env,held

def run_case(binary,name,root,native):
    path,environment,held=config_for_case(name,root);env={'PATH':'','LC_ALL':'C'};env.update(environment)
    try:
        if name in ['changed-file','second-install','second-invalid','second-same-state']:
            rows=[];events=[]
            with Session(binary,path,env=environment) as session:
                def call(wire,op=0):
                    status,code,payload=session.call(wire)
                    rows.append({'status':status,'payload_hex':payload.hex()})
                    return status,payload
                for op in [1,2,3,6]:call(query(op),op)
                events.append({'both_original_locks_held':all(not unlocked(root/'state'/n) for n in ['controller.owner.lock','controller.lock'])})
                if name=='changed-file':
                    path.write_bytes(b'not json');(root/'state').rename(root/'moved');(root/'state').mkdir(mode=0o700)
                else:
                    target=root/('state' if name=='second-same-state' else 'second')
                    value=config(target,{'other':{'ssh_target':'new-target','remote_state_dir':'/new'}})
                    if name=='second-invalid':value['hosts']={}
                    write_config(path,value);call(startup(path))
                    if name=='second-install':events.append({'new_locks_released':all(unlocked(root/'second'/n) for n in ['controller.owner.lock','controller.lock'])})
                for _ in range(2):
                    for op in [1,2,3,6]:call(query(op),op)
                retained=root/('moved' if name=='changed-file' else 'state')
                events.append({'old_locks_still_held':all(not unlocked(retained/n) for n in ['controller.owner.lock','controller.lock'])})
            events.append({'old_locks_released_at_eof':all(unlocked(retained/n) for n in ['controller.owner.lock','controller.lock'])})
            return {'exit':0,'stdout_rows':rows,'stderr_hex':'','events':events,'snapshot':snapshot(root)}
        requests=[(op,b'') for op in [1,2,3,6,1,2,3]]
        if name=='name-and-alias-order':requests += [(4,b'z'),(5,b'z'),(5,b'other'),(5,b'missing'),(4,'中😀'.encode())]
        data=b''.join(struct.pack('<Q',len(q))+q for op,key in requests for q in [query(op,key)])
        p=subprocess.run([str(binary),'--runtime-config',os.fsdecode(path)],input=data,capture_output=True,env=env,timeout=15)
        assert p.returncode in [0,78],(name,p.returncode,p.stderr)
        rows=unpack(p.stdout,[op for op,_ in requests],native) if p.returncode==0 else []
        if p.returncode!=0:assert p.stdout==b''
        COUNTS['actual_elf_requests']+=len(rows)
        return {'exit':p.returncode,'stdout_rows':rows,'stderr_hex':p.stderr.hex(),'snapshot':snapshot(root)}
    finally:
        if held is not None:os.close(held)
