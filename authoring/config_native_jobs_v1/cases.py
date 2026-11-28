#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Current native_jobs differential inputs, retaining both complete original corpora."""
from __future__ import annotations
from pathlib import Path
import argparse,collections,copy,hashlib,json,random,struct,sys
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests/hia_native')]
import config_typed_cases as original_typed
import config_semantics_cases as original_semantics
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ROLES=(('entry','hia-job-entry'),('submit','hia-job-submit'),('observation','hia-job-observation'),('cancel','hia-job-cancel'),('launcher','hia-job-launch'))
def encode(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def profile():return {name:{'executable':'/native/'+basename,'sha256':'a'*64} for name,basename in ROLES}
def host():return dict(native_jobs=profile(),ssh_target='private-target',remote_state_dir='/private/state')
def semwire(value,operation=1,default=b'/default-state'):
    raw=value if isinstance(value,bytes) else encode(value)
    return b'HRCFGJ01'+struct.pack('<4Q',operation,100,len(default),len(raw))+default+raw
def typed():
    rows=[('original/'+label,wire) for label,wire in original_typed.cases()]
    old=b''.join(w.hex().encode()+b'\n' for _,w in rows)
    assert len(rows)==6491 and SHA(old)=='87a619c1f79f22d4e8f5074856d0e49ed4fd475bf2809deb91e79d492f65b7c1'
    def add(label,kind,value):
        raw=value if isinstance(value,bytes) else encode(value)
        rows.append(('current/'+label,original_typed.wire(kind,raw)))
    malformed=[b'null',b'true',b'false',b'0',b'-0',b'0.0',b'1e9999',b'18446744073709551616',
        b'""',b'"\\xff"',b'"\\ud800"',b'"\\udc00"',b'"\\ud800\\udc00"',b'[]',b'{}',
        b'[1,]',b'{"a":1,}',b'{"a" 1}',b'[[[]]]',b'{"x":"\\xff"}',b'"\\q"',b'"\\n"']
    specs=[(109,profile()),(110,profile()['entry']),(101,host()),(100,{'state_dir':'/state','hosts':{'h':host()}})]
    for kind,value in specs:
        add('full-map',kind,value)
        for raw in malformed:add('root-type',kind,raw)
        fields=list(value)
        for end in range(len(fields)+2):
            values=list(value.values());add('sequence-prefix',kind,values[:end] if end<=len(values) else values+[0])
        for field in fields:
            rest={k:v for k,v in value.items() if k!=field}
            add('field-missing',kind,rest)
            for raw in malformed:
                prefix=encode(rest)[:-1]
                add('field-type',kind,prefix+(b',' if rest else b'')+encode(field)+b':'+raw+b'}')
            prefix=encode(rest)[:-1]+(b',' if rest else b'')
            for a,b in [(encode(value[field]),encode(value[field])),(b'null',b'null'),(b'null',encode(value[field])),(encode(value[field]),b'null')]:
                add('duplicate-known',kind,prefix+encode(field)+b':'+a+b','+encode(field)+b':'+b+b'}')
            escaped=('"\\u%04x'%ord(field[0])+field[1:]+'"').encode()
            add('escaped-known-key',kind,prefix+escaped+b':'+encode(value[field])+b'}')
        for raw in malformed+[b'['*256+b'0'+b']'*256]:
            add('unknown-field',kind,encode(value)[:-1]+b',"unknown":'+raw+b'}')
    full=original_typed.sample(101)
    full={'native_jobs':profile(),**full}
    add('full-host-all-original-fields',101,full)
    for end in range(22):add('full-host-array',101,list(full.values())[:end] if end<=20 else list(full.values())+[None])
    for state in [None,profile(),{},[],False,0]:
        value=copy.deepcopy(full);value['native_jobs']=state;add('host-option',101,value)
        add('runtime-host-option',100,{'hosts':{'h':value}})
    rng=random.Random(711011);seeds=[(k,encode(v)) for k,v in specs]
    for i in range(600):
        kind,seed=seeds[i%len(seeds)];raw=bytearray(seed);at=rng.randrange(len(raw)+1)
        if i%3==0:raw[at:at]=bytes([rng.randrange(256)])
        elif i%3==1:del raw[at:at+rng.randrange(1,4)]
        else:raw[at:at+1]=bytes([rng.randrange(256)])
        add('raw-mutation',kind,bytes(raw))
    return rows
def semantics():
    rows=[('original/'+label,wire) for label,wire in original_semantics.cases()]
    old=b''.join(w.hex().encode()+b'\n' for _,w in rows)
    assert len(rows)==2063 and SHA(old)=='b817774c48233e843a9b7b5f3f1577a0306846946694ca9f6be1c4e0517ddee2'
    def add(label,value):
        for op in (1,2,3,4):rows.append(('current/'+label+'/op'+str(op),semwire(value,op)))
    base={'state_dir':'/controller/state','hosts':{'h':host()}}
    add('valid-all-five',base)
    absent=copy.deepcopy(base);del absent['hosts']['h']['native_jobs'];add('absent',absent)
    null=copy.deepcopy(base);null['hosts']['h']['native_jobs']=None;add('explicit-null',null)
    for role,basename in ROLES:
        for path in ['', '/', 'relative/'+basename, '/native/other', '/native/'+basename+'x',
            '/native//'+basename, '/native/./'+basename, '/native/../'+basename, '/native/'+basename+'/',
            '//native/'+basename, '/native/中😀/'+basename,
            '/'+('a'*(4096-len(basename)-2))+'/'+basename,
            '/'+('a'*(4097-len(basename)-2))+'/'+basename]+['/native/'+chr(c)+'/'+basename for c in (0,1,9,10,13,31,127,128,133,159)]+['/native/'+chr(c)+'/'+basename for c in (160,0x2028,0x2029,0x200b)]:
            value=copy.deepcopy(base);value['hosts']['h']['native_jobs'][role]['executable']=path;add('path-'+role,value)
        for digest in ['', 'a'*63,'a'*65,'A'*64,'g'*64,'0'*64,'0123456789abcdef'*4,'é'*64,'a'*63+'\n']:
            value=copy.deepcopy(base);value['hosts']['h']['native_jobs'][role]['sha256']=digest;add('sha-'+role,value)
        value=copy.deepcopy(base);del value['hosts']['h']['native_jobs'][role];add('missing-'+role,value)
        for field in ('executable','sha256'):
            for bad in (None,False,0,[],{},''):
                value=copy.deepcopy(base);value['hosts']['h']['native_jobs'][role][field]=bad;add('pin-type-'+role+'-'+field,value)
    for platform in ('linux','macos'):
        value=copy.deepcopy(base);value['hosts']['h']['platform']=platform;add('platform-'+platform,value)
    for mode in ('isolated','operator'):
        value=copy.deepcopy(base);value['hosts']['h'].update(execution_mode=mode,allow_execute=True,allow_job_network=True);add('mode-'+mode,value)
    for name in ('bad host','h','h-_.9',''):
        value=copy.deepcopy(base);value['hosts']={name:value['hosts']['h']};add('host-name',value)
    conflicts=[('state_dir','relative'),('controller_workspace_roots',['relative'])]
    for key,bad in conflicts:
        value=copy.deepcopy(base);value[key]=bad;value['hosts']['h']['native_jobs']['entry']['executable']='relative';add('first-error-'+key,value)
    for field,bad in [('ssh_target','-bad'),('remote_state_dir','relative'),('checkpoint_binary','relative'),('execution_mode','operator')]:
        value=copy.deepcopy(base);value['hosts']['h'][field]=bad;value['hosts']['h']['native_jobs']['entry']['executable']='relative';add('native-before-host-'+field,value)
    for role,_ in ROLES:
        value=copy.deepcopy(base);value['hosts']['h']['native_jobs'][role]['sha256']='b'*64;add('identity-binds-'+role,value)
    return rows
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    out=a.output;out.mkdir(mode=0o700,parents=True,exist_ok=False)
    current=(ROOT/'src/mcp/runtime/config.rs').read_text()
    assert 'pub struct NativeJobPin {\n\tpub executable: String,\n\tpub sha256: String,\n}' in current
    inputs={str(p):SHA(p.read_bytes()) for p in [Path(__file__),ROOT/'tests/hia_native/config_typed_cases.py',ROOT/'tests/hia_native/config_semantics_cases.py',ROOT/'scripts/config_schema.py',ROOT/'src/mcp/runtime/config.rs']}
    reports={}
    for name,rows in [('typed',typed()),('semantics',semantics())]:
        requests=b''.join(w.hex().encode()+b'\n' for _,w in rows)
        (out/(name+'.requests.hex')).write_bytes(requests)
        (out/(name+'.categories.json')).write_text(json.dumps([k for k,_ in rows])+'\n')
        reports[name]={'cases':len(rows),'original_cases':6491 if name=='typed' else 2063,'requests_sha256':SHA(requests),'requests_bytes':len(requests),'categories':dict(collections.Counter(k for k,_ in rows))}
    assert all(SHA(Path(p).read_bytes())==want for p,want in inputs.items())
    report={'schema':'hepta.runtime.native-jobs-config-corpora.v1','status':'PREPARED','domains':reports,'inputs':inputs,'source_unchanged':True,'reference_executed':False,'native_executed':False}
    (out/'corpora.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({n:{k:v for k,v in r.items() if k!='categories'} for n,r in reports.items()},sort_keys=True))
if __name__=='__main__':main()
