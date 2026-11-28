#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Execute exact current Rust and HIA config domains; Rust is only an external oracle."""
from __future__ import annotations
from pathlib import Path
import argparse,collections,ctypes,gzip,hashlib,json,os,stat,struct,subprocess,sys,time,traceback,zipfile
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
    ap=argparse.ArgumentParser()
    for n in ('repo','native','reference','validator','corpus','output'):ap.add_argument('--'+n,type=Path,required=True)
    a=ap.parse_args();repo=a.repo.resolve(strict=True);out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    sys.path[:0]=[str(repo/'scripts'),str(repo/'tests/hia_native')]
    from hia_native_loader import NativeModule,NativeRejected,NativeCapacityError
    from config_regex_session import NativeValidator
    captured={};counts=collections.Counter();records=[];differences=[];started=time.monotonic()
    def read(p):
        p=p.resolve(strict=True);raw=p.read_bytes();r={'bytes':len(raw),'sha256':SHA(raw),'mode':stat.S_IMODE(p.stat().st_mode)}
        if str(p) in captured:assert captured[str(p)]==r,str(p)
        captured[str(p)]=r;return raw
    def terminal():
        for name,want in list(captured.items()):read(Path(name))
    def data(p):return json.loads(read(p))
    def call(session,wire):
        counts['native_calls']+=1
        try:
            raw=session.invoke(wire);return len(raw),raw
        except NativeRejected as e:
            assert e.code in (0xffffffff,0xfffffffd),hex(e.code)
            return e.code,b''
    def command(name,binary,requests):
        t=time.monotonic();raw=read(binary)
        p=subprocess.run([str(binary)],input=requests,capture_output=True,timeout=180,env={'PATH':'','LC_ALL':'C'})
        (out/(name+'.stdout.gz')).write_bytes(gzip.compress(p.stdout,mtime=0));(out/(name+'.stderr')).write_bytes(p.stderr)
        records.append({'name':name,'binary':str(binary),'binary_sha256':SHA(raw),'input_bytes':len(requests),'input_sha256':SHA(requests),'exit':p.returncode,'seconds':time.monotonic()-t,'timeout_seconds':180,'stdout_sha256':SHA(p.stdout),'stderr_sha256':SHA(p.stderr)})
        assert p.returncode==0 and p.stdout.count(b'\n')==requests.count(b'\n'),name
        return p.stdout.splitlines()
    def compare(name,labels,native,reference):
        assert len(labels)==len(native)==len(reference)
        for index,(label,n,r) in enumerate(zip(labels,native,reference,strict=True)):
            nc,np=n.split(b':',1);rc,rp=r.split(b':',1)
            if nc in (b'ffffffff',b'fffffffd'):
                equal=rc==nc and np==b'';counts[name+'/typed_refusals']+=1
            else:
                equal=n==r;counts[name+'/exact_results']+=1
            if not equal:differences.append({'domain':name,'index':index,'case':label,'native':n.decode(),'reference':r.decode()})
        counts[name+'/cases']+=len(native)
    report={'status':'RUNNING'}
    try:
        read(Path(__file__))
        for n in ('scripts/hia_native_loader.py','tests/hia_native/config_regex_session.py'):read(repo/n)
        nb=data(a.native);ref=data(a.reference);vr=data(a.validator)
        assert nb['status']==ref['status']==vr['status']=='PASS'
        for name,want in nb['physical_inputs'].items():
            raw=read(Path(name));assert len(raw)==want['bytes'] and SHA(raw)==want['sha256']
        for name,want in vr['physical_inputs'].items():
            raw=read(Path(name));assert len(raw)==want['bytes'] and SHA(raw)==want['sha256']
        executables={name:Path(row['path']) for name,row in ref['executables'].items()}
        for name,p in executables.items():assert SHA(read(p))==ref['executables'][name]['sha256']
        project=next(iter(executables.values())).parents[2]/'project'
        for name,want in ref['project_inputs'].items():assert SHA(read(project/name))==want
        original_meta=data(repo/'tests/hia_native/config_reference_sources.json')
        for name,want in original_meta['files'].items():
            if name=='Cargo.toml':continue
            raw=read(project/name);assert (len(raw),SHA(raw))==(want['bytes'],want['sha256'])
        for block in original_meta['source_blocks']:
            for target in block['targets']:
                b=read(project/target['path'])[target['offset']:target['offset']+block['bytes']]
                assert SHA(b)==block['sha256'],block['label']
        assert len(original_meta['source_blocks'])==54
        cm=data(a.corpus/'inputs.json');archive=read(a.corpus/'inputs.zip')
        assert (len(archive),SHA(archive))==(cm['archive_bytes'],cm['archive_sha256'])
        corpus={}
        with zipfile.ZipFile(a.corpus/'inputs.zip') as z:
            assert z.testzip() is None and set(z.namelist())==set(cm['files'])
            for name,want in cm['files'].items():
                raw=z.read(name);assert (len(raw),SHA(raw))==(want['bytes'],want['sha256']);corpus[name]=raw
                (out/name).write_bytes(raw)
        meta=json.loads(corpus['corpora.json'])
        models={}
        for name,path in nb['model_manifests'].items():
            p=Path(path);m=data(p)
            assert SHA(read(p.parent/m['image']))==m['image_sha256']
            assert SHA(read(p.parent/m['source']))==m['source_sha256']
            models[name]=NativeModule(p,manifest_sha256=SHA(read(p)))
        oldrow=next(row for row in nb['members'] if row['name']=='native/config_json_span.hepta') if any(row['name']=='native/config_json_span.hepta' for row in nb['members']) else None
        old_manifest=repo.parent/'public126-baseline-build-v2/build/modules/public-task-batch-extract-json/manifest.json'
        oldmeta=data(old_manifest);assert SHA(read(old_manifest.parent/oldmeta['image']))==oldmeta['image_sha256']
        old=NativeModule(old_manifest,manifest_sha256=SHA(read(old_manifest)))
        typed_wire=corpus['typed.requests.hex'];typed_labels=json.loads(corpus['typed.categories.json'])
        wires=[bytes.fromhex(x.decode()) for x in typed_wire.splitlines()]
        assert len(wires)==meta['domains']['typed']['cases']==7666
        original_wire=b''.join(x.hex().encode()+b'\n' for x in wires[:6491])
        assert SHA(original_wire)=='87a619c1f79f22d4e8f5074856d0e49ed4fd475bf2809deb91e79d492f65b7c1'
        prior_reference=command('original-typed',executables['hia-runtime-config-typed'],original_wire)
        native=[]
        with old.session(output_capacity=2<<20,workspace_capacity=4<<20) as session:
            for wire in wires[:6491]:
                code,raw=call(session,wire);native.append(f'{code:08x}:'.encode()+raw.hex().encode())
        oldbytes=b'\n'.join(native)+b'\n';assert SHA(oldbytes)=='7d72f4df20f45a0b2317782dec628048360a79b724d008231d5f6a46439fb9f7'
        (out/'original-typed-native.txt.gz').write_bytes(gzip.compress(oldbytes,mtime=0))
        compare('original-typed',typed_labels[:6491],native,prior_reference)
        current_reference=command('current-typed',executables['hia-runtime-config-current-typed'],typed_wire)
        required=[i for i,label in enumerate(typed_labels) if label=='current/full-map']
        assert len(required)==4
        assert all(current_reference[i].split(b':',1)[0] not in (b'ffffffff',b'fffffffd') for i in required),'current positive typed fixtures must be accepted'
        counts['current-typed/required-positive-fixtures']=len(required)
        native=[]
        with models['json'].session(output_capacity=2<<20,workspace_capacity=4<<20) as session:
            for wire in wires:
                code,raw=call(session,wire);native.append(f'{code:08x}:'.encode()+raw.hex().encode())
        (out/'current-typed-native.txt.gz').write_bytes(gzip.compress(b'\n'.join(native)+b'\n',mtime=0))
        compare('current-typed',typed_labels,native,current_reference)
        semwire=corpus['semantics.requests.hex'];labels=json.loads(corpus['semantics.categories.json'])
        wires=[bytes.fromhex(x.decode()) for x in semwire.splitlines()]
        assert len(wires)==meta['domains']['semantics']['cases']==3131
        current_reference=command('current-semantics',executables['hia-runtime-config-current-semantics'],semwire)
        required=[i for i,label in enumerate(labels) if label.startswith('current/valid-all-five/')]
        assert len(required)==4 and all(current_reference[i].startswith(b'00000000:') for i in required),'current positive semantic fixtures must be accepted'
        counts['current-semantics/required-positive-fixtures']=len(required)
        native=[]
        with models['json'].session(output_capacity=16<<20,workspace_capacity=32<<20) as parser, models['identity'].session(output_capacity=16<<20,workspace_capacity=32<<20) as identity, NativeValidator(Path(vr['manifest']),Path(vr['source_view'])) as validator:
            for wire in wires:
                operation=struct.unpack_from('<Q',wire,8)[0]
                parse=bytearray(wire);struct.pack_into('<Q',parse,8,2)
                code,arena=call(parser,bytes(parse))
                if code in (0xffffffff,0xfffffffd):
                    native.append(f'{code:08x}:'.encode());continue
                if operation==4:
                    frame=b'HRCFGI01'+struct.pack('<2Q',1,len(arena))+arena
                    code,digest=call(identity,frame)
                    if code in (0xffffffff,0xfffffffd):
                        native.append(f'{code:08x}:'.encode());continue
                    assert len(digest)==32
                    c,canonical=call(identity,b'HRCFGI01'+struct.pack('<2Q',2,len(arena))+arena)
                    assert c==len(canonical) and SHA(canonical)==digest.hex()
                    native.append(b'00000000:'+digest.hex().encode());counts['identity-canonical-calls']+=1
                else:
                    counts['native_calls']+=1
                    answer=validator.invoke(b'HRCFGV01'+struct.pack('<2Q',operation,len(arena))+arena)
                    assert len(answer)>=32
                    magic,status,diag,n=struct.unpack_from('<8s3Q',answer)
                    assert magic==b'HRCFGR01' and status in (0,1) and n==len(answer)-32
                    native.append(f'{status:08x}:'.encode()+answer[32:].hex().encode())
        (out/'current-semantics-native.txt.gz').write_bytes(gzip.compress(b'\n'.join(native)+b'\n',mtime=0))
        compare('current-semantics',labels,native,current_reference)
        def selected(label):
            indices=[i for i,value in enumerate(labels) if value==label];assert len(indices)==1
            return native[indices[0]]
        absent=selected('current/absent/op4');null=selected('current/explicit-null/op4');valid=selected('current/valid-all-five/op4')
        assert absent==null and valid!=absent and valid.startswith(b'00000000:')
        digests=[selected('current/identity-binds-'+role+'/op4') for role in ('entry','submit','observation','cancel','launcher')]
        assert len(set(digests+[valid,absent]))==7 and all(x.startswith(b'00000000:') for x in digests)
        counts['current-native-jobs/identity-binding-controls']=7
        for m in models.values():m.close()
        old.close();terminal()
        report={'status':'PASS' if not differences else 'FAIL','counts':dict(counts),'differences':differences,'source_unchanged':True,'source_blocks_retained':54,'reference_runtime_dependency':False,'public_complete':False,'whole_runtime_complete':False}
    except BaseException as e:
        report={'status':'FAIL','error':repr(e),'traceback':traceback.format_exc(),'counts':dict(counts),'differences':differences}
    report.update(schema='hepta.runtime.config-native-jobs-differential.v1',seconds=time.monotonic()-started,physical_inputs=captured,commands=records)
    (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('physical_inputs','commands','differences')}|{'differences':len(differences)},indent=2),flush=True)
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
