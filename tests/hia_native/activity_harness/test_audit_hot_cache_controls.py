"""Reject malformed borrowed requests, child receipts and private cache ownership."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import struct
import sys

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
WORK=8<<20
OUT=266304
INVALID=0xffffffff
CAPACITY=0xfffffffe
STATE=0xfffffff9
EFFECT=0xfffffff0
def setq(raw,offset,value):
    out=bytearray(raw);struct.pack_into('<Q',out,offset,value);return bytes(out)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','runtime','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    sys.path[:0]=[str(Path(__file__).resolve().parent),str(args.runtime.resolve(strict=True)/'scripts')]
    from hia_native_loader import NativeModule
    from audit_hot_cache_cases import request,step,query,put,hit,cold,stamp,record,reply,records_wire
    from audit_hot_cache_driver import invoke
    manifest=args.manifest.read_bytes();rows=[];rejects=0
    a=stamp();wire=request(query(a));primary=request(put(a,[record()]))
    before=request(step(4,[record()],before=a));snapshot=request(hit(a))
    def rejected(name,code,output,state,expected,outcap=OUT):
        nonlocal rejects
        assert code==expected and output==b'\xa7'*outcap,(name,code,expected)
        rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejects+=1
    def put_reply(session,raw):
        ctypes.memmove(ctypes.addressof(session._workspace)+524288,raw,len(raw))
        sequence=struct.unpack_from('<Q',session._workspace,264)[0]
        struct.pack_into('<2Q',session._workspace,320,sequence,len(raw))
    with NativeModule(args.manifest,manifest_sha256=SHA(manifest)) as module:
        bad=[('short',wire[:63],OUT,WORK,INVALID),('oversize',wire+bytes((1<<20)+1-len(wire)),OUT,WORK,INVALID),
            ('magic',b'BADMAGIC'+wire[8:],OUT,WORK,INVALID),('output-header',wire,63,WORK,CAPACITY),
            ('snapshot-output',snapshot,OUT-1,WORK,CAPACITY),('workspace',wire,OUT,WORK-1,CAPACITY),
            ('trailing',wire+b'\0',OUT,WORK,INVALID),('truncated-record',primary[:-1],OUT,WORK,INVALID)]
        for at,value in ((8,6),(24,1),(32,1),(32,2),(40,1),(40,513),(48,1),(48,112),(56,1)):
            bad.append((f'request-{at}-{value}',setq(wire,at,value),OUT,WORK,INVALID))
        for operation in (0,5):
            bad.append((f'no-directory-{operation}',setq(request(step(operation)),16,1),OUT,WORK,INVALID))
        for at,value in ((40,0),(40,2),(48,0),(48,111)):
            bad.append((f'completion-{at}-{value}',setq(before,at,value),OUT,WORK,INVALID))
        for at,value in ((0,0),(56,0),(56,3),(80,1),(104,1)):
            bad.append((f'stamp-{at}-{value}',setq(before,64+at,value),OUT,WORK,INVALID))
        fingerprint=request(step(4,[record()],before=stamp(kind=2)))
        for at in (64,72):bad.append((f'fingerprint-watch-{at}',setq(fingerprint,64+at,1),OUT,WORK,INVALID))
        for at,value in ((0,0),(8,2),(16,2),(40,3),(48,1),(56,1),(64,257),(72,513),(112,1),(248,1)):
            bad.append((f'projection-{at}-{value}',setq(primary,72+at,value),OUT,WORK,INVALID))
        bad.extend([('record-length',setq(primary,64,513),OUT,WORK,INVALID),
            ('record-utf8',primary[:-1]+b'\xff',OUT,WORK,INVALID)])
        for name,raw,outcap,workcap,expected in bad:
            code,out,state=module.invoke_raw(raw,output_capacity=outcap,workspace_capacity=workcap,output_fill=0xa7)
            rejected(name,code,out,state,expected,outcap)
        answer=reply(112,a)
        mutations=[]
        for at,value in ((0,0),(8,2),(16,101),(24,2),(32,8193),(40,9),(48,524289),(56,266287),
                (64,0),(64,2),(72,47),(72,266289),(80,5),(88,1)):
            mutations.append((f'action-{at}-{value}',lambda s,at=at,value=value:struct.pack_into('<Q',s._workspace,256+at,value),answer,wire))
        mutations.extend([
            ('argument-changed',lambda s:struct.pack_into('<Q',s._workspace,8192,12),answer,wire),
            ('sequence-changed',lambda s:struct.pack_into('<Q',s._workspace,16,2),answer,wire),
            ('phase-invalid',lambda s:struct.pack_into('<Q',s._workspace,8,7),answer,wire),
            ('input-value-changed',lambda s:None,answer,setq(wire,16,12)),
            ('input-length-changed',lambda s:None,answer,wire+b'\0'),
        ])
        error=reply(diagnostic=23,errno=2,error_kind=1)
        replies=[('magic',b'BADMAGIC'+answer[8:]),('short',answer[:47]),('stamp-short',answer[:-1]),
            ('stamp-value',setq(answer,32,111)),('stamp-tag',setq(answer,48+56,0)),
            ('stamp-watch-digest',setq(answer,48+80,1)),('error-payload',error+b'\0'),
            ('error-value',setq(error,32,1)),('fingerprint-watch',reply(112,setq(stamp(kind=2),64,1)))]
        for at,value in ((8,65536),(16,4096),(24,2),(40,1)):
            replies.append((f'field-{at}-{value}',setq(error,at,value)))
        for diagnostic in (0,24):
            replies.append((f'nonio-error-{diagnostic}',reply(diagnostic=diagnostic,errno=2)))
            replies.append((f'nonio-kind-{diagnostic}',reply(diagnostic=diagnostic,error_kind=1)))
        mutations.extend(('reply-'+name,lambda s:None,raw,wire) for name,raw in replies)
        for name,mutate,response,resume in mutations:
            with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
                assert session.invoke_raw(wire)[0]==EFFECT
                put_reply(session,response);mutate(session);ctypes.memset(session._output,0xa7,OUT)
                code,out,state=session.invoke_raw(resume);rejected(name,code,out,state,INVALID)
        command=cold(a,[record()]);command['name']='staged'
        normal=reply(1,records_wire([record()]))
        staged=[
            ('entries-count',1,setq(normal,32,513)),
            ('entries-no-record',1,reply(1)),
            ('entries-record-length',1,setq(normal,48,513)),
            ('entries-extra-byte',1,normal+b'\0'),
            ('entries-projection',1,setq(normal,56,0)),
            ('entries-utf8',1,normal[:-1]+b'\xff'),
            ('exists-value',3,reply(2)),('exists-payload',3,reply(0,b'x')),
            ('save-value',4,reply(1)),('save-payload',4,reply(0,b'x')),
            ('revalidation-stamp',2,setq(answer,48+56,0)),
            ('publication-stamp',5,setq(answer,48+56,0)),
        ]
        for name,index,response in staged:
            with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
                raw=request(command);assert session.invoke_raw(raw)[0]==EFFECT
                for at in range(index):
                    put_reply(session,bytes.fromhex(command['effects'][at]['reply_hex']))
                    assert session.invoke_raw(raw)[0]==EFFECT
                put_reply(session,response);ctypes.memset(session._output,0xa7,OUT)
                code,out,state=session.invoke_raw(raw);rejected(name,code,out,state,INVALID)
        cache_mutations=[('initialized',384,2),('poison',392,2),('count',400,17),
            ('uninitialized-nonempty',384,0),('slot',416,16),('stamp-magic',3145728,0),
            ('stamp-kind',3145728+56,0),('record-count',3145728+112,513)]
        for name,at,value in cache_mutations:
            with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
                command=put(a,[record()]);command['name']='cache';invoke(session,command)
                struct.pack_into('<Q',session._workspace,at,value);ctypes.memset(session._output,0xa7,OUT)
                code,out,state=session.invoke_raw(request(step(0)));rejected('cache-'+name,code,out,state,STATE)
        with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
            for index in range(2):
                command=put(stamp(inode=index),[record(index)]);command['name']='cache';invoke(session,command)
            struct.pack_into('<Q',session._workspace,424,struct.unpack_from('<Q',session._workspace,416)[0])
            ctypes.memset(session._output,0xa7,OUT)
            code,out,state=session.invoke_raw(request(step(0)));rejected('duplicate-cache-slot',code,out,state,STATE)
        with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
            session.invoke(request(step(0)));struct.pack_into('<Q',session._workspace,16,(1<<64)-1)
            ctypes.memset(session._output,0xa7,OUT)
            code,out,state=session.invoke_raw(wire);rejected('private-sequence-exhaustion',code,out,state,INVALID)
        for attempt in range(2):
            with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
                command=put(a,[record()]);command['name']='put';invoke(session,command)
                command=hit(a,True);command['name']='consume';result=invoke(session,command)
                raw=bytes.fromhex(result['result_hex'])
                assert struct.unpack_from('<3Q',raw,40)==(1,0,1)
                rows.append(dict(name=f'synthetic-put-consume-{attempt}',phase_cleared=True,
                    cache_entry_consumed=True,code=len(raw)))
        with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
            command=cold(a,[record()]);raw=request(command);assert session.invoke_raw(raw)[0]==EFFECT
            for at in range(5):
                put_reply(session,bytes.fromhex(command['effects'][at]['reply_hex']))
                assert session.invoke_raw(raw)[0]==EFFECT
            struct.pack_into('<Q',session._workspace,392,1)
            put_reply(session,bytes.fromhex(command['effects'][5]['reply_hex']))
            out=session.invoke(raw)
            assert struct.unpack_from('<Q',out,8)[0]==43 and struct.unpack_from('<Q',out,48)[0]==0
            rows.append(dict(name='synthetic-poison-before-final-publication',code=len(out),
                earlier_scripted_child_effects_preserved=True,cache_not_published=True))
    assert args.manifest.read_bytes()==manifest
    report=dict(schema='hepta.request-audit.hot-cache-controls.v1',status='PASS',checks=len(rows),
        rejection_controls=rejects,synthetic_completion_controls=len(rows)-rejects,cases=rows,
        manifest_sha256=SHA(manifest),original_executed=False,real_filesystem_effects=False,
        real_archive_executed=False,native_language_unwind_qualified=False,
        production_activated=False,whole_runtime_replaced=False)
    (args.output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},sort_keys=True))

if __name__=='__main__':main()
