"""Raw borrowed-input and private child-receipt controls; no real children."""
from pathlib import Path
import argparse,ctypes,hashlib,json,struct,sys
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
WORK=4<<20;INVALID=0xffffffff;CAPACITY=0xfffffffe;EFFECT=0xfffffff0
def setq(raw,offset,value):
    raw=bytearray(raw);struct.pack_into('<Q',raw,offset,value);return bytes(raw)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','runtime','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(mode=0o700,parents=True)
    sys.path[:0]=[str(Path(__file__).resolve().parent),str(args.runtime.resolve(strict=True)/'scripts')]
    from hia_native_loader import NativeModule
    from audit_retention_cases import request,row,record,reply,ID,OWNER
    raw_manifest=args.manifest.read_bytes();rows=[];rejects=0
    wire=request(row('raw',1,id=ID));primary=request(row('primary',2,primary=record()))
    with NativeModule(args.manifest,manifest_sha256=SHA(raw_manifest)) as module:
        bad=[('short',wire[:63],576,WORK,INVALID),('oversize',wire+bytes((1<<20)+1-len(wire)),576,WORK,INVALID),
            ('magic',b'BADMAGIC'+wire[8:],576,WORK,INVALID),('output-header',wire,63,WORK,CAPACITY),
            ('output-bound',wire,575,WORK,CAPACITY),('workspace',wire,576,WORK-1,CAPACITY),
            ('trailing',wire+b'\0',576,WORK,INVALID),('identifier-utf8',wire[:-1]+b'\xff',576,WORK,INVALID),
            ('truncated-primary',primary[:-1],576,WORK,INVALID)]
        for at,value in ((8,0),(8,5),(16,2),(24,513),(32,513),(40,513),(48,257),(56,257),
                (16,1),(24,1),(32,1),(40,1),(48,1)):
            bad.append((f'field-{at}-{value}',setq(wire,at,value),576,WORK,INVALID))
        for at,value in ((24,1),(56,1)):
            bad.append((f'retention-unused-{at}',setq(request(row('empty',4)),at,value),576,WORK,INVALID))
        for at,value in ((0,0),(8,2),(16,2),(40,3),(56,1),(64,257),(72,513),(112,1),(248,1),(48,1)):
            bad.append((f'projection-{at}-{value}',setq(primary,64+at,value),576,WORK,INVALID))
        bad.append(('primary-unused-id',setq(primary,56,1),576,WORK,INVALID))
        bad.append(('projection-utf8',primary[:-1]+b'\xff',576,WORK,INVALID))
        bad.append(('pending-utf8',request(row('pending',4,pending=['x']))[:-1]+b'\xff',576,WORK,INVALID))
        bad.append(('record-length',setq(request(row('record',4,records=[record()])),64,513),1024,WORK,INVALID))
        bad.append(('pending-length',setq(request(row('pending',4,pending=['x'])),64,257),576,WORK,INVALID))
        many=request(row('capacity',4,records=[record(i) for i in range(128)],owner=OWNER))
        bad.append(('retention-output-bound',many,64+128*520-1,WORK,CAPACITY))
        for name,raw,outcap,workcap,expected in bad:
            code,received,state=module.invoke_raw(raw,output_capacity=outcap,workspace_capacity=workcap,output_fill=0xa7)
            assert code==expected and received==b'\xa7'*outcap,(name,code,expected)
            rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejects+=1
        def put_reply(session,raw):
            ctypes.memmove(ctypes.addressof(session._workspace)+4096,raw,len(raw))
            sequence=struct.unpack_from('<Q',session._workspace,264)[0]
            struct.pack_into('<2Q',session._workspace,320,sequence,len(raw))
        absent=reply(diagnostic=23,error=2,not_found=True)
        mutations=[]
        for at,value in ((0,0),(8,2),(16,101),(24,1),(32,8193),(40,68),(48,4097),(56,559),
                (64,0),(64,2),(72,47),(72,561),(80,5),(88,1)):
            mutations.append((f'action-{at}-{value}',lambda s,at=at,value=value:struct.pack_into('<Q',s._workspace,256+at,value),absent,wire))
        mutations.append(('argument-mutation',lambda s:struct.pack_into('<B',s._workspace,8192,0),absent,wire))
        mutations.append(('input-mutation',lambda s:None,absent,wire[:-1]+b'b'))
        mutations.append(('input-length-mutation',lambda s:None,absent,wire+b'b'))
        replies=[('magic',b'BADMAGIC'+absent[8:]),('short',absent[:47]),('error-payload',absent+b'\0'),
            ('success-empty',reply()),('success-length',setq(reply(record()),32,1)),
            ('success-oversize',setq(reply(record()),32,513)),('projection-magic',setq(reply(record()),48,0)),
            ('projection-state',setq(reply(record()),88,3)),('projection-reserved',setq(reply(record()),160,1))]
        for at,value in ((8,65536),(16,4096),(24,2),(32,1),(40,1)):
            replies.append((f'field-{at}-{value}',setq(absent,at,value)))
        for diagnostic in (0,24):
            replies.append((f'non-io-errno-{diagnostic}',reply(diagnostic=diagnostic,error=2)))
            replies.append((f'non-io-kind-{diagnostic}',reply(diagnostic=diagnostic,not_found=True)))
        mutations.extend(('reply-'+name,lambda s:None,raw,wire) for name,raw in replies)
        for name,mutate,returned,resume in mutations:
            with module.session(output_capacity=576,workspace_capacity=WORK) as session:
                assert session.invoke_raw(wire)[0]==EFFECT
                put_reply(session,returned);mutate(session);ctypes.memset(session._output,0xa7,576)
                code,received,state=session.invoke_raw(resume)
                assert code==INVALID and received==b'\xa7'*576,(name,code)
                rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejects+=1
        for name,target,returned in [('active-value',102,reply(value=2)),
                ('active-payload',102,reply(record(0))),('remove-value',103,reply(value=1))]:
            outcap=64+128*520
            with module.session(output_capacity=outcap,workspace_capacity=WORK) as session:
                assert session.invoke_raw(many)[0]==EFFECT
                if target==103:
                    assert struct.unpack_from('<Q',session._workspace,272)[0]==102
                    put_reply(session,reply(value=0));assert session.invoke_raw(many)[0]==EFFECT
                    assert struct.unpack_from('<Q',session._workspace,272)[0]==101
                    put_reply(session,reply(record(0)));assert session.invoke_raw(many)[0]==EFFECT
                assert struct.unpack_from('<Q',session._workspace,272)[0]==target
                put_reply(session,returned);ctypes.memset(session._output,0xa7,outcap)
                code,received,state=session.invoke_raw(many)
                assert code==INVALID and received==b'\xa7'*outcap,(name,code)
                rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejects+=1
        with module.session(output_capacity=576,workspace_capacity=WORK) as session:
            for attempt in range(2):
                assert session.invoke_raw(wire)[0]==EFFECT
                assert struct.unpack_from('<Q',session._workspace,272)[0]==100
                put_reply(session,absent);assert session.invoke_raw(wire)[0]==EFFECT
                assert struct.unpack_from('<Q',session._workspace,272)[0]==101
                put_reply(session,absent);code,received,state=session.invoke_raw(wire)
                assert code==64 and received[:code]==b'HRAKR001'+bytes(56) and struct.unpack_from('<Q',state,8)[0]==0
                rows.append(dict(name='synthetic-absent-reuse-'+str(attempt),code=code,phase_cleared=True))
    assert args.manifest.read_bytes()==raw_manifest
    report=dict(schema='hepta.request-audit.retention-controls.v1',status='PASS',checks=len(rows),
        rejection_controls=rejects,synthetic_completion_controls=len(rows)-rejects,cases=rows,
        manifest_sha256=SHA(raw_manifest),original_executed=False,real_filesystem_effects=False,
        real_archive_executed=False,real_active_registry_executed=False,
        production_activated=False,whole_runtime_replaced=False)
    (args.output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},sort_keys=True))
if __name__=='__main__':main()
